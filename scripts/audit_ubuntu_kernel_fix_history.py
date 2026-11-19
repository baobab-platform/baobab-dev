#!/usr/bin/env python3
"""Read-only upstream-fix ancestry and backport correspondence evidence.

This tool never decides that a CVE is fixed, unaffected, accepted, or releasable.
"""
from __future__ import annotations

import argparse
from contextlib import suppress
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
from time import monotonic
from collections import Counter

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dev10_evidence_lock import EvidenceLock, require_binary_provenance

LOCK = EvidenceLock.load()
SOURCE_REPO = "https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/resolute"
REF_RE = re.compile(
    r"^https://git\.kernel\.org/(stable|linus)/c/([a-f0-9]{40})(?:[/?#].*)?$"
)
TRAILER_RE = re.compile(
    r"(?im)^\s*[\(\[]?\s*(?:cherry picked from commit|backport(?:ed)?(?: from)?(?: commit)?|upstream commit)\s*:?\s*([a-f0-9]{40})\b"
)
SHA_RE = re.compile(r"^[a-f0-9]{40}$")
MAX_PATH_HISTORY_COMMITS = 2000
CANDIDATE_FETCH_TIMEOUT = 60
UPSTREAM_FETCH_BATCH = 32
PREFETCH_SECONDS = 180
GIT_LOCAL_ONLY = dict(os.environ, GIT_NO_LAZY_FETCH="1")


class EvidenceError(ValueError):
    pass


def run(repo: Path, *args: str, check: bool = True, timeout: int = 120,
        replace_invalid_text: bool = False) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], encoding="utf-8",
        errors="replace" if replace_invalid_text else "strict",
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=timeout, check=False,
    )
    if check and proc.returncode:
        raise EvidenceError("git " + " ".join(args[:3]) + " failed: " + proc.stderr[:240])
    return proc.stdout.strip() if proc.returncode == 0 else ""


def has_commit(repo: Path, sha: str) -> bool:
    proc = subprocess.run(
        ["git", "-C", str(repo), "cat-file", "-e", sha + "^{commit}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
        env=GIT_LOCAL_ONLY, timeout=20,
    )
    return proc.returncode == 0


def present_commits(repo: Path, shas: set[str]) -> set[str]:
    if not shas:
        return set()
    proc = subprocess.run(
        ["git", "-C", str(repo), "cat-file", "--batch-check=%(objectname) %(objecttype)"],
        input="\n".join(sorted(shas)) + "\n", capture_output=True, text=True,
        env=GIT_LOCAL_ONLY, timeout=60, check=True,
    )
    return {line[:-7] for line in proc.stdout.splitlines()
            if line.endswith(" commit") and line[:-7] in shas}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def patch_id(repo: Path, sha: str) -> str | None:
    try:
        show = subprocess.run(
            ["git", "-C", str(repo), "show", "--format=", "--no-ext-diff", "--binary", sha],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=120,
        )
        if show.returncode:
            return None
        result = subprocess.run(
            ["git", "patch-id", "--stable"], input=show.stdout,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=30,
        )
    except subprocess.TimeoutExpired:
        return None
    if result.returncode or not result.stdout.strip():
        return None
    value = result.stdout.decode("ascii", "replace").split()
    return value[0] if value else None


def commit_metadata(repo: Path, sha: str) -> dict:
    raw = run(repo, "show", "-s", "--format=%H%x00%P%x00%T%x00%ct%x00%s", sha,
              replace_invalid_text=True)
    parts = raw.split("\0", 4)
    if len(parts) != 5 or parts[0] != sha:
        raise EvidenceError("candidate commit metadata did not resolve to requested SHA")
    return {
        "sha": parts[0],
        "parents": parts[1].split() if parts[1] else [],
        "tree": parts[2],
        "committer_unix": int(parts[3]),
        "subject": parts[4][:240],
    }


def changed_paths(repo: Path, sha: str, parents: list[str]) -> list[str]:
    if len(parents) > 1:
        return []
    if parents:
        values = run(repo, "diff-tree", "--no-commit-id", "--name-only", "-r", sha).splitlines()
    else:
        values = run(repo, "diff-tree", "--root", "--no-commit-id", "--name-only", "-r", sha).splitlines()
    return sorted({p for p in values if p and not p.startswith("/") and "\\" not in p})


def cached_patch_id(repo: Path, sha: str, cache: dict) -> str | None:
    key = (str(repo.resolve()), sha)
    if key not in cache:
        cache[key] = patch_id(repo, sha)
    return cache[key]


def candidate_identity(url: str) -> tuple[str, str] | None:
    match = REF_RE.fullmatch(url) if isinstance(url, str) else None
    return (match.group(1), match.group(2)) if match else None


def configure_candidate_remote(candidate_root: Path, kind: str, url: str) -> bool:
    if run(candidate_root, "remote", "get-url", kind, check=False) != url:
        existing = run(candidate_root, "remote", check=False).splitlines()
        if kind in existing:
            return False
        run(candidate_root, "remote", "add", kind, url)
    return True


def fetch_candidates(candidate_root: Path, kind: str, shas: list[str], timeout: float):
    argv = ["git", "-C", str(candidate_root), "fetch", "--atomic", "--no-tags", "--depth=2",
            "--filter=blob:none", kind, *shas]
    git_dir = candidate_root / ".git"
    shallow_lock = git_dir / "shallow.lock"
    # A fetch can spawn transport and index-pack children. Kill the complete
    # process group and remove only a lock created during our exclusive fetch.
    with (git_dir / "dev10-fetch.lock").open("a") as lease:
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if os.path.lexists(shallow_lock):
            raise EvidenceError("candidate repository has a pre-existing shallow lock")
        with subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True) as proc:
            try:
                stdout, stderr = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                with suppress(ProcessLookupError):
                    os.killpg(proc.pid, signal.SIGKILL)
                proc.communicate()
                shallow_lock.unlink(missing_ok=True)
                raise
            return subprocess.CompletedProcess(argv, proc.returncode, stdout, stderr)


def prefetch_candidates(candidate_root: Path, by_repo: dict[str, list[str]],
                        remotes: dict[str, str], deadline: float) -> None:
    for kind, shas in by_repo.items():
        if len(shas) < 2 or monotonic() >= deadline:
            continue
        if not configure_candidate_remote(candidate_root, kind, remotes[kind]):
            continue
        present = present_commits(candidate_root, set(shas))
        missing = [sha for sha in shas if sha not in present]
        for start in range(0, len(missing), UPSTREAM_FETCH_BATCH):
            remaining = deadline - monotonic()
            if remaining <= 0:
                return
            try:
                fetch_candidates(candidate_root, kind, missing[start:start + UPSTREAM_FETCH_BATCH],
                                 min(CANDIDATE_FETCH_TIMEOUT, remaining))
            except (subprocess.TimeoutExpired, EvidenceError, BlockingIOError):
                break
            # A refused batch falls back to exact, individual lookup during analysis.


def ensure_candidate_object(candidate_root: Path, sha: str, kind: str,
                            remotes: dict[str, str]) -> tuple[Path | None, str, str]:
    if has_commit(candidate_root, sha):
        return candidate_root, "present_in_candidate_object_store", ""
    if not configure_candidate_remote(candidate_root, kind, remotes[kind]):
        return None, "candidate_remote_configuration_mismatch", "candidate remote URL differs from the configured official upstream"
    try:
        fetched = fetch_candidates(candidate_root, kind, [sha], CANDIDATE_FETCH_TIMEOUT)
    except subprocess.TimeoutExpired:
        return None, "candidate_fetch_timed_out", "upstream commit object fetch exceeded its time limit"
    except (EvidenceError, BlockingIOError):
        return None, "candidate_repository_busy", "upstream fetch could not acquire its candidate-store lease"
    if fetched.returncode or not has_commit(candidate_root, sha):
        diagnostic = fetched.stderr.decode("utf-8", "replace")[:180]
        return None, "candidate_commit_unavailable", diagnostic
    if run(candidate_root, "rev-parse", sha + "^{commit}") != sha:
        return None, "candidate_commit_identity_mismatch", "fetched object did not resolve to the requested commit SHA"
    return candidate_root, "fetched_and_sha_verified", ""


def trailer_index(repo: Path, tag: str, candidate_shas: set[str]) -> dict[str, list[str]]:
    if not candidate_shas:
        return {}
    # Keep the commit ID and exact ASCII reference intact through historical
    # messages that contain non-UTF-8 bytes. Inspect only likely trailers.
    output = run(
        repo, "log", "--format=%H%x00%B%x00", "--extended-regexp", "--regexp-ignore-case",
        "--grep=(cherry picked from commit|backport|upstream commit).*([a-f0-9]{40})",
        tag, timeout=300, replace_invalid_text=True,
    )
    wanted: dict[str, list[str]] = {sha: [] for sha in candidate_shas}
    parts = output.split("\0")
    for index in range(0, len(parts) - 1, 2):
        commit = parts[index].strip()
        body = parts[index + 1]
        if not SHA_RE.fullmatch(commit):
            continue
        for sha in set(TRAILER_RE.findall(body)) & candidate_shas:
            wanted[sha].append(commit)
    return {sha: sorted(set(commits)) for sha, commits in wanted.items() if commits}


def history_candidates(repo: Path, tag: str, paths: list[str]) -> tuple[list[str], bool]:
    if not paths:
        return [], False
    output = run(
        repo, "log", "--format=%H", f"--max-count={MAX_PATH_HISTORY_COMMITS + 1}",
        tag, "--", *paths, timeout=300,
    )
    commits = [line.strip() for line in output.splitlines() if SHA_RE.fullmatch(line.strip())]
    truncated = len(commits) > MAX_PATH_HISTORY_COMMITS
    return commits[:MAX_PATH_HISTORY_COMMITS], truncated


def inspect_candidate(repo: Path, candidate_root: Path, tag: str,
                      url: str, kind: str, sha: str, row: dict,
                      ubuntu_row: dict, trailer_commits: list[str],
                      remotes: dict[str, str], history_cache: dict,
                      patch_cache: dict, *, available_in_ubuntu: set[str], ancestors: set[str],
                      deadline: float) -> tuple[dict, list[str]]:
    base = {
        "reference": url, "candidate_commit": sha, "upstream_tree": kind,
        "candidate_remote": remotes[kind],
        "exact_commit_ancestor_of_ubuntu_tag": None,
        "ubuntu_merge_base": None,
        "upstream_patch_id": None, "upstream_changed_paths": [],
        "backport_trailer_matches": [], "patch_id_matches": [],
        "candidate_object_status": "analysis_budget_exhausted",
        "candidate_object_diagnostic": "",
        "assessment": "ANALYSIS_BUDGET_EXHAUSTED",
    }
    if sha in ancestors:
        base.update(
            candidate_object_status="present_in_ubuntu_source_repository",
            exact_commit_ancestor_of_ubuntu_tag=True, ubuntu_merge_base=sha,
            assessment="EXACT_UPSTREAM_COMMIT_IN_UBUNTU_ANCESTRY",
            backport_trailer_matches=[{"commit": commit, "patch_id": None} for commit in trailer_commits],
        )
        return base, list(row.get("upstream_paths", []))
    if monotonic() >= deadline:
        base["backport_trailer_matches"] = [{"commit": commit, "patch_id": None} for commit in trailer_commits]
        return base, []
    if sha in available_in_ubuntu:
        candidate_repo, object_status, diagnostic = repo, "present_in_ubuntu_source_repository", ""
    else:
        candidate_repo, object_status, diagnostic = ensure_candidate_object(candidate_root, sha, kind, remotes)
    base.update(candidate_object_status=object_status, candidate_object_diagnostic=diagnostic, assessment=object_status)
    if candidate_repo is None:
        base["backport_trailer_matches"] = [
            {"commit": commit, "patch_id": cached_patch_id(repo, commit, patch_cache)
             if monotonic() < deadline else None}
            for commit in trailer_commits
        ]
        if trailer_commits:
            base["assessment"] = "CANDIDATE_OBJECT_UNAVAILABLE_TRAILER_EVIDENCE_RETAINED"
        return base, list(row.get("upstream_paths", []))

    try:
        meta = commit_metadata(candidate_repo, sha)
        paths = changed_paths(candidate_repo, sha, meta["parents"])
    except subprocess.TimeoutExpired:
        base["assessment"] = "UPSTREAM_COMMIT_READ_TIMED_OUT"
        return base, []
    base.update({
        "candidate_commit_metadata": meta,
        "upstream_changed_paths": paths,
    })
    if candidate_repo == repo:
        try:
            ancestor = subprocess.run(
                ["git", "-C", str(repo), "merge-base", "--is-ancestor", sha, tag],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=60,
            )
            merge_base = run(repo, "merge-base", sha, tag, check=False, timeout=60)
        except subprocess.TimeoutExpired:
            base["assessment"] = "ANCESTRY_CHECK_TIMED_OUT"
            return base, paths
        base["exact_commit_ancestor_of_ubuntu_tag"] = ancestor.returncode == 0
        base["ubuntu_merge_base"] = merge_base if SHA_RE.fullmatch(merge_base) else None
        if ancestor.returncode not in (0, 1):
            base["exact_commit_ancestor_of_ubuntu_tag"] = None
            base["assessment"] = "ancestry_check_inconclusive"
            return base, paths or list(row.get("upstream_paths", []))
    else:
        # Complete Ubuntu history has been verified; a candidate object fetched
        # separately cannot be an ancestor unless it is present in this object graph.
        base["exact_commit_ancestor_of_ubuntu_tag"] = False

    base["backport_trailer_matches"] = [
        {"commit": commit, "patch_id": cached_patch_id(repo, commit, patch_cache)
         if monotonic() < deadline else None}
        for commit in trailer_commits
    ]
    search_paths = set(paths) | set(row.get("upstream_paths", []))
    for correspondence in ubuntu_row.get("upstream_path_correspondence", []):
        search_paths.update(correspondence.get("same_basename_candidates", []))
    if base["exact_commit_ancestor_of_ubuntu_tag"]:
        base["assessment"] = "EXACT_UPSTREAM_COMMIT_IN_UBUNTU_ANCESTRY"
        return base, sorted(search_paths)
    if monotonic() >= deadline:
        base["assessment"] = "ANALYSIS_BUDGET_EXHAUSTED"
        return base, sorted(search_paths)
    pid = cached_patch_id(candidate_repo, sha, patch_cache)
    base["upstream_patch_id"] = pid
    if pid is None:
        base["assessment"] = "UPSTREAM_PATCH_ID_UNAVAILABLE"
        return base, sorted(search_paths)

    history_key = tuple(sorted(search_paths))
    if history_key not in history_cache:
        try:
            history_cache[history_key] = history_candidates(repo, tag, list(history_key))
        except subprocess.TimeoutExpired:
            base["assessment"] = "DOWNSTREAM_HISTORY_READ_TIMED_OUT"
            return base, sorted(search_paths)
    history, truncated = history_cache[history_key]
    unavailable = 0
    examined = 0
    matches = {}
    for commit in history:
        if monotonic() >= deadline:
            break
        downstream_pid = cached_patch_id(repo, commit, patch_cache)
        examined += 1
        if downstream_pid is None:
            unavailable += 1
        elif downstream_pid == pid:
            matches[commit] = downstream_pid
    for item in base["backport_trailer_matches"]:
        if item["patch_id"] == pid:
            matches[item["commit"]] = pid
    base["patch_id_matches"] = [
        {"commit": commit, "patch_id": value} for commit, value in sorted(matches.items())
    ]
    budget_exhausted = examined != len(history)
    complete = not truncated and not budget_exhausted and unavailable == 0
    base["history_search"] = {
        "path_count": len(search_paths),
        "commit_count_examined": examined,
        "patch_id_unavailable_count": unavailable,
        "truncated": truncated,
        "budget_exhausted": budget_exhausted,
        "complete_for_selected_paths": complete,
    }
    if budget_exhausted:
        base["assessment"] = ("PATCH_ID_MATCH_FOUND_BUT_SEARCH_BUDGET_EXHAUSTED" if matches
                              else "PATCH_SEARCH_BUDGET_EXHAUSTED")
    elif truncated and matches:
        base["assessment"] = "PATCH_ID_MATCH_FOUND_BUT_HISTORY_TRUNCATED"
    elif truncated:
        base["assessment"] = "PATCH_SEARCH_TRUNCATED_INCOMPLETE"
    elif unavailable:
        base["assessment"] = "DOWNSTREAM_PATCH_EVIDENCE_INCOMPLETE"
    elif len(matches) == 1:
        base["assessment"] = "UNIQUE_STABLE_PATCH_ID_CORRESPONDENCE"
    elif len(matches) > 1:
        base["assessment"] = "AMBIGUOUS_STABLE_PATCH_ID_CORRESPONDENCE"
    elif base["backport_trailer_matches"]:
        base["assessment"] = "BACKPORT_TRAILER_WITHOUT_PATCH_ID_MATCH"
    else:
        base["assessment"] = "NO_PATCH_ID_MATCH_IN_COMPLETE_SELECTED_PATH_HISTORY"
    return base, sorted(search_paths)


def audit(upstream: dict, ubuntu_paths: dict, repo: Path, candidate_root: Path,
          binary_source: dict, expected_commit: str, remotes: dict[str, str],
          input_digests: dict, *, analysis_seconds: int = 1200) -> dict:
    if upstream.get("package") != "linux-libc-dev=" + LOCK.package_version:
        raise EvidenceError("upstream evidence package differs from evidence lock")
    require_binary_provenance(binary_source, LOCK)
    if expected_commit != LOCK.ubuntu_tag_commit:
        raise EvidenceError("Ubuntu source commit differs from evidence lock")
    if run(repo, "remote", "get-url", "origin") != SOURCE_REPO:
        raise EvidenceError("Ubuntu source remote is not Canonical's official Resolute source")
    tag = LOCK.ubuntu_tag
    actual = run(repo, "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}")
    head = run(repo, "rev-parse", "HEAD")
    if actual != expected_commit or head != expected_commit:
        raise EvidenceError("Ubuntu tag, HEAD and locked commit do not match")
    if run(repo, "rev-parse", "--is-shallow-repository") != "false":
        raise EvidenceError("Ubuntu source history is shallow; ancestry search is incomplete")

    upstream_rows = upstream.get("records", [])
    ubuntu_rows = ubuntu_paths.get("records", [])
    if len(upstream_rows) != LOCK.inventory_count or len(ubuntu_rows) != LOCK.inventory_count:
        raise EvidenceError("upstream and Ubuntu path evidence must contain the locked 298 records")
    upstream_by_cve = {row.get("cve"): row for row in upstream_rows}
    ubuntu_by_cve = {row.get("cve"): row for row in ubuntu_rows}
    if (len(upstream_by_cve) != LOCK.inventory_count
            or set(upstream_by_cve) != set(ubuntu_by_cve)):
        raise EvidenceError("upstream and Ubuntu path evidence CVE identities differ")

    cve_order = sorted(upstream_by_cve, key=lambda cve: (cve not in LOCK.observed_kernel_cves, cve))
    identities: dict[str, dict[str, None]] = {}
    for cve in cve_order:
        for url in sorted(upstream_by_cve[cve].get("candidate_upstream_fix_references", [])):
            identity = candidate_identity(url)
            if identity:
                kind, sha = identity
                identities.setdefault(kind, {})[sha] = None
    candidate_shas = {sha for by_kind in identities.values() for sha in by_kind}
    available_in_ubuntu = present_commits(repo, candidate_shas)
    history = run(repo, "rev-list", expected_commit, timeout=300).splitlines()
    if not history or history[0] != expected_commit:
        raise EvidenceError("complete Ubuntu ancestor walk did not start at the exact release tag")
    ancestors = available_in_ubuntu.intersection(history)
    reachable_count = len(history)
    del history
    trailers = trailer_index(repo, expected_commit, candidate_shas)
    deadline = monotonic() + analysis_seconds
    prefetch_candidates(candidate_root, {
        kind: [sha for sha in values if sha not in available_in_ubuntu]
        for kind, values in identities.items()
    }, remotes, min(deadline, monotonic() + PREFETCH_SECONDS))
    records = []
    counts = Counter()
    all_search_paths: set[str] = set()
    history_cache: dict = {}
    patch_cache: dict = {}
    for cve in cve_order:
        row = upstream_by_cve[cve]
        ubuntu_row = ubuntu_by_cve[cve]
        candidates = []
        invalid = []
        refs = sorted(set(row.get("candidate_upstream_fix_references", [])))
        for url in refs:
            identity = candidate_identity(url)
            if not identity:
                invalid.append({"reference": str(url)[:1024], "assessment": "INVALID_CANDIDATE_REFERENCE"})
                continue
            kind, sha = identity
            result, searched = inspect_candidate(
                repo, candidate_root, expected_commit, url, kind, sha,
                row, ubuntu_row, trailers.get(sha, []), remotes,
                history_cache, patch_cache, available_in_ubuntu=available_in_ubuntu, ancestors=ancestors,
                deadline=deadline,
            )
            candidates.append(result)
            all_search_paths.update(searched)
            counts[result["assessment"]] += 1
        if not refs:
            counts["NO_CANDIDATE_FIX_REFERENCE"] += 1
        records.append({
            "cve": cve,
            "source_package": binary_source["source_package"],
            "source_version": binary_source["source_version"],
            "binary_package": binary_source["binary_package"],
            "binary_version": binary_source["binary_version"],
            "release_pocket": binary_source["release_pocket"],
            "ubuntu_release_tag": tag,
            "ubuntu_release_tag_commit": expected_commit,
            "candidate_count": len(candidates),
            "invalid_reference_count": len(invalid),
            "candidates": candidates,
            "invalid_references": invalid,
            "disposition": "under_investigation",
        })
    return {
        "schema": "baobab.dev10.ubuntu-fix-history-evidence.v1",
        "decision": "EVIDENCE_ONLY_NO_VEX_NO_RISK_ACCEPTANCE_NO_RELEASE_AUTHORITY",
        "inputs": input_digests,
        "ubuntu_source": {
            "repository": SOURCE_REPO, "tag": tag, "commit": expected_commit,
            "history_complete": True, "shallow": False,
            "reachable_commit_count": reachable_count,
        },
        "binary_source": {
            key: binary_source[key] for key in (
                "source_package", "source_version", "binary_package",
                "binary_version", "release_pocket", "architecture",
            )
        },
        "candidate_commit_count": len(candidate_shas),
        "analysis_budget_seconds": analysis_seconds,
        "analysis_budget_exhausted": any("BUDGET_EXHAUSTED" in status for status in counts),
        "path_search_count": len(all_search_paths),
        "assessment_counts": dict(sorted(counts.items())),
        "record_count": len(records),
        "counts": {"under_investigation": len(records)},
        "records": sorted(records, key=lambda row: row["cve"]),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--ubuntu-paths", type=Path, required=True)
    parser.add_argument("--ubuntu-checkout", type=Path, required=True)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--binary-source", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--stable-remote", default="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git")
    parser.add_argument("--linus-remote", default="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git")
    parser.add_argument("--analysis-seconds", type=int, default=1200)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.analysis_seconds < 1:
        parser.error("--analysis-seconds must be positive")
    try:
        if not args.candidate_root.exists():
            args.candidate_root.mkdir(parents=True)
            subprocess.run(["git", "init", "-q", str(args.candidate_root)], check=True)
        remotes = {"stable": args.stable_remote, "linus": args.linus_remote}
        digests = {
            "upstream_evidence_sha256": sha256_file(args.upstream),
            "ubuntu_path_evidence_sha256": sha256_file(args.ubuntu_paths),
            "binary_source_evidence_sha256": sha256_file(args.binary_source),
        }
        report = audit(
            json.loads(args.upstream.read_text(encoding="utf-8")),
            json.loads(args.ubuntu_paths.read_text(encoding="utf-8")),
            args.ubuntu_checkout, args.candidate_root,
            json.loads(args.binary_source.read_text(encoding="utf-8")),
            args.expected_commit, remotes, digests, analysis_seconds=args.analysis_seconds,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("Ubuntu fix-history evidence:", report["assessment_counts"])
        print("CVEs retained under investigation:", report["counts"])
        return 0
    except (EvidenceError, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
        print("::error::Incomplete Ubuntu fix-history evidence: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
