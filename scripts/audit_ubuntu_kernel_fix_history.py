#!/usr/bin/env python3
"""Read-only upstream-fix ancestry and backport correspondence evidence.

This tool never decides that a CVE is fixed, unaffected, accepted, or releasable.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from collections import Counter

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dev10_evidence_lock import EvidenceLock

LOCK = EvidenceLock.load()
SOURCE_REPO = "https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/resolute"
REF_RE = re.compile(
    r"^https://git\.kernel\.org/(stable|linus)/c/([a-f0-9]{40})(?:[/?#].*)?$"
)
TRAILER_RE = re.compile(
    r"(?im)^\s*(?:cherry picked from commit|backport(?:ed)?(?: from)?(?: commit)?|upstream commit)\s*:?\s*([a-f0-9]{40})\b"
)
SHA_RE = re.compile(r"^[a-f0-9]{40}$")
MAX_PATH_HISTORY_COMMITS = 2000


class EvidenceError(ValueError):
    pass


def run(repo: Path, *args: str, check: bool = True, timeout: int = 120) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], text=True,
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
    )
    return proc.returncode == 0


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def patch_id(repo: Path, sha: str) -> str | None:
    show = subprocess.run(
        ["git", "-C", str(repo), "show", "--format=", "--no-ext-diff", "--binary", sha],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=120,
    )
    if show.returncode:
        return None
    result = subprocess.run(
        ["git", "patch-id", "--stable"], input=show.stdout,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=120,
    )
    if result.returncode or not result.stdout.strip():
        return None
    value = result.stdout.decode("ascii", "replace").split()
    return value[0] if value else None


def commit_metadata(repo: Path, sha: str) -> dict:
    raw = run(repo, "show", "-s", "--format=%H%x00%P%x00%T%x00%ct%x00%s", sha)
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


def candidate_identity(url: str) -> tuple[str, str] | None:
    match = REF_RE.fullmatch(url) if isinstance(url, str) else None
    return (match.group(1), match.group(2)) if match else None


def ensure_candidate_object(candidate_root: Path, sha: str, kind: str,
                            remotes: dict[str, str]) -> tuple[Path | None, str]:
    if has_commit(candidate_root, sha):
        return candidate_root, "present_in_candidate_object_store"
    remote_name = kind
    if run(candidate_root, "remote", "get-url", remote_name, check=False) != remotes[kind]:
        existing = run(candidate_root, "remote", check=False).splitlines()
        if remote_name in existing:
            return None, "candidate_remote_configuration_mismatch"
        subprocess.run(
            ["git", "-C", str(candidate_root), "remote", "add", remote_name, remotes[kind]],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    fetched = subprocess.run(
        ["git", "-C", str(candidate_root), "fetch", "--no-tags", "--depth=2", remote_name, sha],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=300,
    )
    if fetched.returncode or not has_commit(candidate_root, sha):
        return None, "candidate_commit_unavailable"
    if run(candidate_root, "rev-parse", sha + "^{commit}") != sha:
        return None, "candidate_commit_identity_mismatch"
    return candidate_root, "fetched_and_sha_verified"


def trailer_index(repo: Path, tag: str, candidate_shas: set[str]) -> dict[str, list[str]]:
    if not candidate_shas:
        return {}
    # Search commit messages once; only messages containing a full SHA are returned.
    output = run(
        repo, "log", "--format=%H%x00%B%x00", "--extended-regexp",
        "--grep=[a-f0-9]{40}", tag, timeout=300,
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


def inspect_candidate(repo: Path, candidate_root: Path, tag: str, cve: str,
                      url: str, kind: str, sha: str, row: dict,
                      ubuntu_row: dict, trailer_commits: list[str],
                      remotes: dict[str, str]) -> tuple[dict, list[str]]:
    if has_commit(repo, sha):
        candidate_repo, object_status = repo, "present_in_ubuntu_source_repository"
    else:
        candidate_repo, object_status = ensure_candidate_object(candidate_root, sha, kind, remotes)
    base = {
        "reference": url, "candidate_commit": sha, "upstream_tree": kind,
        "candidate_object_status": object_status,
        "exact_commit_ancestor_of_ubuntu_tag": False,
        "upstream_patch_id": None, "upstream_changed_paths": [],
        "backport_trailer_matches": [], "patch_id_matches": [],
        "assessment": object_status,
    }
    if candidate_repo is None:
        return base, list(row.get("upstream_paths", []))

    meta = commit_metadata(candidate_repo, sha)
    paths = changed_paths(candidate_repo, sha, meta["parents"])
    pid = patch_id(candidate_repo, sha)
    base.update({
        "candidate_commit_metadata": meta,
        "upstream_patch_id": pid,
        "upstream_changed_paths": paths,
    })
    if has_commit(repo, sha):
        ancestor = subprocess.run(
            ["git", "-C", str(repo), "merge-base", "--is-ancestor", sha, tag],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
        )
        base["exact_commit_ancestor_of_ubuntu_tag"] = ancestor.returncode == 0
        if ancestor.returncode not in (0, 1):
            base["assessment"] = "ancestry_check_inconclusive"
            return base, paths or list(row.get("upstream_paths", []))
    else:
        base["exact_commit_ancestor_of_ubuntu_tag"] = False

    base["backport_trailer_matches"] = [
        {"commit": commit, "patch_id": patch_id(repo, commit)}
        for commit in trailer_commits
    ]
    search_paths = set(paths) | set(row.get("upstream_paths", []))
    for correspondence in ubuntu_row.get("upstream_path_correspondence", []):
        search_paths.update(correspondence.get("same_basename_candidates", []))
    history, truncated = history_candidates(repo, tag, sorted(search_paths))
    matches = []
    if pid:
        for commit in history:
            downstream_pid = patch_id(repo, commit)
            if downstream_pid == pid:
                matches.append({"commit": commit, "patch_id": downstream_pid})
        for item in base["backport_trailer_matches"]:
            if item["patch_id"] == pid and not any(x["commit"] == item["commit"] for x in matches):
                matches.append(item)
    base["patch_id_matches"] = sorted(matches, key=lambda item: item["commit"])
    base["history_search"] = {
        "path_count": len(search_paths),
        "commit_count_examined": len(history),
        "truncated": truncated,
        "complete_for_selected_paths": not truncated,
    }
    if base["exact_commit_ancestor_of_ubuntu_tag"]:
        base["assessment"] = "EXACT_UPSTREAM_COMMIT_IN_UBUNTU_ANCESTRY"
    elif len(matches) == 1:
        base["assessment"] = "UNIQUE_STABLE_PATCH_ID_CORRESPONDENCE"
    elif len(matches) > 1:
        base["assessment"] = "AMBIGUOUS_STABLE_PATCH_ID_CORRESPONDENCE"
    elif base["backport_trailer_matches"]:
        base["assessment"] = "BACKPORT_TRAILER_WITHOUT_PATCH_ID_MATCH"
    elif truncated:
        base["assessment"] = "PATCH_SEARCH_TRUNCATED_INCOMPLETE"
    elif not pid:
        base["assessment"] = "UPSTREAM_PATCH_ID_UNAVAILABLE"
    else:
        base["assessment"] = "NO_PATCH_ID_MATCH_IN_COMPLETE_SELECTED_PATH_HISTORY"
    return base, sorted(search_paths)


def audit(upstream: dict, ubuntu_paths: dict, repo: Path, candidate_root: Path,
          binary_source: dict, expected_commit: str, remotes: dict[str, str],
          input_digests: dict) -> dict:
    if upstream.get("package") != "linux-libc-dev=" + LOCK.package_version:
        raise EvidenceError("upstream evidence package differs from evidence lock")
    if binary_source.get("schema") != "baobab.dev10.ubuntu-binary-source-provenance.v1":
        raise EvidenceError("missing Ubuntu binary/source provenance")
    for key, expected in LOCK.binary_source.items():
        if binary_source.get(key) != expected:
            raise EvidenceError("binary/source provenance differs from evidence lock: " + key)
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

    candidate_shas: set[str] = set()
    for row in upstream_rows:
        for url in row.get("candidate_upstream_fix_references", []):
            identity = candidate_identity(url)
            if identity:
                candidate_shas.add(identity[1])
    trailers = trailer_index(repo, expected_commit, candidate_shas)
    records = []
    counts = Counter()
    all_search_paths: set[str] = set()
    for cve in sorted(upstream_by_cve):
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
                repo, candidate_root, expected_commit, cve, url, kind, sha,
                row, ubuntu_row, trailers.get(sha, []), remotes,
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
            "reachable_commit_count": int(run(repo, "rev-list", "--count", expected_commit)),
        },
        "binary_source": {
            key: binary_source[key] for key in (
                "source_package", "source_version", "binary_package",
                "binary_version", "release_pocket", "architecture",
            )
        },
        "candidate_commit_count": len(candidate_shas),
        "path_search_count": len(all_search_paths),
        "assessment_counts": dict(sorted(counts.items())),
        "record_count": len(records),
        "counts": {"under_investigation": len(records)},
        "records": records,
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
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
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
            args.expected_commit, remotes, digests,
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
