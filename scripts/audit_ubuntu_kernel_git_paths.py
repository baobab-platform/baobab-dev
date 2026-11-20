#!/usr/bin/env python3
"""Read-only Ubuntu release-tag source path corroboration for 298 kernel CVEs.

This proves what paths exist at a tagged downstream source snapshot, NOT whether
a particular fix was backported or how generated UAPI/ABI changed. Results never
authorise VEX. Uses official Canonical kernel Git checkout supplied by caller.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from collections import Counter
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dev10_evidence_lock import EvidenceLock, require_binary_provenance

LOCK = EvidenceLock.load()
SOURCE_REPO = "https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/resolute"
RELEASE_TAG = LOCK.ubuntu_tag
RELEASE_VERSION = LOCK.package_version
SHA40 = re.compile(r"^[a-f0-9]{40}$")
EXPECTED = LOCK.inventory_count
EXPECTED_RELEASE_COMMIT = LOCK.ubuntu_tag_commit
MAX_BASENAME_CANDIDATES = 5


def git(repo: Path, *args: str, check: bool = True) -> str:
    proc = subprocess.run(["git", "-C", str(repo), *args], text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=60, check=False)
    if check and proc.returncode:
        raise ValueError("Ubuntu git source verification failed: " + proc.stderr[:250])
    return proc.stdout.strip() if proc.returncode == 0 else ""


def validate_upstream_path(cve: str, path: str) -> None:
    if (not isinstance(path, str) or not path or path.startswith("/")
            or "\\" in path or any(ord(ch) < 32 or ord(ch) == 127 for ch in path)
            or any(part in {"", ".", ".."} for part in path.split("/"))):
        raise ValueError(f"{cve}: invalid upstream source path")


def candidate_index(paths: set[str]) -> dict[str, list[str]]:
    index: dict[str, list[str]] = {}
    for path in paths:
        index.setdefault(path.rsplit("/", 1)[-1], []).append(path)
    for values in index.values():
        values.sort()
    return index


def ranked_candidates(missing: str, index: dict[str, list[str]]) -> list[str]:
    parts = missing.split("/")
    def shared_suffix(candidate: str) -> int:
        count = 0
        for left, right in zip(reversed(parts), reversed(candidate.split("/"))):
            if left != right:
                break
            count += 1
        return count
    return sorted(index.get(parts[-1], []),
                  key=lambda candidate: (-shared_suffix(candidate), candidate))


def inspect(upstream: dict, repo: Path, paths: set[str], *, binary_source: dict,
            exact_tag: str = RELEASE_TAG,
            expected_commit: str = EXPECTED_RELEASE_COMMIT,
            require_origin: bool = True) -> dict:
    if upstream.get("package") != "linux-libc-dev=" + RELEASE_VERSION:
        raise ValueError("mismatched binary package source")
    require_binary_provenance(binary_source, LOCK)
    rows = upstream.get("records", [])
    if len(rows) != EXPECTED or len({r["cve"] for r in rows}) != EXPECTED:
        raise ValueError("missing/duplicate CVE affected-file records")
    if require_origin and git(repo, "remote", "get-url", "origin") != SOURCE_REPO:
        raise ValueError("Ubuntu source remote is not Canonical's official Resolute source")
    if not SHA40.fullmatch(expected_commit):
        raise ValueError("expected Ubuntu release-tag commit must be an immutable 40-character Git SHA")
    # Resolve the fully-qualified tag and compare against an independently
    # reviewed commit pin; self-consistency alone would accept a moved tag.
    sha = git(repo, "rev-parse", "--verify", f"refs/tags/{exact_tag}^{{commit}}")
    checked = git(repo, "rev-parse", "HEAD")
    if not (sha == checked == expected_commit):
        raise ValueError(
            f"Ubuntu release-tag mismatch: tag={sha[:12]} HEAD={checked[:12]} "
            f"expected={expected_commit[:12]}"
        )
    shallow = git(repo, "rev-parse", "--is-shallow-repository") == "true"
    tree = subprocess.run(
        ["git", "-C", str(repo), "ls-tree", "-r", "-z", "--name-only", sha],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120, check=False,
    )
    if tree.returncode:
        raise ValueError("Ubuntu source tree enumeration failed")
    # -z preserves unusual Git paths without C-style quoting or line splitting.
    ubuntu_tree_paths = {item.decode("utf-8", "surrogateescape")
                         for item in tree.stdout.split(b"\0") if item}
    by_basename = candidate_index(ubuntu_tree_paths)
    result = []
    for row in rows:
        cve = row["cve"]
        if row.get("error") or not row.get("upstream_paths"):
            raise ValueError(cve + ": incomplete upstream changed-file claims")
        present, missing, correspondence = [], [], []
        for path in row["upstream_paths"]:
            validate_upstream_path(cve, path)
            # Exact path correspondence is checked against the immutable tag tree.
            if path in ubuntu_tree_paths:
                present.append(path)
                correspondence.append({
                    "upstream_path": path, "ubuntu_tag_status": "present",
                    "same_basename_candidates": [],
                })
            else:
                missing.append(path)
                all_candidates = ranked_candidates(path, by_basename)
                candidates = all_candidates[:MAX_BASENAME_CANDIDATES]
                correspondence.append({
                    "upstream_path": path, "ubuntu_tag_status": "missing",
                    "same_basename_candidates": candidates,
                    "same_basename_candidate_count": len(all_candidates),
                    "same_basename_candidates_truncated": len(all_candidates) > MAX_BASENAME_CANDIDATES,
                })
        path_status = (
            "PATHS_PRESENT_NONDISCRIMINATING" if not missing
            else "SOME_UPSTREAM_PATHS_MISSING"
        )
        direct = []
        for path in row.get("affected_headers", []):
            if path.startswith("include/uapi/"):
                candidate = "/usr/include/" + path[len("include/uapi/"):]
                if candidate in paths:
                    direct.append(candidate)
        result.append({
            "cve": cve,
            "canonical_ubuntu_source_repository": SOURCE_REPO,
            "ubuntu_release_tag": exact_tag,
            "ubuntu_release_tag_commit": sha,
            "ubuntu_source_paths_present": present,
            "upstream_paths_missing_from_ubuntu_snapshot": missing,
            "ubuntu_source_path_status": path_status,
            "upstream_path_correspondence": correspondence,
            "direct_binary_manifest_uapi_path_matches": direct,
            "kernel_private_header_paths": [
                p for p in row.get("affected_headers", [])
                if not p.startswith("include/uapi/")],
            "upstream_candidate_fix_references": row.get("candidate_upstream_fix_references", []),
            "ubuntu_fix_commit_verified": False,
            "ubuntu_backport_provenance_verified": False,
            "ubuntu_security_pocket_fixed_version_verified": False,
            "shipped_header_byte_comparison_verified": False,
            "uapi_abi_macro_indirect_exposure": "under_investigation",
            "binary_disposition": "under_investigation",
        })
    return {
        "schema": "baobab.dev10.ubuntu-source-path-correspondence.v1",
        "decision": "SECURITY_HELD_NO_APPROVAL",
        "ubuntu_release_tag": exact_tag, "ubuntu_source_commit": sha,
        "binary_source": binary_source,
        "expected_ubuntu_source_commit": expected_commit,
        "shallow_history": shallow,
        "note": ("Snapshot path presence is NOT a fixing-commit or backport assessment; "
                 "missing paths can represent renames and do not prove unaffected."),
        "counts": dict(Counter(x["binary_disposition"] for x in result)),
        "path_counts": dict(Counter(x["ubuntu_source_path_status"] for x in result)),
        "records": result,
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--upstream", type=Path, required=True)
    p.add_argument("--ubuntu-checkout", type=Path, required=True)
    p.add_argument("--installed-manifest", type=Path, required=True)
    p.add_argument("--binary-source", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--expected-commit", default=EXPECTED_RELEASE_COMMIT)
    a = p.parse_args()
    upstream = json.loads(a.upstream.read_text(encoding="utf-8"))
    manifest_bytes = a.installed_manifest.read_bytes()
    installed = set(manifest_bytes.decode("utf-8").splitlines())
    header_count = sum(p.endswith(".h") for p in installed)
    if (header_count != LOCK.header_count
            or len(installed) != LOCK.binary_manifest_path_count
            or hashlib.sha256(manifest_bytes).hexdigest() != LOCK.binary_manifest_sha256):
        raise SystemExit("Exact binary manifest digest/path/header count differs from evidence lock")
    binary_source = json.loads(a.binary_source.read_text(encoding="utf-8"))
    report = inspect(upstream, a.ubuntu_checkout, installed,
                     binary_source=binary_source, expected_commit=a.expected_commit)
    report["binary_manifest"] = {
        "package": "linux-libc-dev=" + RELEASE_VERSION,
        "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "path_count": len(installed),
        "header_count": header_count,
    }
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("Ubuntu source path review:", report["counts"])
    print("Release tag:", report["ubuntu_release_tag"], "commit:", report["ubuntu_source_commit"])
    print("No Ubuntu patch/backport or binary exposure clearance is asserted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
