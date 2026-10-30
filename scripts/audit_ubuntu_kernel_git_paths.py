#!/usr/bin/env python3
"""Read-only Ubuntu release-tag source path corroboration for 295 kernel CVEs.

This proves what paths exist at a tagged downstream source snapshot, NOT whether
a particular fix was backported or how generated UAPI/ABI changed. Results never
authorise VEX. Uses official Canonical kernel Git checkout supplied by caller.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
from collections import Counter
from pathlib import Path

SOURCE_REPO = "https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/resolute"
RELEASE_TAG = "Ubuntu-7.0.0-42.42"
RELEASE_VERSION = "7.0.0-42.42"
SHA40 = re.compile(r"^[a-f0-9]{40}$")
EXPECTED = 295


def git(repo: Path, *args: str, check: bool = True) -> str:
    proc = subprocess.run(["git", "-C", str(repo), *args], text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=60, check=False)
    if check and proc.returncode:
        raise ValueError("Ubuntu git source verification failed: " + proc.stderr[:250])
    return proc.stdout.strip() if proc.returncode == 0 else ""


def inspect(upstream: dict, repo: Path, paths: set[str], *,
            exact_tag: str = RELEASE_TAG, require_origin: bool = True) -> dict:
    if upstream.get("package") != "linux-libc-dev=" + RELEASE_VERSION:
        raise ValueError("mismatched binary package source")
    rows = upstream.get("records", [])
    if len(rows) != EXPECTED or len({r["cve"] for r in rows}) != EXPECTED:
        raise ValueError("missing/duplicate CVE affected-file records")
    if require_origin and git(repo, "remote", "get-url", "origin") != SOURCE_REPO:
        raise ValueError("Ubuntu source remote is not Canonical's official Resolute source")
    # A peeled exact release tag, not an evolving master/master-next branch.
    sha = git(repo, "rev-parse", "--verify", exact_tag + "^{commit}")
    if not SHA40.fullmatch(sha):
        raise ValueError("Ubuntu release-tag commit missing")
    checked = git(repo, "rev-parse", "HEAD")
    if checked != sha:
        raise ValueError("Ubuntu checkout is not the exact release-tag commit")
    shallow = git(repo, "rev-parse", "--is-shallow-repository") == "true"
    result = []
    for row in rows:
        cve = row["cve"]
        if row.get("error") or not row.get("upstream_paths"):
            raise ValueError(cve + ": incomplete upstream changed-file claims")
        present, missing = [], []
        for path in row["upstream_paths"]:
            if path.startswith("/") or ".." in path.split("/"):
                raise ValueError(cve + ": invalid upstream source path")
            # Check source object presence without inferring any fix/backport.
            proc = subprocess.run(["git", "-C", str(repo), "cat-file",
                                   "-e", sha + ":" + path],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  timeout=15, check=False)
            (present if proc.returncode == 0 else missing).append(path)
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
        "shallow_history": shallow,
        "note": ("Snapshot path presence is NOT a fixing-commit or backport assessment; "
                 "missing paths can represent renames and do not prove unaffected."),
        "counts": dict(Counter(x["binary_disposition"] for x in result)),
        "records": result,
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--upstream", type=Path, required=True)
    p.add_argument("--ubuntu-checkout", type=Path, required=True)
    p.add_argument("--installed-manifest", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    upstream = json.loads(a.upstream.read_text(encoding="utf-8"))
    installed = set(a.installed_manifest.read_text(encoding="utf-8").splitlines())
    if sum(p.endswith(".h") for p in installed) != 1039:
        raise SystemExit("Exact binary manifest version/header count mismatch")
    report = inspect(upstream, a.ubuntu_checkout, installed)
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("Ubuntu source path review:", report["counts"])
    print("Release tag:", report["ubuntu_release_tag"], "commit:", report["ubuntu_source_commit"])
    print("No Ubuntu patch/backport or binary exposure clearance is asserted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
