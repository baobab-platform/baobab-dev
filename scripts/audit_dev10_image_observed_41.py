#!/usr/bin/env python3
"""Reconcile supplemental 41 image CVEs against pinned Linux CNA and Canonical OSV records.

Evidence capture only: no runtime exploitability, binary applicability, VEX, or
release authorization is inferred.
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit_kernel_cve_paths import SHA_RE, parse_upstream_details

EXPECTED_VERSION = "7.0.0-43.43"
EXPECTED_SOURCE_PURL = "pkg:deb/ubuntu/linux@7.0.0-43.43?arch=source&distro=resolute"
COMMIT_URL_RE = re.compile(
    r"https://git\.kernel\.org/(?:stable|linus)/c/([a-f0-9]{40})(?:[/?#]|$)"
)


def read_tsv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream, delimiter="\t"))


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args], text=True, capture_output=True,
        timeout=30, check=False,
    )
    if result.returncode:
        raise ValueError("git evidence verification failed: " + result.stderr[:200])
    return result.stdout.strip()


def validate_inputs(inventory: list[dict[str, str]], canonical: list[dict[str, str]],
                    lock: dict) -> set[str]:
    ids = {row.get("cve", "") for row in inventory}
    canonical_ids = {row.get("cve", "") for row in canonical}
    lock_records = lock.get("records", [])
    lock_ids = {row.get("cve", "") for row in lock_records}
    if (len(inventory) != 41 or len(ids) != 41 or ids != canonical_ids
            or len(canonical) != 41 or len(lock_records) != 41 or ids != lock_ids):
        raise ValueError("supplemental inventory, Canonical TSV and lock must contain the same 41 unique CVEs")
    if lock.get("schema") != "baobab.dev10.image-observed-cve-canonical-evidence.v1":
        raise ValueError("unsupported supplemental Canonical evidence lock")
    source = lock.get("source", {})
    if (source.get("commit") != "a64faad6c6b5b52353b7300d278e501c0ca75d21"
            or source.get("record_count") != 41
            or source.get("record_inventory_blob_sha1") != "93e1e8b8b20579157234a9e040c1cfdcc1eabfcd"):
        raise ValueError("Canonical source pin or inventory blob differs from reviewed lock")
    for row in canonical:
        if (row.get("installed_7_0_0_43_43_listed_as_affected") != "true"
                or row.get("resolute_source_purl") != EXPECTED_SOURCE_PURL
                or row.get("binary_disposition") != "under_investigation"):
            raise ValueError(row.get("cve", "unknown") + ": Canonical Resolute evidence or disposition is invalid")
    for row in lock_records:
        if row.get("resolute_7_0_0_43_43_affected") is not True:
            raise ValueError(row.get("cve", "unknown") + ": Canonical OSV does not establish 7.0.0-43.43 as affected")
    return ids


def audit(inventory_path: Path, canonical_tsv: Path, canonical_lock_path: Path,
          upstream_root: Path, canonical_root: Path, upstream_sha: str) -> dict:
    if not SHA_RE.fullmatch(upstream_sha):
        raise ValueError("upstream CNA revision must be an immutable 40-character SHA")
    inventory = read_tsv(inventory_path)
    canonical = read_tsv(canonical_tsv)
    lock = json.loads(canonical_lock_path.read_text(encoding="utf-8"))
    ids = validate_inputs(inventory, canonical, lock)
    if git(upstream_root, "rev-parse", "HEAD") != upstream_sha:
        raise ValueError("upstream CNA checkout does not match pinned revision")
    canonical_source = lock["source"]
    canonical_commit = canonical_source["commit"]
    if git(canonical_root, "rev-parse", "HEAD") != canonical_commit:
        raise ValueError("Canonical OSV checkout does not match pinned revision")
    canonical_records = {row["cve"]: row for row in lock["records"]}
    upstream_records = []
    for cve in sorted(ids):
        record_path = upstream_root / "cve" / "published" / cve[4:8] / (cve + ".json")
        raw = record_path.read_bytes()
        if len(raw) > 1024 * 1024:
            raise ValueError(cve + ": upstream CNA record exceeds 1 MiB")
        data = json.loads(raw)
        if (data.get("dataType") != "CVE_RECORD"
                or data.get("cveMetadata", {}).get("cveId") != cve):
            raise ValueError(cve + ": upstream CNA record identity mismatch")
        canonical_record = canonical_records[cve]
        actual_blob = git(canonical_root, "rev-parse",
                          f"{canonical_commit}:{canonical_record['path']}")
        if actual_blob != canonical_record["blob_sha1"]:
            raise ValueError(cve + ": Canonical OSV blob SHA differs from pinned lock")
        paths, references = parse_upstream_details(base64.b64encode(raw))
        candidate_commit_references = sorted(
            url for url in references if COMMIT_URL_RE.search(url)
        )
        candidate_commits = sorted({
            match.group(1) for url in candidate_commit_references
            if (match := COMMIT_URL_RE.search(url))
        })
        if not paths:
            raise ValueError(cve + ": no validated Linux affected source paths")
        upstream_records.append({
            "cve": cve,
            "upstream_record_path": str(record_path.relative_to(upstream_root)),
            "upstream_record_sha256": hashlib.sha256(raw).hexdigest(),
            "affected_source_paths": paths,
            "upstream_references": references,
            "candidate_fix_commit_references": candidate_commit_references,
            "candidate_fix_commit_ids": candidate_commits,
            "canonical_osv_record_path": canonical_record["path"],
            "canonical_osv_blob_sha1": canonical_record["blob_sha1"],
            "canonical_modified": canonical_record["modified"],
            "canonical_ubuntu_priority": canonical_record["ubuntu_priority"],
            "canonical_resolute_source_package": "linux",
            "canonical_resolute_affected_version": EXPECTED_VERSION,
            "ubuntu_binary_applicability": "under_investigation",
            "vex_disposition": "under_investigation",
        })
    return {
        "schema": "baobab.dev10.image-observed-cve-upstream-canonical-evidence.v1",
        "status": "SOURCE_RECORDS_VERIFIED_NO_BINARY_DISPOSITION",
        "upstream": {
            "repository": "https://kernel.googlesource.com/pub/scm/linux/security/vulns",
            "commit": upstream_sha,
            "record_count": len(upstream_records),
        },
        "canonical": {
            "repository": canonical_source["repository"],
            "commit": canonical_commit,
            "record_count": len(canonical_records),
            "resolute_source_package": "linux",
            "affected_version": EXPECTED_VERSION,
        },
        "counts": {
            "records": len(upstream_records),
            "records_with_candidate_fix_commit_ids": sum(bool(x["candidate_fix_commit_ids"]) for x in upstream_records),
            "records_with_affected_paths": sum(bool(x["affected_source_paths"]) for x in upstream_records),
        },
        "policy_boundary": lock["policy_boundary"],
        "records": upstream_records,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--canonical-tsv", type=Path, required=True)
    parser.add_argument("--canonical-lock", type=Path, required=True)
    parser.add_argument("--upstream-root", type=Path, required=True)
    parser.add_argument("--canonical-root", type=Path, required=True)
    parser.add_argument("--upstream-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = audit(args.inventory, args.canonical_tsv, args.canonical_lock,
                       args.upstream_root, args.canonical_root, args.upstream_sha)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("Verified supplemental upstream/CNA + Canonical records:", result["counts"])
        print("All binary and VEX dispositions remain under investigation.")
        return 0
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError,
            subprocess.TimeoutExpired) as exc:
        print("::error::Incomplete supplemental 41-CVE source evidence:", str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
