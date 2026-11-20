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
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit_kernel_cve_paths import COMMIT_URL_RE, SHA_RE, parse_upstream_details, read_locked_cna_record

EXPECTED_VERSION = "7.0.0-43.43"
EXPECTED_BINARY_PACKAGE = "linux-libc-dev"
EXPECTED_SOURCE_PURL = "pkg:deb/ubuntu/linux@7.0.0-43.43?arch=source&distro=resolute"


def read_tsv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream, delimiter="\t"))


def git_blob_sha1(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


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
            or not SHA_RE.fullmatch(source.get("record_inventory_blob_sha1", ""))):
        raise ValueError("Canonical source pin or inventory blob differs from reviewed lock")
    locked_by_id = {row["cve"]: row for row in lock_records}
    for row in canonical:
        locked = locked_by_id[row["cve"]]
        if (row.get("canonical_osv_blob_sha") != locked.get("blob_sha1")
                or row.get("canonical_modified") != locked.get("modified")
                or row.get("canonical_osv_ubuntu_severity") != locked.get("canonical_osv_ubuntu_severity")
                or row.get("canonical_linux_source_version_7_0_0_43_43_affected") != "true"
                or row.get("canonical_linux_libc_dev_binary_version") != EXPECTED_VERSION
                or row.get("canonical_linux_libc_dev_binary_listed_as_affected") != "true"
                or locked.get("canonical_linux_source_version_affected") is not True
                or locked.get("linux_libc_dev_binary_version") != EXPECTED_VERSION
                or locked.get("linux_libc_dev_binary_listed_as_affected") is not True):
            raise ValueError(row["cve"] + ": Canonical TSV does not match its pinned OSV blob metadata")
        if (row.get("resolute_source_purl") != EXPECTED_SOURCE_PURL
                or row.get("binary_disposition") != "under_investigation"):
            raise ValueError(row.get("cve", "unknown") + ": Canonical Resolute evidence or disposition is invalid")
    binary_mapping = lock.get("source", {}).get("binary_package_mapping", {})
    if (binary_mapping.get("binary_package") != EXPECTED_BINARY_PACKAGE
            or binary_mapping.get("binary_version") != EXPECTED_VERSION
            or binary_mapping.get("records_listed_as_affected") != 41):
        raise ValueError("Canonical lock does not pin all 41 linux-libc-dev binary associations")
    for row in lock_records:
        if row.get("resolute_7_0_0_43_43_affected") is not True:
            raise ValueError(row.get("cve", "unknown") + ": Canonical OSV does not establish 7.0.0-43.43 as affected")
    return ids


def audit(inventory_path: Path, canonical_tsv: Path, canonical_lock_path: Path,
          upstream_lock_path: Path, upstream_root: Path, canonical_root: Path,
          upstream_sha: str) -> dict:
    if not SHA_RE.fullmatch(upstream_sha):
        raise ValueError("upstream CNA revision must be an immutable 40-character SHA")
    inventory = read_tsv(inventory_path)
    canonical = read_tsv(canonical_tsv)
    lock = json.loads(canonical_lock_path.read_text(encoding="utf-8"))
    upstream_lock = json.loads(upstream_lock_path.read_text(encoding="utf-8"))
    ids = validate_inputs(inventory, canonical, lock)
    if (upstream_lock.get("schema") != "baobab.dev10.image-observed-cve-upstream-source-lock.v1"
            or upstream_lock.get("commit") != upstream_sha
            or upstream_lock.get("record_count") != 41
            or len(upstream_lock.get("cves", [])) != 41
            or set(upstream_lock.get("cves", [])) != ids
            or upstream_lock.get("record_inventory_blob_sha1") != git_blob_sha1(inventory_path.read_bytes())):
        raise ValueError("upstream CNA revision, CVE set or inventory blob differs from immutable source lock")
    if upstream_lock.get("canonical_evidence_lock") != str(canonical_lock_path).replace("\\\\", "/"):
        raise ValueError("upstream lock does not bind the Canonical evidence lock path")
    if git_blob_sha1(canonical_tsv.read_bytes()) != lock["source"]["record_inventory_blob_sha1"]:
        raise ValueError("Canonical OSV index TSV blob differs from immutable Canonical source lock")
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
        raw = read_locked_cna_record(upstream_root, cve, upstream_sha)
        data = json.loads(raw)
        if (data.get("dataType") != "CVE_RECORD"
                or data.get("cveMetadata", {}).get("cveId") != cve):
            raise ValueError(cve + ": upstream CNA record identity mismatch")
        canonical_record = canonical_records[cve]
        actual_blob = git(canonical_root, "rev-parse",
                          f"{canonical_commit}:{canonical_record['path']}")
        if actual_blob != canonical_record["blob_sha1"]:
            raise ValueError(cve + ": Canonical OSV blob SHA differs from pinned lock")
        canonical_data = json.loads(git(canonical_root, "show", f"{canonical_commit}:{canonical_record['path']}"))
        if canonical_data.get("id") != "UBUNTU-" + cve or canonical_data.get("modified") != canonical_record["modified"]:
            raise ValueError(cve + ": Canonical OSV identity or modified timestamp differs from lock")
        ubuntu_severity = next(
            (item.get("score") for item in canonical_data.get("severity", [])
             if item.get("type") == "Ubuntu"), None
        )
        if ubuntu_severity != canonical_record["canonical_osv_ubuntu_severity"]:
            raise ValueError(cve + ": Canonical Ubuntu priority differs from pinned OSV record")
        resolute_linux = [
            item for item in canonical_data.get("affected", [])
            if item.get("package", {}).get("name") == "linux"
            and item.get("package", {}).get("purl") == EXPECTED_SOURCE_PURL
            and EXPECTED_VERSION in item.get("versions", [])
        ]
        if len(resolute_linux) != 1:
            raise ValueError(cve + ": Canonical OSV does not list the exact Resolute linux source version as affected")
        binaries = resolute_linux[0].get("ecosystem_specific", {}).get("binaries", [])
        if not any(item.get("binary_name") == EXPECTED_BINARY_PACKAGE
                   and item.get("binary_version") == EXPECTED_VERSION for item in binaries):
            raise ValueError(cve + ": Canonical OSV does not list linux-libc-dev 7.0.0-43.43 as affected")
        try:
            paths, references = parse_upstream_details(base64.b64encode(raw))
            path_status = "AFFECTED_SOURCE_PATHS_VALIDATED"
        except ValueError as error:
            if str(error) != "kernel CVE has no validated affected-file paths":
                raise
            cna = data.get("containers", {}).get("cna", {})
            paths = []
            references = sorted({
                item["url"] for item in cna.get("references", [])
                if isinstance(item, dict) and isinstance(item.get("url"), str)
                and item["url"].startswith("https://") and len(item["url"]) < 1024
            })
            path_status = "CNA_RECORD_HAS_NO_VALIDATED_AFFECTED_FILE_PATHS"
        candidate_commit_references = sorted(
            url for url in references if COMMIT_URL_RE.search(url)
        )
        candidate_commits = sorted({
            match.group(1) for url in candidate_commit_references
            if (match := COMMIT_URL_RE.search(url))
        })
        upstream_records.append({
            "cve": cve,
            "upstream_record_path": str(record_path.relative_to(upstream_root)),
            "upstream_record_sha256": hashlib.sha256(raw).hexdigest(),
            "affected_source_paths": paths,
            "affected_source_path_status": path_status,
            "upstream_references": references,
            "candidate_fix_commit_references": candidate_commit_references,
            "candidate_fix_commit_ids": candidate_commits,
            "canonical_osv_record_path": canonical_record["path"],
            "canonical_osv_blob_sha1": canonical_record["blob_sha1"],
            "canonical_modified": canonical_record["modified"],
            "canonical_osv_ubuntu_severity": canonical_record["canonical_osv_ubuntu_severity"],
            "canonical_resolute_source_package": "linux",
            "canonical_resolute_affected_version": EXPECTED_VERSION,
            "canonical_linux_libc_dev_binary_version": EXPECTED_VERSION,
            "canonical_linux_libc_dev_binary_listed_as_affected": True,
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
            "binary_package": EXPECTED_BINARY_PACKAGE,
            "binary_version": EXPECTED_VERSION,
            "binary_records_listed_as_affected": 41,
        },
        "counts": {
            "records": len(upstream_records),
            "records_with_candidate_fix_commit_ids": sum(bool(x["candidate_fix_commit_ids"]) for x in upstream_records),
            "records_with_affected_paths": sum(bool(x["affected_source_paths"]) for x in upstream_records),
            "records_without_affected_paths": sum(not x["affected_source_paths"] for x in upstream_records),
        },
        "policy_boundary": lock["policy_boundary"],
        "records": upstream_records,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--canonical-tsv", type=Path, required=True)
    parser.add_argument("--canonical-lock", type=Path, required=True)
    parser.add_argument("--upstream-lock", type=Path, required=True)
    parser.add_argument("--upstream-root", type=Path, required=True)
    parser.add_argument("--canonical-root", type=Path, required=True)
    parser.add_argument("--upstream-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = audit(args.inventory, args.canonical_tsv, args.canonical_lock,
                       args.upstream_lock, args.upstream_root, args.canonical_root, args.upstream_sha)
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
