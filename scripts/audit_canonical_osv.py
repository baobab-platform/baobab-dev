#!/usr/bin/env python3
"""Validate and digest Canonical's pinned Ubuntu OSV records without VEX inference."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from dev10_evidence_lock import EvidenceLock

LOCK = EvidenceLock.load()
CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
TARGET_ECOSYSTEM = "Ubuntu:26.04:LTS"
TARGET_SOURCE_PACKAGE = "linux"
TARGET_BINARY_PACKAGE = "linux-libc-dev"


def read_inventory(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream, delimiter="\t"))
    ids = [row.get("cve", "") for row in rows]
    if len(rows) != LOCK.inventory_count or len(set(ids)) != LOCK.inventory_count:
        raise ValueError("Canonical OSV input must match the unique CVEs in the evidence lock")
    if any(not CVE_RE.fullmatch(cve) for cve in ids):
        raise ValueError("Canonical OSV inventory contains an invalid CVE identifier")
    return rows


def require_git_revision(root: Path) -> None:
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        text=True, capture_output=True, check=False, timeout=20,
    )
    if result.returncode or result.stdout.strip() != LOCK.canonical_osv_commit:
        raise ValueError("Canonical OSV checkout differs from the reviewed evidence lock")
    committed = subprocess.run(
        ["git", "-C", str(root), "show", "-s", "--format=%cI", "HEAD"],
        text=True, capture_output=True, check=False, timeout=20,
    )
    if committed.returncode:
        raise ValueError("Canonical OSV commit timestamp unavailable")
    commit_time = datetime.fromisoformat(committed.stdout.strip().replace("Z", "+00:00"))
    age = datetime.now(timezone.utc) - commit_time.astimezone(timezone.utc)
    if age.total_seconds() < 0 or age.total_seconds() > 7 * 86400:
        raise ValueError("pinned Canonical OSV snapshot is older than the seven-day freshness window")


def extract_record(cve: str, root: Path, retrieved_at: str, raw_dir: Path) -> dict:
    year = cve[4:8]
    path = root / LOCK.canonical_osv_snapshot_path / year / f"UBUNTU-{cve}.json"
    raw = path.read_bytes()
    if len(raw) > 4 * 1024 * 1024:
        raise ValueError(f"{cve}: Canonical OSV record exceeds 4 MiB")
    data = json.loads(raw)
    if data.get("schema_version") != "1.7.0":
        raise ValueError(f"{cve}: unsupported Canonical OSV schema version")
    if data.get("id") != f"UBUNTU-{cve}" or cve not in data.get("upstream", []):
        raise ValueError(f"{cve}: Canonical OSV identity/upstream mapping mismatch")
    modified = data.get("modified")
    published = data.get("published")
    parsed = {}
    for value, label in ((modified, "modified"), (published, "published")):
        if not isinstance(value, str):
            raise ValueError(f"{cve}: missing Canonical OSV {label} timestamp")
        parsed[label] = datetime.fromisoformat(value.replace("Z", "+00:00"))
    retrieved = datetime.fromisoformat(retrieved_at.replace("Z", "+00:00"))
    if parsed["published"] > parsed["modified"] or parsed["modified"] > retrieved:
        raise ValueError(f"{cve}: Canonical OSV timestamps are inconsistent or future-dated")

    release_entries = []
    for affected in data.get("affected", []):
        package = affected.get("package", {})
        if package.get("ecosystem") != TARGET_ECOSYSTEM or package.get("name") != TARGET_SOURCE_PACKAGE:
            continue
        binaries = affected.get("ecosystem_specific", {}).get("binaries", [])
        binary_versions = sorted({
            item.get("binary_version") for item in binaries
            if item.get("binary_name") == TARGET_BINARY_PACKAGE
            and isinstance(item.get("binary_version"), str)
        })
        fixed_versions = sorted({
            event["fixed"]
            for version_range in affected.get("ranges", [])
            for event in version_range.get("events", [])
            if isinstance(event, dict) and isinstance(event.get("fixed"), str)
        })
        purl = package.get("purl", "")
        source_version = purl.split("@", 1)[1].split("?", 1)[0] if "@" in purl else None
        release_entries.append({
            "source_package": package.get("name"),
            "source_package_purl": purl,
            "source_package_version": source_version,
            "linux_libc_dev_binary_versions": binary_versions,
            "canonical_fixed_versions": fixed_versions,
            "target_binary_version_listed": LOCK.package_version in binary_versions,
            "target_version_in_affected_versions": LOCK.package_version in affected.get("versions", []),
        })
    if not release_entries:
        # Missing package entries are an evidence gap, never a negative status.
        release_evidence = "NO_UBUNTU_26_04_LINUX_SOURCE_ENTRY"
    elif any(entry["target_binary_version_listed"]
             for entry in release_entries):
        release_evidence = "TARGET_BINARY_VERSION_LISTED_AS_AFFECTED"
    elif any(entry["target_version_in_affected_versions"] for entry in release_entries):
        release_evidence = "SOURCE_VERSION_AFFECTED_BINARY_VERSION_UNLISTED"
    else:
        release_evidence = "TARGET_BINARY_VERSION_NOT_LISTED_REQUIRES_REVIEW"

    raw_dir.mkdir(parents=True, exist_ok=True)
    raw_path = raw_dir / f"UBUNTU-{cve}.json"
    raw_path.write_bytes(raw)
    return {
        "cve": cve,
        "canonical_id": data["id"],
        "schema_version": data["schema_version"],
        "published": published,
        "modified": modified,
        "retrieved_at": retrieved_at,
        "source_path": str(path.relative_to(root)),
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "raw_size_bytes": len(raw),
        "ubuntu_26_04_linux_source_entries": release_entries,
        "release_evidence": release_evidence,
        "disposition": "UNDER_INVESTIGATION_NO_VEX_NO_EXCEPTION",
        "raw_artifact": str(raw_path.name),
    }


def audit(inventory: list[dict[str, str]], root: Path, output: Path) -> dict:
    require_git_revision(root)
    retrieved_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    raw_dir = output.parent / "canonical-osv-raw"
    with ThreadPoolExecutor(max_workers=8) as pool:
        records = list(pool.map(
            lambda row: extract_record(row["cve"], root, retrieved_at, raw_dir),
            inventory,
        ))
    if len(records) != LOCK.canonical_count or len({row["cve"] for row in records}) != LOCK.canonical_count:
        raise ValueError("Canonical OSV snapshot is incomplete or duplicated")
    counts = {}
    for row in records:
        counts[row["release_evidence"]] = counts.get(row["release_evidence"], 0) + 1
    return {
        "schema": "baobab.dev10.canonical-osv-evidence.v1",
        "source_repository": LOCK.canonical_osv_repository,
        "source_commit": LOCK.canonical_osv_commit,
        "retrieved_at": retrieved_at,
        "release": TARGET_ECOSYSTEM,
        "source_package": TARGET_SOURCE_PACKAGE,
        "binary_package": TARGET_BINARY_PACKAGE,
        "target_binary_version": LOCK.package_version,
        "record_count": len(records),
        "counts": counts,
        "disposition": "UNDER_INVESTIGATION_NO_VEX_NO_EXCEPTION",
        "records": records,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--canonical-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = audit(read_inventory(args.inventory), args.canonical_root, args.output)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("Canonical OSV records:", report["record_count"])
    print("Pinned Canonical source commit:", report["source_commit"])
    print("Ubuntu 26.04 source/binary evidence:", report["counts"])
    print("No VEX, exception or not-affected disposition inferred.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
