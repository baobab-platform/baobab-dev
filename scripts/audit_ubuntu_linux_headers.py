#!/usr/bin/env python3
"""Capture Canonical per-CVE Ubuntu 26.04 source-package status without waivers.

Reads an immutable Trivy finding inventory (one CVE per row) and produces a
reviewable vendor fact set.  It does NOT conclude individual exploitability or
modify any Trivy exit code / ignore list.
"""
from __future__ import annotations
import argparse
import concurrent.futures
import csv
import json
from collections import Counter
from pathlib import Path
import re
import sys
import time
import urllib.error
import urllib.request

CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
API = "https://ubuntu.com/security/cves/"


def get_vendor(row: dict[str, str]) -> dict:
    cve = row["cve"]
    result: dict = {
        "cve": cve, "severity": row["severity"], "trivy_title": row["trivy_title"],
        "url": API + cve + ".json",
        "source_package": "linux", "ubuntu_release": "resolute",
        "ubuntu_status": "UNVERIFIED", "ubuntu_detail": "",
        "canonical_priority": "", "vendor_updated_at": "",
        "affected_implementation": "REQUIRES_PATCH_PATH_REVIEW",
        "vendor_description": "", "error": "",
    }
    for attempt in range(3):
        try:
            req = urllib.request.Request(result["url"], headers={"Accept": "application/json", "User-Agent": "Baobab-DEV10-vendor-advisory-audit/1.0"})
            with urllib.request.urlopen(req, timeout=22) as response:
                data = json.load(response)
            if not isinstance(data, dict) or data.get("id") != cve:
                raise ValueError("vendor response CVE ID mismatch")
            result["canonical_priority"] = data.get("priority") or ""
            result["vendor_updated_at"] = data.get("updated_at") or ""
            result["vendor_description"] = data.get("description") or ""
            found = False
            for package in data.get("packages") or []:
                if package.get("name") != "linux":
                    continue
                for status in package.get("statuses") or []:
                    if status.get("release_codename") == "resolute" and status.get("pocket") == "security":
                        result["ubuntu_status"] = status.get("status") or "UNVERIFIED"
                        result["ubuntu_detail"] = status.get("description") or ""
                        found = True
                        break
                if found:
                    break
            if not found:
                result["error"] = "No Ubuntu 26.04 linux/security source-package status in Canonical API"
            # Description identifies a candidate source family; it does NOT
            # establish an accepted per-CVE applicability decision.
            desc = (result["vendor_description"] + " " + result["trivy_title"]).lower()
            if "linux kernel" in desc or result["trivy_title"].lower().startswith("kernel:"):
                result["affected_implementation"] = "KERNEL_IMPLEMENTATION_CANDIDATE_REVIEW_REQUIRED"
            return result
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            result["error"] = type(exc).__name__ + ": " + str(exc)[:200]
            if attempt != 2:
                time.sleep(1.5 * (attempt + 1))
    return result


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--inventory", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    with args.inventory.open(newline="") as stream:
        rows = list(csv.DictReader(stream, delimiter="\t"))
    ids = [r["cve"] for r in rows]
    if len(rows) != 295 or len(set(ids)) != 295 or not all(CVE_PATTERN.fullmatch(x) for x in ids):
        raise SystemExit("Invalid/partial Trivy inventory; expected exactly 295 distinct CVEs")
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        records = list(pool.map(get_vendor, rows))
    summary = {
        "schema": "baobab.dev10.canonical-kernel-source-status.v1",
        "status": "REVIEW_ONLY_NO_EXCEPTIONS",
        "package": "linux-libc-dev",
        "installed_package_version": "7.0.0-42.42",
        "ubuntu_source_package": "linux",
        "ubuntu_release": "resolute",
        "cves": len(records),
        "vendor_verified": sum(r["ubuntu_status"] != "UNVERIFIED" for r in records),
        "vendor_status_counts": dict(Counter(r["ubuntu_status"] for r in records)),
        "candidate_runtime_impl": sum(r["affected_implementation"] == "KERNEL_IMPLEMENTATION_CANDIDATE_REVIEW_REQUIRED" for r in records),
        "no_automated_applicability_or_waivers": True,
        "records": records,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print("Canonical verification:", summary["vendor_verified"], "/", len(records))
    print("Canonical Ubuntu 26.04 linux status counts:", summary["vendor_status_counts"])
    print("Candidate kernel implementation review:", summary["candidate_runtime_impl"])
    for r in records:
        print("VENDOR_CVE " + json.dumps({
            "id": r["cve"], "severity": r["severity"], "status": r["ubuntu_status"],
            "detail": r["ubuntu_detail"], "updated": r["vendor_updated_at"],
            "candidate": r["affected_implementation"], "error": r["error"]
        }, separators=(",", ":"), sort_keys=True))
    return 0 if summary["vendor_verified"] == len(records) else 2


if __name__ == "__main__":
    sys.exit(main())
