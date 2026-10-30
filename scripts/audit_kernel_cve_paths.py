#!/usr/bin/env python3
"""Capture upstream Linux CVE affected-file paths, without making VEX/waiver decisions.

Gitiles file metadata is upstream evidence, not an Ubuntu patch-diff assessment.
An upstream implementation-only path is NOT sufficient for security clearance.
"""
from __future__ import annotations

import argparse
import base64
from collections import Counter
import concurrent.futures
import csv
import json
from pathlib import Path
import re
import sys
import time
from urllib import request

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
SHA_RE = re.compile(r"^[a-f0-9]{40}$")
GITILES = "https://kernel.googlesource.com/pub/scm/linux/security/vulns"


def read_tsv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f, delimiter="\t"))


def upstream_url(cve: str, sha: str) -> str:
    if not CVE_RE.fullmatch(cve) or not SHA_RE.fullmatch(sha):
        raise ValueError("untrusted CVE or upstream source revision")
    return f"{GITILES}/+/{sha}/cve/published/{cve[4:8]}/{cve}.json?format=TEXT"


def parse_upstream(blob: bytes) -> list[str]:
    data = json.loads(base64.b64decode(blob, validate=True))
    if data.get("dataType") != "CVE_RECORD":
        raise ValueError("upstream source is not a published CVE record")
    cna = data.get("containers", {}).get("cna", {})
    paths: set[str] = set()
    for item in cna.get("affected", []):
        if item.get("vendor") != "Linux" or item.get("product") != "Linux":
            continue
        for path in item.get("programFiles", []):
            if isinstance(path, str) and path and not path.startswith("/") and ".." not in path.split("/"):
                paths.add(path)
    if not paths:
        raise ValueError("kernel CVE has no validated affected-file paths")
    return sorted(paths)


def inspect(cve: str, sha: str, manifest: set[str]) -> dict:
    url = upstream_url(cve, sha)
    record: dict = {
        "cve": cve, "upstream_url": url, "upstream_paths": [],
        "affected_headers": [], "matching_shipped_uapi_headers": [],
        "classification": "UPSTREAM_UNVERIFIED", "error": "",
        "binary_disposition": "PENDING_INDEPENDENT_SECURITY_REVIEW",
    }
    for attempt in range(3):
        try:
            req = request.Request(url, headers={"Accept": "text/plain", "User-Agent": "Baobab-DEV10-Kernel-Path-Audit/1"})
            with request.urlopen(req, timeout=28) as result:
                paths = parse_upstream(result.read(1024 * 1024))
            headers = [path for path in paths if path.endswith(".h")]
            matches = []
            for path in headers:
                # Strong positive match only; nonmatches are never called safe.
                suffix = path.split("include/uapi/", 1)[-1] if "include/uapi/" in path else ""
                if suffix and "/usr/include/" + suffix in manifest:
                    matches.append(path)
            record.update({
                "upstream_paths": paths, "affected_headers": headers,
                "matching_shipped_uapi_headers": sorted(matches),
                "classification": "HEADER_PATH_REVIEW_REQUIRED" if headers
                    else "KERNEL_IMPLEMENTATION_PATHS_REVIEW_REQUIRED",
                "error": "",
            })
            break
        except (OSError, ValueError, TypeError, KeyError) as exc:
            record["error"] = f"{type(exc).__name__}: {str(exc)[:180]}"
            if attempt < 2:
                time.sleep(attempt + 1)
    return record


def audit(trivy: list[dict[str, str]], vendor: list[dict[str, str]],
          manifest: set[str], sha: str) -> dict:
    ids = {row["cve"] for row in trivy}
    vendors = {row["cve"]: row for row in vendor}
    if len(trivy) != 295 or len(ids) != 295 or ids != set(vendors) or len(vendor) != 295:
        raise ValueError("Trivy and Canonical evidence must contain the same 295 unique CVEs")
    if not all(CVE_RE.fullmatch(x) for x in ids) or not SHA_RE.fullmatch(sha):
        raise ValueError("invalid CVE or upstream commit")
    if not any(p.endswith(".h") for p in manifest):
        raise ValueError("exact binary manifest has no development headers")
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        rows = list(pool.map(lambda item: inspect(item["cve"], sha, manifest), trivy))
    for row, item in zip(trivy, rows):
        item["severity"] = row["severity"]
        item["canonical_ubuntu_linux_status"] = vendors[row["cve"]]["ubuntu_linux_resolute_status"]
    return {
        "schema": "baobab.dev10.kernel-cve-upstream-file-evidence.v1",
        "decision": "SECURITY_HELD_NO_VEX_NO_EXCEPTIONS",
        "upstream_commit": sha, "package": "linux-libc-dev=7.0.0-42.42",
        "manifest_header_count": sum(p.endswith(".h") for p in manifest),
        "counts": dict(Counter(row["classification"] for row in rows)),
        "records": rows,
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--trivy", type=Path, required=True)
    p.add_argument("--vendor", type=Path, required=True)
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--upstream-sha", required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    try:
        result = audit(read_tsv(a.trivy), read_tsv(a.vendor),
                       set(a.manifest.read_text(encoding="utf-8").splitlines()),
                       a.upstream_sha)
        a.output.parent.mkdir(parents=True, exist_ok=True)
        a.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("Upstream CVE file path evidence:", result["counts"])
        print("All binary dispositions: PENDING_INDEPENDENT_SECURITY_REVIEW")
        return 2 if result["counts"].get("UPSTREAM_UNVERIFIED") else 0
    except (KeyError, ValueError, OSError) as exc:
        print("::error::Incomplete upstream CVE path evidence:", str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
