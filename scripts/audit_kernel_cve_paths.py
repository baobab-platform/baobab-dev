#!/usr/bin/env python3
"""Capture upstream Linux CVE affected-file paths, without making VEX/waiver decisions.

Gitiles file metadata is upstream evidence, not an Ubuntu patch-diff assessment.
An upstream implementation-only path is NOT sufficient for security clearance.
"""
from __future__ import annotations

import argparse
import base64
from collections import Counter
import csv
import json
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dev10_evidence_lock import EvidenceLock

LOCK = EvidenceLock.load()
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
SHA_RE = re.compile(r"^[a-f0-9]{40}$")
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+-\d+\.\d+$")
GITILES = "https://kernel.googlesource.com/pub/scm/linux/security/vulns"


def read_tsv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f, delimiter="\t"))


def upstream_url(cve: str, sha: str) -> str:
    if not CVE_RE.fullmatch(cve) or not SHA_RE.fullmatch(sha):
        raise ValueError("untrusted CVE or upstream source revision")
    return f"{GITILES}/+/{sha}/cve/published/{cve[4:8]}/{cve}.json?format=TEXT"


def parse_upstream_details(blob: bytes) -> tuple[list[str], list[str]]:
    """Return upstream candidate paths and reference URLs, not fix attestations."""
    data = json.loads(base64.b64decode(blob, validate=True))
    if data.get("dataType") != "CVE_RECORD":
        raise ValueError("upstream source is not a published CVE record")
    cna = data.get("containers", {}).get("cna", {})
    paths: set[str] = set()
    for item in cna.get("affected", []):
        if item.get("vendor") != "Linux" or item.get("product") != "Linux":
            continue
        for path in item.get("programFiles", []):
            if (isinstance(path, str) and path and not path.startswith("/")
                    and "\\" not in path
                    and not any(ord(ch) < 32 or ord(ch) == 127 for ch in path)
                    and all(part not in {"", ".", ".."} for part in path.split("/"))):
                paths.add(path)
            elif isinstance(path, str):
                raise ValueError("upstream CVE contains an unsafe source path")
    if not paths:
        raise ValueError("kernel CVE has no validated affected-file paths")
    refs: set[str] = set()
    for entry in cna.get("references", []):
        url = entry.get("url") if isinstance(entry, dict) else None
        if isinstance(url, str) and url.startswith("https://") and len(url) < 1024:
            refs.add(url)
    return sorted(paths), sorted(refs)


def parse_upstream(blob: bytes) -> list[str]:
    """Backward-compatible affected-path reader for existing verified tests."""
    return parse_upstream_details(blob)[0]


def inspect(cve: str, sha: str, manifest: set[str], source_root: Path) -> dict:
    url = upstream_url(cve, sha)
    record: dict = {
        "cve": cve, "upstream_url": url, "upstream_paths": [], "candidate_upstream_fix_references": [],
        "affected_headers": [], "matching_shipped_uapi_headers": [],
        "classification": "UPSTREAM_UNVERIFIED", "error": "",
        "binary_disposition": "PENDING_INDEPENDENT_SECURITY_REVIEW",
    }
    try:
        # Only a caller-supplied immutable Git checkout is accepted. No live
        # HTTP fallback: identical inputs must always produce identical evidence.
        local = source_root / "cve" / "published" / cve[4:8] / (cve + ".json")
        blob = local.read_bytes()
        if len(blob) > 1024 * 1024:
            raise ValueError("upstream CVE JSON exceeds 1 MiB")
        paths, refs = parse_upstream_details(base64.b64encode(blob))
        headers = [path for path in paths if path.endswith(".h")]
        matches = []
        for path in headers:
            suffix = path.split("include/uapi/", 1)[-1] if "include/uapi/" in path else ""
            if suffix and "/usr/include/" + suffix in manifest:
                matches.append(path)
        record.update({
            "upstream_paths": paths, "candidate_upstream_fix_references": refs,
            "affected_headers": headers,
            "matching_shipped_uapi_headers": sorted(matches),
            "classification": "HEADER_PATH_REVIEW_REQUIRED" if headers
                else "KERNEL_IMPLEMENTATION_PATHS_REVIEW_REQUIRED",
            "error": "",
        })
    except (OSError, ValueError, TypeError, KeyError) as exc:
        record["error"] = f"{type(exc).__name__}: {str(exc)[:180]}"
    return record


def audit(trivy: list[dict[str, str]], vendor: list[dict[str, str]],
          manifest: set[str], sha: str, package_version: str, source_root: Path) -> dict:
    ids = {row["cve"] for row in trivy}
    vendors = {row["cve"]: row for row in vendor}
    if (len(trivy) != LOCK.inventory_count or len(ids) != LOCK.inventory_count
            or ids != set(vendors) or len(vendor) != LOCK.canonical_count):
        raise ValueError("Trivy and Canonical evidence must match the reviewed evidence lock")
    if not all(CVE_RE.fullmatch(x) for x in ids) or not SHA_RE.fullmatch(sha):
        raise ValueError("invalid CVE or upstream commit")
    if package_version != LOCK.package_version:
        raise ValueError("installed linux-libc-dev binary package version differs from evidence lock")
    if not any(p.endswith(".h") for p in manifest):
        raise ValueError("exact binary manifest has no development headers")
    # A mutable branch checkout is not sufficient evidence. Validate the local
    # Git object identity independently of the workflow before reading files.
    checked = subprocess.run(["git", "-C", str(source_root), "rev-parse", "HEAD"],
                             text=True, capture_output=True, check=False, timeout=15)
    if checked.returncode != 0 or checked.stdout.strip() != sha:
        raise ValueError("upstream Git checkout revision mismatch")
    rows = [inspect(item["cve"], sha, manifest, source_root) for item in trivy]
    for row, item in zip(trivy, rows):
        item["severity"] = row["severity"]
        item["canonical_ubuntu_linux_status"] = vendors[row["cve"]]["ubuntu_linux_resolute_status"]
    return {
        "schema": "baobab.dev10.kernel-cve-upstream-file-evidence.v1",
        "decision": "SECURITY_HELD_NO_VEX_NO_EXCEPTIONS",
        "upstream_commit": sha, "package": f"linux-libc-dev={package_version}",
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
    p.add_argument("--binary-package-version", required=True,
                   help="exact linux-libc-dev version installed from the configured Ubuntu pockets")
    p.add_argument("--upstream-root", type=Path, required=True, help="required immutable Git checkout; network fallback is disabled")
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    try:
        result = audit(read_tsv(a.trivy), read_tsv(a.vendor),
                       set(a.manifest.read_text(encoding="utf-8").splitlines()),
                       a.upstream_sha, a.binary_package_version, a.upstream_root)
        a.output.parent.mkdir(parents=True, exist_ok=True)
        a.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("Upstream CVE file path evidence:", result["counts"])
        print("Pinned upstream Linux CVE revision:", result["upstream_commit"])
        for item in result["records"]:
            if item["classification"] == "UPSTREAM_UNVERIFIED":
                print("::error::UPSTREAM_UNVERIFIED " + json.dumps({
                    "cve": item["cve"], "url": item["upstream_url"],
                    "reason": item["error"]}, sort_keys=True))
            if item["classification"] == "HEADER_PATH_REVIEW_REQUIRED":
                print("HEADER_REVIEW " + json.dumps({
                    "cve": item["cve"], "severity": item["severity"],
                    "upstream_headers": item["affected_headers"],
                    "shipped_uapi_path_matches": item["matching_shipped_uapi_headers"],
                    "status": item["canonical_ubuntu_linux_status"]
                }, separators=(",", ":"), sort_keys=True))
        print("All binary dispositions: PENDING_INDEPENDENT_SECURITY_REVIEW")
        return 2 if result["counts"].get("UPSTREAM_UNVERIFIED") else 0
    except (KeyError, ValueError, OSError, subprocess.TimeoutExpired) as exc:
        print("::error::Incomplete upstream CVE path evidence:", str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
