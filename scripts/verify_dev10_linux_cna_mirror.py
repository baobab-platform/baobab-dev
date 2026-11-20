#!/usr/bin/env python3
"""Verify pinned Linux CNA CVE List mirror records against the pinned kernel.org tree."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from audit_kernel_cve_paths import COMMIT_URL_RE, parse_upstream_details, read_locked_cna_record


def git(repo: Path, *args: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True,
        timeout=90, check=False,
    )
    if result.returncode:
        raise ValueError("git evidence command failed: " + result.stderr.decode(errors="replace")[:240])
    return result.stdout


def git_blob_sha1(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def read_tsv(path: Path) -> list[dict[str, str]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines:
        raise ValueError("empty CVE List mirror TSV")
    header = lines[0].split("\t")
    rows = [dict(zip(header, line.split("\t"), strict=True)) for line in lines[1:]]
    if len(rows) != 41 or len({row["cve"] for row in rows}) != 41:
        raise ValueError("CVE List mirror TSV must contain 41 unique CVEs")
    return rows


def candidate_refs(references: list[str]) -> list[str]:
    return sorted({url for url in references if COMMIT_URL_RE.search(url)})


def candidate_ids(references: list[str]) -> list[str]:
    return sorted({match.group(1) for url in references
                   if (match := COMMIT_URL_RE.search(url))})


def verify(args: argparse.Namespace) -> dict:
    lock = json.loads(args.cvelist_lock.read_text(encoding="utf-8"))
    upstream_lock = json.loads(args.upstream_lock.read_text(encoding="utf-8"))
    rows = read_tsv(args.cvelist_tsv)
    if lock.get("schema") != "baobab.dev10.image-observed-41-cvelist-upstream-lock.v1":
        raise ValueError("unexpected CVE List mirror lock schema")
    source = lock["source"]
    cna_pin = lock["kernel_cna_repository_pin"]
    cvelist_sha = source["commit"]
    kernel_sha = cna_pin["commit"]
    if git(args.cvelist_root, "rev-parse", "HEAD").decode().strip() != cvelist_sha:
        raise ValueError("CVE List checkout does not match pinned commit")
    if git(args.kernel_root, "rev-parse", "HEAD").decode().strip() != kernel_sha:
        raise ValueError("kernel.org CNA checkout does not match pinned commit")
    if source.get("record_count") != 41 or len(lock.get("records", [])) != 41:
        raise ValueError("CVE List lock must contain exactly 41 records")
    if git_blob_sha1(args.cvelist_tsv.read_bytes()) != source.get("record_inventory_blob_sha1"):
        raise ValueError("CVE List TSV blob differs from pinned lock")
    if (upstream_lock.get("cvelist_mirror_lock") != str(args.cvelist_lock)
            or upstream_lock.get("cvelist_mirror_commit") != cvelist_sha
            or upstream_lock.get("cvelist_mirror_inventory_blob_sha1") != source.get("record_inventory_blob_sha1")
            or upstream_lock.get("commit") != kernel_sha):
        raise ValueError("upstream lock does not bind both exact CNA source revisions")
    rows_by_id = {row["cve"]: row for row in rows}
    lock_by_id = {record["cve"]: record for record in lock["records"]}
    if set(rows_by_id) != set(lock_by_id) or set(rows_by_id) != set(upstream_lock["cves"]):
        raise ValueError("CVE List mirror, inventory and kernel CNA lock CVE sets differ")

    results = []
    for cve in sorted(rows_by_id):
        record = lock_by_id[cve]
        row = rows_by_id[cve]
        path = record["path"]
        blob = git(args.cvelist_root, "rev-parse", f"{cvelist_sha}:{path}").decode().strip()
        if blob != record["blob_sha1"] or row["record_blob_sha1"] != blob:
            raise ValueError(cve + ": CVE List record blob differs from its immutable lock")
        cvelist_data = json.loads(git(args.cvelist_root, "show", f"{cvelist_sha}:{path}"))
        cna = cvelist_data.get("containers", {}).get("cna", {})
        if (cna.get("providerMetadata", {}).get("shortName") != "Linux"
                or cvelist_data.get("cveMetadata", {}).get("assignerShortName") != "Linux"):
            raise ValueError(cve + ": CVE List record is not attributed to the Linux CNA")
        cvelist_paths = sorted({item for affected in cna.get("affected", [])
                                for item in affected.get("programFiles", [])})
        cvelist_refs = candidate_refs([item.get("url", "") for item in cna.get("references", [])])
        cvelist_ids = candidate_ids(cvelist_refs)
        if (cvelist_paths != record["affected_source_paths"]
                or cvelist_refs != record["candidate_fix_commit_references"]
                or cvelist_ids != record["candidate_fix_commit_ids"]):
            raise ValueError(cve + ": CVE List record content differs from its indexed source paths/fix references")
        if (row["affected_source_paths"].split(";") != cvelist_paths
                or row["candidate_fix_commit_references"].split(";") != cvelist_refs
                or row["candidate_fix_commit_ids"].split(";") != cvelist_ids):
            raise ValueError(cve + ": CVE List TSV differs from the pinned record")

        kernel_raw = read_locked_cna_record(args.kernel_root, cve, kernel_sha)
        kernel_data = json.loads(kernel_raw)
        if kernel_data.get("cveMetadata", {}).get("cveId") != cve:
            raise ValueError(cve + ": kernel.org CNA record identity mismatch")
        kernel_paths, kernel_references = parse_upstream_details(base64.b64encode(kernel_raw))
        kernel_paths = sorted(set(kernel_paths))
        kernel_refs = candidate_refs(kernel_references)
        kernel_ids = candidate_ids(kernel_references)
        comparison = {
            "affected_source_paths_match": kernel_paths == cvelist_paths,
            "candidate_fix_commit_references_match": kernel_refs == cvelist_refs,
            "candidate_fix_commit_ids_match": kernel_ids == cvelist_ids,
        }
        comparison["match"] = all(comparison.values())
        results.append({
            "cve": cve,
            "cvelist_record_path": path,
            "cvelist_record_blob_sha1": blob,
            "cvelist_record_updated": cvelist_data.get("cveMetadata", {}).get("dateUpdated"),
            "kernel_cna_record_sha256": hashlib.sha256(kernel_raw).hexdigest(),
            "affected_source_paths": cvelist_paths,
            "candidate_fix_commit_references": cvelist_refs,
            "candidate_fix_commit_ids": cvelist_ids,
            "kernel_cna_mirror_comparison": comparison,
        })
    mismatch_count = sum(not item["kernel_cna_mirror_comparison"]["match"] for item in results)
    return {
        "schema": "baobab.dev10.image-observed-41-linux-cna-mirror-reconciliation.v1",
        "status": "MATCHED" if mismatch_count == 0 else "MIRROR_MISMATCH_REQUIRES_REVIEW",
        "cvelist_source": {"repository": source["repository"], "commit": cvelist_sha},
        "kernel_cna_source": {"repository": cna_pin["repository"], "commit": kernel_sha},
        "counts": {
            "records": len(results),
            "records_with_affected_paths": sum(bool(x["affected_source_paths"]) for x in results),
            "total_affected_source_paths": sum(len(x["affected_source_paths"]) for x in results),
            "total_candidate_fix_commits": sum(len(x["candidate_fix_commit_ids"]) for x in results),
            "mirror_mismatches": mismatch_count,
        },
        "records": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cvelist-lock", type=Path, required=True)
    parser.add_argument("--cvelist-tsv", type=Path, required=True)
    parser.add_argument("--upstream-lock", type=Path, required=True)
    parser.add_argument("--cvelist-root", type=Path, required=True)
    parser.add_argument("--kernel-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = verify(args)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")
        print("Linux CNA mirror reconciliation:", result["counts"])
        if result["counts"]["mirror_mismatches"]:
            return 2
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        print("Linux CNA mirror reconciliation denied:", error, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
