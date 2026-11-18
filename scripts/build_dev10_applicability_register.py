#!/usr/bin/env python3
"""Conservative, reviewable DEV-10 CVE applicability register.

Joins immutable scanner, Canonical and upstream evidence. Never converts a path
nonmatch or source-package status to an approved binary applicability verdict.
Ubuntu downstream patch provenance must be independently supplied and reviewed.
"""
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
import re
import sys
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dev10_evidence_lock import EvidenceLock

LOCK = EvidenceLock.load()
COUNT = LOCK.inventory_count
SOURCE_SHA = LOCK.upstream_sha


def tsv(path: Path) -> list[dict]:
    with path.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream, delimiter="\t"))


def unique(rows: list[dict], label: str) -> dict[str, dict]:
    result = {row["cve"]: row for row in rows}
    if len(rows) != COUNT or len(result) != COUNT:
        raise ValueError(f"{label}: expected exactly {COUNT} unique CVEs")
    return result


def build(scanner: list[dict], canonical: list[dict],
          upstream: dict | None = None, ubuntu_patches: dict | None = None,
          canonical_osv: dict | None = None, now: datetime | None = None) -> dict:
    by_scanner = unique(scanner, "Trivy")
    by_vendor = unique(canonical, "Canonical")
    if set(by_scanner) != set(by_vendor):
        raise ValueError("Trivy and Canonical CVE IDs differ")
    upstream_rows = {}
    source_sha = SOURCE_SHA  # Historical reference only when no live upstream input is provided.
    if upstream is not None:
        source_sha = upstream.get("upstream_commit")
        if source_sha != LOCK.upstream_sha:
            raise ValueError("upstream source revision differs from reviewed evidence lock")
        upstream_rows = unique(upstream["records"], "upstream")
        if set(upstream_rows) != set(by_scanner):
            raise ValueError("upstream CVE IDs differ")
        if any(row.get("error") or row.get("classification") == "UPSTREAM_UNVERIFIED"
               for row in upstream_rows.values()):
            raise ValueError("upstream evidence contains unverified cases")
    # Optional Ubuntu-specific evidence must be supplied as separate auditable
    # source-file/commit facts. It is NOT an independent authorisation.
    patch_rows = {}
    canonical_osv_rows = {}
    if canonical_osv is not None:
        if canonical_osv.get("source_commit") != LOCK.canonical_osv_commit:
            raise ValueError("Canonical OSV source revision differs from evidence lock")
        if canonical_osv.get("target_binary_version") != LOCK.package_version:
            raise ValueError("Canonical OSV target package version differs from evidence lock")
        if canonical_osv.get("record_count") != LOCK.canonical_count:
            raise ValueError("Canonical OSV record count differs from evidence lock")
        retrieved_at = datetime.fromisoformat(
            canonical_osv["retrieved_at"].replace("Z", "+00:00")
        )
        age = (now or datetime.now(timezone.utc)) - retrieved_at.astimezone(timezone.utc)
        if age.total_seconds() < 0 or age.total_seconds() > 7 * 86400:
            raise ValueError("Canonical OSV snapshot is outside the seven-day freshness window")
        canonical_osv_rows = unique(canonical_osv["records"], "Canonical OSV")
        if set(canonical_osv_rows) != set(by_scanner):
            raise ValueError("Canonical OSV CVE IDs differ from inventory")
        if any(not re.fullmatch(r"[a-f0-9]{64}", row.get("raw_sha256", ""))
               or row.get("disposition") != "UNDER_INVESTIGATION_NO_VEX_NO_EXCEPTION"
               for row in canonical_osv_rows.values()):
            raise ValueError("Canonical OSV evidence has invalid digest or disposition")
    if ubuntu_patches is not None and canonical_osv is None:
        raise ValueError("fresh pinned Canonical OSV evidence is required for Ubuntu-tag register")
    if ubuntu_patches is not None:
        if ubuntu_patches.get("ubuntu_release_tag") != LOCK.ubuntu_tag:
            raise ValueError("Ubuntu source tag differs from reviewed evidence lock")
        if ubuntu_patches.get("ubuntu_source_commit") != LOCK.ubuntu_tag_commit:
            raise ValueError("Ubuntu source commit differs from reviewed evidence lock")
        manifest = ubuntu_patches.get("binary_manifest") or {}
        if manifest.get("package") != "linux-libc-dev=" + LOCK.package_version:
            raise ValueError("captured binary manifest package differs from reviewed evidence lock")
        if manifest.get("header_count") != LOCK.header_count:
            raise ValueError("captured binary manifest header count differs from reviewed evidence lock")
        digest = manifest.get("sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise ValueError("captured binary manifest has no computed SHA-256")
        if LOCK.binary_manifest_sha256 and digest != LOCK.binary_manifest_sha256:
            raise ValueError("captured binary manifest digest differs from reviewed evidence lock")
        patch_rows = unique(ubuntu_patches["records"], "Ubuntu source")
        if set(patch_rows) != set(by_scanner):
            raise ValueError("Ubuntu patch input is incomplete")
    records = []
    for cve in sorted(by_scanner):
        t, v = by_scanner[cve], by_vendor[cve]
        u, patch = upstream_rows.get(cve, {}), patch_rows.get(cve, {})
        osv = canonical_osv_rows.get(cve, {})
        if t["severity"] != v["severity"]:
            raise ValueError(f"{cve}: severity changed between sources")
        paths = u.get("upstream_paths", [])
        internal = u.get("affected_headers", [])
        matched = u.get("matching_shipped_uapi_headers", [])
        records.append({
            "cve": cve, "severity": t["severity"], "original_scanner_title": t["trivy_title"],
            "inventory_provenance": {
                "origin": ("new_298_cve_extension" if cve in {
                    "CVE-2026-98869", "CVE-2026-98890", "CVE-2026-99083"
                } else "historical_295_cve_inventory"),
                "scan_observation": "not_asserted_by_source_path_audit",
                "historical_inventory_package_version": (
                    "7.0.0-42.42" if cve not in {
                        "CVE-2026-98869", "CVE-2026-98890", "CVE-2026-99083"
                    } else None
                ),
            },
            "canonical": {"status": v["ubuntu_linux_resolute_status"],
                          "pending_version_or_detail": v["canonical_pending_version_or_detail"],
                          "last_updated": v["canonical_updated_at"], "url": v["vendor_url"],
                          "snapshot_kind": "historical_canonical_tsv"},
            "canonical_osv": {
                "source_commit": canonical_osv.get("source_commit") if canonical_osv else None,
                "retrieved_at": canonical_osv.get("retrieved_at") if canonical_osv else None,
                "modified": osv.get("modified"),
                "raw_sha256": osv.get("raw_sha256"),
                "release_evidence": osv.get("release_evidence"),
                "ubuntu_26_04_linux_source_entries": osv.get("ubuntu_26_04_linux_source_entries", []),
            },
            "upstream": {
                "source_revision": source_sha, "ubuntu_source_tag": u.get("ubuntu_source_tag"),
                "ubuntu_source_commit": u.get("ubuntu_source_commit"),
                "ubuntu_source_path_status": u.get("ubuntu_source_path_status"),
                "ubuntu_source_paths_present": u.get("ubuntu_source_paths_present", []),
                "ubuntu_source_paths_missing": u.get("ubuntu_source_paths_missing", []),
                "url": u.get("upstream_url",
                    f"https://kernel.googlesource.com/pub/scm/linux/security/vulns/+/{source_sha}/cve/published/{cve[4:8]}/{cve}.json"),
                "affected_paths": paths,
                "candidate_fix_references": u.get("candidate_upstream_fix_references", []),
                "kernel_private_headers": internal, "direct_shipped_uapi_matches": matched,
                "evidence": "verified_upstream_record" if u else "historical_artifact_only",
            },
            "ubuntu_source": {
                "source_revision": patch.get("source_revision") or patch.get("ubuntu_release_tag_commit"),
                "release_tag": patch.get("ubuntu_release_tag"),
                "release_tag_commit": patch.get("ubuntu_release_tag_commit"),
                "source_paths_present": patch.get("ubuntu_source_paths_present", []),
                "ubuntu_source_path_status": patch.get("ubuntu_source_path_status"),
                "upstream_path_correspondence": patch.get("upstream_path_correspondence", []),
                "upstream_paths_missing_from_ubuntu_snapshot": patch.get("upstream_paths_missing_from_ubuntu_snapshot", []),
                "direct_binary_manifest_uapi_path_matches": patch.get("direct_binary_manifest_uapi_path_matches", []),
                "kernel_private_header_paths": patch.get("kernel_private_header_paths", []),
                "candidate_upstream_fix_references": patch.get("upstream_candidate_fix_references", []),
                "ubuntu_fix_commit_verified": patch.get("ubuntu_fix_commit_verified", False),
                "patch_commit_references": patch.get("patch_commit_references", []),
                "downstream_changed_paths": patch.get("downstream_changed_paths", []),
                "backport_provenance": patch.get("backport_provenance"),
                "release_pocket": patch.get("release_pocket"),
                "source_diff_verified": patch.get("source_diff_verified", False),
                "binary_header_diff_verified": patch.get("binary_header_diff_verified", False),
            },
            "binary_exposure": {
                "direct_executable": "not_observed_in_exact_binary_manifest",
                "shipped_header_inline_macro": "under_investigation",
                "abi_uapi_compiler_transitive": "under_investigation",
                "downstream_userspace_compilation": "under_investigation",
                "host_kernel": "out_of_scope_separate_assurance",
            },
            "technical_reasoning": (
                "The exact binary manifest contains only headers and documentation. "
                "Upstream paths alone do not establish Ubuntu downstream modifications "
                "or indirect compiler-visible/ABI effects; no independent applicability "
                "review or signature is present."
            ),
            "uncertainty": "Ubuntu patch/backport and indirect header/UAPI/ABI review incomplete",
            "remediation": "Check supported Canonical security/updates pockets; no proposed/PPA substitute",
            "proposed_disposition": "under_investigation",
            "approved_disposition": None,
            "independent_approval_reference": None,
        })
    return {
        "schema": "baobab.dev10.cve-applicability-register.v1",
        "decision": "SECURITY_HELD_NO_EXCEPTION_APPROVED",
        "advisory_count": COUNT,
        "source_provenance": {"upstream_linux_cna_revision": source_sha,
                              "ubuntu_source_tag": (ubuntu_patches or {}).get("ubuntu_release_tag"),
                              "ubuntu_source_commit": (ubuntu_patches or {}).get("ubuntu_source_commit"),
                              "ubuntu_source_path_counts": (ubuntu_patches or {}).get("path_counts"),
                              "binary_manifest": (ubuntu_patches or {}).get("binary_manifest"),
                              "canonical_osv_snapshot": ({
                                  "source_commit": canonical_osv.get("source_commit"),
                                  "retrieved_at": canonical_osv.get("retrieved_at"),
                                  "counts": canonical_osv.get("counts"),
                              } if canonical_osv else None)},
        "counts": dict(Counter(r["proposed_disposition"] for r in records)),
        "records": records,
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--trivy", type=Path, required=True)
    p.add_argument("--canonical", type=Path, required=True)
    p.add_argument("--upstream", type=Path)
    p.add_argument("--ubuntu-patches", type=Path)
    p.add_argument("--canonical-osv", type=Path)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    upstream = json.loads(args.upstream.read_text()) if args.upstream else None
    patches = json.loads(args.ubuntu_patches.read_text()) if args.ubuntu_patches else None
    canonical_osv = json.loads(args.canonical_osv.read_text()) if args.canonical_osv else None
    report = build(tsv(args.trivy), tsv(args.canonical), upstream, patches, canonical_osv)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("DEV-10 CVEs:", report["advisory_count"], "dispositions:", report["counts"])
    print("Security clearance: NOT AUTHORISED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
