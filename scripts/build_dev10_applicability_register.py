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

COUNT = 295
SOURCE_SHA = "604accad567eb6e7fb4c7fdc422470c25f35f467"
ARTIFACT_SHA256 = "bd2730b71a5dc7302373a7953d67dfbbe37a44ae2ede01039a63ba2df00398d4"
MANIFEST_SHA256 = "688453ae46c07ec19b3bf6734eb2f23b0dfe5625c16d76d75149b8194da91fa3"


def tsv(path: Path) -> list[dict]:
    with path.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream, delimiter="\t"))


def unique(rows: list[dict], label: str) -> dict[str, dict]:
    result = {row["cve"]: row for row in rows}
    if len(rows) != COUNT or len(result) != COUNT:
        raise ValueError(f"{label}: expected exactly {COUNT} unique CVEs")
    return result


def build(scanner: list[dict], canonical: list[dict],
          upstream: dict | None = None, ubuntu_patches: dict | None = None) -> dict:
    by_scanner = unique(scanner, "Trivy")
    by_vendor = unique(canonical, "Canonical")
    if set(by_scanner) != set(by_vendor):
        raise ValueError("Trivy and Canonical CVE IDs differ")
    upstream_rows = {}
    if upstream is not None:
        if upstream.get("upstream_commit") != SOURCE_SHA:
            raise ValueError("upstream source revision differs from independently captured evidence")
        upstream_rows = unique(upstream["records"], "upstream")
        if set(upstream_rows) != set(by_scanner):
            raise ValueError("upstream CVE IDs differ")
        if any(row.get("error") or row.get("classification") == "UPSTREAM_UNVERIFIED"
               for row in upstream_rows.values()):
            raise ValueError("upstream evidence contains unverified cases")
    # Optional Ubuntu-specific evidence must be supplied as separate auditable
    # source-file/commit facts. It is NOT an independent authorisation.
    patch_rows = {}
    if ubuntu_patches is not None:
        patch_rows = unique(ubuntu_patches["records"], "Ubuntu source")
        if set(patch_rows) != set(by_scanner):
            raise ValueError("Ubuntu patch input is incomplete")
    records = []
    for cve in sorted(by_scanner):
        t, v = by_scanner[cve], by_vendor[cve]
        u, patch = upstream_rows.get(cve, {}), patch_rows.get(cve, {})
        if t["severity"] != v["severity"]:
            raise ValueError(f"{cve}: severity changed between sources")
        paths = u.get("upstream_paths", [])
        internal = u.get("affected_headers", [])
        matched = u.get("matching_shipped_uapi_headers", [])
        records.append({
            "cve": cve, "severity": t["severity"], "original_scanner_title": t["trivy_title"],
            "scanned_package": {"name": "linux-libc-dev", "version": "7.0.0-42.42",
                                "source": "linux", "distribution": "ubuntu:26.04"},
            "canonical": {"status": v["ubuntu_linux_resolute_status"],
                          "pending_version_or_detail": v["canonical_pending_version_or_detail"],
                          "last_updated": v["canonical_updated_at"], "url": v["vendor_url"]},
            "upstream": {
                "source_revision": SOURCE_SHA, "url": u.get("upstream_url",
                    f"https://kernel.googlesource.com/pub/scm/linux/security/vulns/+/{SOURCE_SHA}/cve/published/{cve[4:8]}/{cve}.json"),
                "affected_paths": paths,
                "kernel_private_headers": internal, "direct_shipped_uapi_matches": matched,
                "evidence": "verified_upstream_record" if u else "historical_artifact_only",
            },
            "ubuntu_source": {
                "source_revision": patch.get("source_revision"),
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
                "manifest_sha256": MANIFEST_SHA256,
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
        "source_provenance": {"upstream_linux_cna_revision": SOURCE_SHA,
                              "historical_upstream_artifact_sha256": ARTIFACT_SHA256,
                              "binary_manifest_sha256": MANIFEST_SHA256},
        "counts": dict(Counter(r["proposed_disposition"] for r in records)),
        "records": records,
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--trivy", type=Path, required=True)
    p.add_argument("--canonical", type=Path, required=True)
    p.add_argument("--upstream", type=Path)
    p.add_argument("--ubuntu-patches", type=Path)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    upstream = json.loads(args.upstream.read_text()) if args.upstream else None
    patches = json.loads(args.ubuntu_patches.read_text()) if args.ubuntu_patches else None
    report = build(tsv(args.trivy), tsv(args.canonical), upstream, patches)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("DEV-10 CVEs:", report["advisory_count"], "dispositions:", report["counts"])
    print("Security clearance: NOT AUTHORISED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
