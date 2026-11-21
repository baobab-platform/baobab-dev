#!/usr/bin/env python3
"""Assemble an exact-digest, review-only DEV-10 policy candidate from Trivy scans.

Inputs must be independently captured GHCR child-digest scans, one per
profile/architecture. This tool cannot authorize an exception or choose an
approver/expiry. Incomplete evidence is rejected rather than guessed.
"""
import argparse
import hashlib
import json
from pathlib import Path
from evaluate_protected_risk_decision import (
    ARCHES, PROFILES, IMAGE_REPOSITORY, TRIVY_VERSION, DIGEST,
    _finding_key, _validate_scan_identity, demand,
)

def assemble(entries):
    demand(len(entries) == len(PROFILES) * len(ARCHES),
           "eight profile/architecture evidence records required")
    seen = set()
    inventory = set()
    evidence = []
    for item in entries:
        profile, arch, digest = item["profile"], item["architecture"], item["digest"]
        demand(profile in PROFILES and arch in ARCHES and bool(DIGEST.fullmatch(digest)),
               "invalid profile/architecture/immutable digest")
        key = (profile, arch)
        demand(key not in seen, "duplicate profile/architecture")
        seen.add(key)
        raw = Path(item["report"]).read_bytes()
        report = json.loads(raw)
        _validate_scan_identity(report, image_repository=IMAGE_REPOSITORY,
                                image_digest=digest, architecture=arch,
                                expected_trivy_version=TRIVY_VERSION)
        demand((report.get("Trivy") or {}).get("Version") == TRIVY_VERSION,
               "scanner version mismatch")
        demand(isinstance(report.get("Results"), list) and report["Results"],
               "missing vulnerability results")
        findings = set()
        for result in report["Results"]:
            demand(not result.get("Secrets"), "secret findings require remediation")
            for vuln in result.get("Vulnerabilities") or []:
                demand(not vuln.get("FixedVersion"), "upstream fix available; remediate")
                finding = _finding_key({
                    "cve": vuln.get("VulnerabilityID"),
                    "package": vuln.get("PkgName"),
                    "version": vuln.get("InstalledVersion"),
                    "severity": vuln.get("Severity"),
                    "type": result.get("Type"),
                })
                findings.add(finding)
        inventory.update(findings)
        evidence.append({"profile": profile, "architecture": arch,
                         "digest": digest, "raw_trivy_sha256": hashlib.sha256(raw).hexdigest(),
                         "scanner": TRIVY_VERSION,
                         "scanner_database_evidence": item.get("database_evidence"),
                         "captured_at": item.get("captured_at"),
                         "findings": len(findings)})
        demand(item.get("database_evidence") and item.get("captured_at"),
               "scanner DB provenance and capture timestamp required")
    demand(seen == {(p,a) for p in PROFILES for a in ARCHES},
           "incomplete profile/architecture matrix")
    # The limited engineering authorization covers exactly this package and
    # version and eight HIGH CVEs; anything else requires remediation or
    # a separate independent decision, not silent scope expansion.
    demand(len(inventory) == 8 and all(
        pkg == "linux-libc-dev" and ver == "7.0.0-43.43" and sev == "HIGH"
        for _, pkg, ver, sev, _ in inventory),
        "outside sknabusiu's PR #74-only eight-HIGH scope")
    return {
        "schema_version": 2, "status": "pending_independent_review",
        "repository": "baobab-platform/baobab-dev",
        "image_repository": IMAGE_REPOSITORY,
        "environment": "development",
        "profiles": sorted(PROFILES), "architectures": sorted(ARCHES),
        "scope_pr": 74, "release_authorized": False,
        "approval_id": None, "prepared_by": None, "approved_by": None,
        "approval_evidence": None, "approved_at": None, "expires_at": None,
        "findings": [
            dict(cve=c, package=p, version=v, severity=s, type=t)
            for c,p,v,s,t in sorted(inventory)],
        "exact_digest_evidence": sorted(evidence, key=lambda x:(x["profile"],x["architecture"])),
        "notes": "REVIEW ONLY. Engineering scope from sknabusiu is not risk approval. "
                 "No exception, tag, promotion, merge or release is authorized.",
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    candidate = assemble(manifest["scans"])
    args.output.write_text(json.dumps(candidate, indent=2, sort_keys=True) + "\n")
    print("Review-only evidence candidate prepared; no protected SHA activated.")

if __name__ == "__main__":
    main()
