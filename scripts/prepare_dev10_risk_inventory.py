#!/usr/bin/env python3
"""Prepare a review-only exact Trivy risk inventory. Never grants approval."""
import argparse
import hashlib
import json
from pathlib import Path
from evaluate_protected_risk_decision import _finding_key, demand, TRIVY_VERSION

def extract(report, *, scanner_version):
    demand(report.get("SchemaVersion") == 2 and report.get("ArtifactType") == "container_image",
           "requires raw Trivy container image report")
    # Standard Trivy JSON does not embed the CLI version. CI verifies the
    # pinned scanner binary independently and supplies its observed version.
    demand(scanner_version == TRIVY_VERSION, "unqualified scanner version")
    results = report.get("Results")
    demand(isinstance(results, list) and results, "missing scan results")
    found = {}
    for result in results:
        demand(isinstance(result, dict), "invalid result")
        demand(not result.get("Secrets"), "secret findings require remediation")
        for item in result.get("Vulnerabilities") or []:
            demand(not item.get("FixedVersion"), "fixed vulnerability must be remediated")
            record = {"cve": item.get("VulnerabilityID"),
                      "package": item.get("PkgName"),
                      "version": item.get("InstalledVersion"),
                      "severity": item.get("Severity"),
                      "type": result.get("Type")}
            key = _finding_key(record)
            found[key] = record
    demand(found, "no residual HIGH/CRITICAL findings to propose")
    return [found[key] for key in sorted(found)]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-trivy", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--architecture", required=True)
    parser.add_argument("--scanner-version", required=True)
    args = parser.parse_args()
    raw = args.raw_trivy.read_bytes()
    report = json.loads(raw)
    inventory = extract(report, scanner_version=args.scanner_version)
    draft = {"schema_version": 2, "status": "pending_independent_review",
             "repository": "baobab-platform/baobab-dev",
             "image_repository": "ghcr.io/baobab-platform/baobab-dev",
             "environment": "development",
             "profiles": [args.profile], "architectures": [args.architecture],
             "raw_report_sha256": hashlib.sha256(raw).hexdigest(),
             "approval_id": None, "prepared_by": None, "approved_by": None,
             "approval_evidence": None, "approved_at": None, "expires_at": None,
             "scanner": TRIVY_VERSION, "findings": inventory,
             "finding_count": len(inventory),
             "warning": "REVIEW ONLY. No exception or approval is granted."}
    args.output.write_text(json.dumps(draft, indent=2, sort_keys=True) + "\n")
    print(f"Prepared {len(inventory)} exact findings for independent review; NOT approved.")

if __name__ == "__main__":
    main()
