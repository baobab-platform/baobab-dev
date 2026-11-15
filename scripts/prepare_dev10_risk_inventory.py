#!/usr/bin/env python3
"""Prepare a review-only exact Trivy risk inventory. Never grants approval."""
import argparse
import json
from pathlib import Path
from evaluate_protected_risk_decision import _finding_key, demand, TRIVY_VERSION

def extract(report):
    demand(report.get("SchemaVersion") == 2 and report.get("ArtifactType") == "container_image",
           "requires raw Trivy container image report")
    demand(isinstance(report.get("Trivy"), dict)
           and report["Trivy"].get("Version") == TRIVY_VERSION,
           "unqualified scanner version")
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
    args = parser.parse_args()
    report = json.loads(args.raw_trivy.read_text())
    inventory = extract(report)
    draft = {"status": "pending_independent_review",
             "scanner": TRIVY_VERSION, "findings": inventory,
             "finding_count": len(inventory),
             "warning": "REVIEW ONLY. No exception or approval is granted."}
    args.output.write_text(json.dumps(draft, indent=2, sort_keys=True) + "\n")
    print(f"Prepared {len(inventory)} exact findings for independent review; NOT approved.")

if __name__ == "__main__":
    main()
