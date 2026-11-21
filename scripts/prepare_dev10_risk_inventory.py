#!/usr/bin/env python3
"""Prepare a review-only exact Trivy risk inventory. Never grants approval."""
import argparse
import hashlib
import json
from pathlib import Path
from evaluate_protected_risk_decision import CVE, DecisionDenied, _finding_key, demand, TRIVY_VERSION


class FindingNeedsRemediation(DecisionDenied):
    """The scan contains findings that a development decision cannot cover."""


def scan_findings(report, *, scanner_version):
    """Read the complete blocking inventory, including an explicitly clean scan."""
    demand(isinstance(report, dict) and report.get("SchemaVersion") == 2
           and report.get("ArtifactType") == "container_image",
           "requires a Trivy v2 container image report")
    demand(scanner_version == TRIVY_VERSION, "unqualified scanner version")
    results = report.get("Results")
    demand(isinstance(results, list) and results, "missing scan results")
    found = set()
    for result in results:
        demand(isinstance(result, dict) and isinstance(result.get("Target"), str)
               and result["Target"].strip(), "invalid scan target")
        secrets = result.get("Secrets")
        demand(secrets is None or isinstance(secrets, list), "invalid secret inventory")
        if secrets:
            raise FindingNeedsRemediation("Secret findings require remediation.")
        vulnerabilities = result.get("Vulnerabilities")
        demand(vulnerabilities is None or isinstance(vulnerabilities, list),
               "invalid vulnerability inventory")
        for item in vulnerabilities or []:
            demand(isinstance(item, dict), "invalid vulnerability finding")
            fixed = item.get("FixedVersion")
            demand(fixed is None or isinstance(fixed, str), "invalid fixed-version evidence")
            if fixed:
                raise FindingNeedsRemediation("A scanner-reported fixed version requires remediation.")
            advisory = item.get("VulnerabilityID")
            demand(isinstance(advisory, str) and advisory.strip(), "missing vulnerability identifier")
            if not CVE.fullmatch(advisory):
                raise FindingNeedsRemediation("An advisory lacks a supported CVE identity.")
            found.add(_finding_key({
                "cve": advisory,
                "package": item.get("PkgName"),
                "version": item.get("InstalledVersion"),
                "severity": item.get("Severity"),
                "type": result.get("Type"),
            }))
    return found


def finding_records(found):
    """Serialize exact finding identities in a stable order for review."""
    return [dict(cve=cve, package=package, version=version, severity=severity, type=ecosystem)
            for cve, package, version, severity, ecosystem in sorted(found)]


def extract(report, *, scanner_version):
    found = scan_findings(report, scanner_version=scanner_version)
    demand(found, "no residual HIGH/CRITICAL findings to propose")
    return finding_records(found)


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
