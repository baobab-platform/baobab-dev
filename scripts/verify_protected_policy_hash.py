#!/usr/bin/env python3
"""Fail-closed protected policy verification for locally built Foundation images.

No GHCR digest is claimed for a local image. Remote digest qualification remains
the responsibility of evaluate_protected_risk_decision.py.
"""
import argparse
import datetime as dt
import json
from pathlib import Path
from evaluate_protected_risk_decision import (
    load_verified_decision, _finding_key, _timestamp, demand, REPOSITORY,
    validate_execution_context,
)

def verify(decision_path, trusted_sha256, report, *, profile, architecture,
           event, ref, base_ref="", now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    decision, actual_hash = load_verified_decision(Path(decision_path), trusted_sha256)
    validate_execution_context(decision, event=event, ref=ref, base_ref=base_ref)
    demand(decision.get("schema_version") == 2 and decision.get("status") == "approved"
           and not decision.get("revoked_at"), "decision is not approved")
    demand(isinstance(decision.get("approval_id"), str) and bool(decision["approval_id"])
           and isinstance(decision.get("approval_evidence"), str)
           and decision["approval_evidence"].startswith("https://github.com/baobab-platform/baobab-dev/pull/"),
           "authenticated approval identity and custody link required")
    demand(decision.get("repository") == REPOSITORY
           and decision.get("image_repository") == "ghcr.io/" + REPOSITORY
           and decision.get("environment") == "development",
           "policy is not approved for this development repository/image")
    demand(set(decision.get("profiles", [])) == {"final", "frontend", "frontend-e2e", "infra"}
           and set(decision.get("architectures", [])) == {"linux/amd64", "linux/arm64"}
           and profile in decision["profiles"] and architecture in decision["architectures"],
           "profile or architecture outside the complete protected policy scope")
    demand(decision.get("expires_at") == "2026-11-26T00:00:00Z"
           and decision.get("finding_count") == 8,
           "decision expiry or finding count differs from the approved governance record")
    demand(_timestamp(decision, "approved_at") <= now < _timestamp(decision, "expires_at"),
           "policy expired or not yet approved")
    prepared_by = decision.get("prepared_by")
    approved_by = decision.get("approved_by")
    demand(isinstance(prepared_by, str) and prepared_by.strip()
           and isinstance(approved_by, str) and approved_by.strip()
           and prepared_by.casefold() != approved_by.casefold(),
           "maker-checker separation required")
    findings = decision.get("findings")
    demand(isinstance(findings, list) and len(findings) == 8,
           "the complete eight-finding approval inventory is required")
    approved = {_finding_key(item) for item in findings}
    expected_cves = {
        "CVE-2022-50240", "CVE-2025-40190", "CVE-2026-68103",
        "CVE-2026-72198", "CVE-2026-74578", "CVE-2026-89805",
        "CVE-2026-98376", "CVE-2026-98420",
    }
    demand(len(approved) == 8
           and {item[0] for item in approved} == expected_cves
           and all(item[1:] == ("linux-libc-dev", "7.0.0-43.43", "HIGH", "ubuntu")
                   for item in approved),
           "decision differs from the exact approved Ubuntu package/CVE inventory")
    demand(report.get("SchemaVersion") == 2 and report.get("ArtifactType") == "container_image",
           "raw Trivy container image report required")
    demand(isinstance(report.get("Trivy"), dict)
           and report["Trivy"].get("Version") == "0.73.0", "Trivy version mismatch")
    results = report.get("Results")
    demand(isinstance(results, list) and bool(results), "missing scan inventory")
    observed = set()
    for result in results:
        demand(isinstance(result, dict) and isinstance(result.get("Target"), str),
               "invalid scan target")
        demand(not result.get("Secrets"), "secret findings are not accepted")
        for finding in result.get("Vulnerabilities") or []:
            demand(not finding.get("FixedVersion"), "fixed version available")
            key = _finding_key({"cve": finding.get("VulnerabilityID"),
                                "package": finding.get("PkgName"),
                                "version": finding.get("InstalledVersion"),
                                "severity": finding.get("Severity"),
                                "type": result.get("Type")})
            observed.add(key)
    demand(bool(observed) and observed == approved,
           "scan inventory differs from the complete approved finding set")
    return {"status": "development_risk_accepted_not_remediated",
            "policy_sha256": actual_hash, "findings": len(observed)}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--decision", required=True)
    p.add_argument("--trusted-sha256", required=True)
    p.add_argument("--report", required=True)
    p.add_argument("--profile", required=True)
    p.add_argument("--architecture", required=True)
    p.add_argument("--event", required=True)
    p.add_argument("--ref", required=True)
    p.add_argument("--base-ref", default="")
    args = p.parse_args()
    print(json.dumps(verify(args.decision, args.trusted_sha256,
                            json.loads(Path(args.report).read_text()),
                            profile=args.profile, architecture=args.architecture,
                            event=args.event, ref=args.ref, base_ref=args.base_ref),
                     sort_keys=True))

if __name__ == "__main__":
    main()
