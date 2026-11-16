#!/usr/bin/env python3
"""Fail-closed protected policy verification for locally built Foundation images.

No GHCR digest is claimed for a local image. Remote digest qualification remains
the responsibility of evaluate_protected_risk_decision.py.
"""
import argparse
import datetime as dt
import json
import re
from pathlib import Path
from evaluate_protected_risk_decision import (
    load_verified_decision, _finding_key, _timestamp, demand, REPOSITORY,
    validate_execution_context,
)

def verify(decision_path, trusted_sha256, report, *, profile, architecture,
           event, ref, base_ref="", head_repository="", approval_id=None,
           approval_timestamp=None, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    decision, actual_hash = load_verified_decision(Path(decision_path), trusted_sha256)
    validate_execution_context(decision, event=event, ref=ref, base_ref=base_ref,
                               head_repository=head_repository)
    demand(decision.get("schema_version") == 2 and decision.get("status") == "approved"
           and decision.get("revoked_at") is None, "decision is not approved or has been revoked")
    evidence = decision.get("approval_evidence")
    demand(isinstance(approval_id, str) and bool(approval_id.strip())
           and isinstance(approval_timestamp, str) and bool(approval_timestamp.strip())
           and isinstance(evidence, str)
           and re.fullmatch(r"https://github\.com/baobab-platform/baobab-dev/pull/[1-9][0-9]*", evidence),
           "authenticated approval identity and exact custody link required")
    demand(decision.get("repository") == REPOSITORY
           and decision.get("image_repository") == "ghcr.io/" + REPOSITORY
           and decision.get("environment") == "development",
           "policy is not approved for this development repository/image")
    profiles = decision.get("profiles")
    architectures = decision.get("architectures")
    demand(isinstance(profiles, list)
           and set(profiles) == {"final", "frontend", "frontend-e2e", "infra"}
           and isinstance(architectures, list)
           and set(architectures) == {"linux/amd64", "linux/arm64"}
           and profile in profiles and architecture in architectures,
           "profile or architecture outside the complete protected policy scope")
    demand(decision.get("expires_at") == "2026-11-26T00:00:00Z"
           and decision.get("finding_count") == 8,
           "decision expiry or finding count differs from the approved governance record")
    approved_at = _timestamp({"approved_at": approval_timestamp}, "approved_at")
    demand(approved_at <= now < _timestamp(decision, "expires_at"),
           "policy expired or not yet approved")
    prepared_by_id = decision.get("prepared_by_id")
    approved_by_id = decision.get("approved_by_id")
    demand(type(prepared_by_id) is int and prepared_by_id > 0
           and type(approved_by_id) is int and approved_by_id > 0
           and prepared_by_id != approved_by_id,
           "numeric maker-checker separation required")
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
    demand(bool(observed) and observed <= approved,
           "new or changed findings are outside the approved inventory")
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
    p.add_argument("--head-repository", required=True)
    p.add_argument("--approval-id", required=True)
    p.add_argument("--approved-at", required=True)
    args = p.parse_args()
    print(json.dumps(verify(args.decision, args.trusted_sha256,
                            json.loads(Path(args.report).read_text()),
                            profile=args.profile, architecture=args.architecture,
                            event=args.event, ref=args.ref, base_ref=args.base_ref,
                            head_repository=args.head_repository,
                            approval_id=args.approval_id, approval_timestamp=args.approved_at),
                     sort_keys=True))

if __name__ == "__main__":
    main()
