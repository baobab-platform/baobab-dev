#!/usr/bin/env python3
"""Fail-closed protected policy verification for locally built Foundation images.

No GHCR digest is claimed for a local image. Remote digest qualification remains
the responsibility of evaluate_protected_risk_decision.py.
"""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
from evaluate_protected_risk_decision import (
    load_verified_decision, _finding_key, _timestamp, demand, REPOSITORY,
)

def verify(decision_path, trusted_sha256, report, *, profile, architecture, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    decision, actual_hash = load_verified_decision(Path(decision_path), trusted_sha256)
    demand(decision.get("schema_version") == 2 and decision.get("status") == "approved"
           and not decision.get("revoked_at"), "decision is not approved")
    demand(isinstance(decision.get("approval_id"), str) and bool(decision["approval_id"])\n           and isinstance(decision.get("approval_evidence"), str)\n           and decision["approval_evidence"].startswith("https://github.com/baobab-platform/baobab-dev/pull/"),\n           "authenticated approval identity and custody link required")\n    demand(decision.get("repository") == REPOSITORY
           and decision.get("environment") == "development",
           "policy is not approved for this development repository")
    demand(profile in decision.get("profiles", [])
           and architecture in decision.get("architectures", []),
           "profile or architecture outside protected policy")
    demand(_timestamp(decision, "approved_at") <= now < _timestamp(decision, "expires_at"),
           "policy expired or not yet approved")
    demand(decision.get("prepared_by") and decision.get("approved_by")
           and decision["prepared_by"].casefold() != decision["approved_by"].casefold(),
           "maker-checker separation required")
    approved = {_finding_key(item) for item in decision.get("findings", [])}
    demand(bool(approved) and len(approved) == len(decision.get("findings", [])),
           "invalid or duplicated approved inventory")
    demand(report.get("SchemaVersion") == 2 and report.get("ArtifactType") == "container_image",\n           "raw Trivy container image report required")\n    demand(isinstance(report.get("Trivy"), dict)\n           and report["Trivy"].get("Version") == "0.73.0", "Trivy version mismatch")\n    results = report.get("Results")
    demand(isinstance(results, list) and bool(results), "missing scan inventory")
    observed = set()
    for result in results:
        demand(isinstance(result, dict) and isinstance(result.get("Target"), str),
               "invalid scan target")
        demand(not result.get("Secrets"), "secret findings are not accepted")
        demand(not result.get("Secrets"), "secret findings are not accepted")\n        for finding in result.get("Vulnerabilities") or []:
            demand(not finding.get("FixedVersion"), "fixed version available")
            key = _finding_key({"cve": finding.get("VulnerabilityID"),
                                "package": finding.get("PkgName"),
                                "version": finding.get("InstalledVersion"),
                                "severity": finding.get("Severity"),
                                "type": result.get("Type")})
            observed.add(key)
    demand(bool(observed) and observed <= approved, "new or changed findings denied")
    return {"status": "development_risk_accepted_not_remediated",
            "policy_sha256": actual_hash, "findings": len(observed)}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--decision", required=True)
    p.add_argument("--trusted-sha256", required=True)
    p.add_argument("--report", required=True)
    p.add_argument("--profile", required=True)
    p.add_argument("--architecture", required=True)
    args = p.parse_args()
    print(json.dumps(verify(args.decision, args.trusted_sha256,
                            json.loads(Path(args.report).read_text()),
                            profile=args.profile, architecture=args.architecture),
                     sort_keys=True))

if __name__ == "__main__":
    main()
