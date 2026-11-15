#!/usr/bin/env python3
"""Fail-closed, PR-number-independent risk decision evaluator.

The decision must be supplied by a trusted protected-policy workflow, not by
untrusted PR checkout. A pinned SHA-256 from that workflow authenticates the
exact decision bytes; a hash supplied by the same PR is NOT authorization.
This module does not approve any existing CVE or image.
"""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re

DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
CVE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
PROFILES = frozenset(("final", "frontend", "frontend-e2e", "infra"))
ARCHES = frozenset(("linux/amd64", "linux/arm64"))


class DecisionDenied(ValueError):
    pass


def demand(condition: bool, reason: str) -> None:
    if not condition:
        raise DecisionDenied(reason)


def load_verified_decision(path: Path, trusted_sha256: str) -> dict:
    """Only call with SHA-256 sourced from an independent protected authority."""
    demand(bool(re.fullmatch(r"[a-f0-9]{64}", trusted_sha256)), "invalid trusted policy hash")
    raw = path.read_bytes()
    demand(hashlib.sha256(raw).hexdigest() == trusted_sha256, "decision bytes differ from protected approval")
    decision = json.loads(raw)
    demand(isinstance(decision, dict), "invalid decision document")
    return decision


def evaluate(decision: dict, report: dict, *, image_digest: str,
             profile: str, architecture: str, environment: str,
             now: dt.datetime | None = None) -> dict:
    now = now or dt.datetime.now(dt.timezone.utc)
    demand(now.tzinfo is not None, "timezone-aware clock required")
    demand(environment == "development", "risk decision not valid outside development")
    demand(profile in PROFILES and architecture in ARCHES, "unknown image profile or architecture")
    demand(bool(DIGEST.fullmatch(image_digest)), "immutable image digest required")
    demand(decision.get("schema_version") == 1, "unsupported decision schema")
    demand(decision.get("status") == "approved", "decision not approved or revoked")
    demand(decision.get("environment") == environment, "environment outside approval")
    demand(decision.get("repository") == "baobab-platform/baobab-dev", "repository mismatch")
    demand(image_digest in decision.get("image_digests", []), "image digest not authorized")
    demand(profile in decision.get("profiles", []), "profile not authorized")
    demand(architecture in decision.get("architectures", []), "architecture not authorized")
    demand(isinstance(decision.get("approval_id"), str) and bool(decision["approval_id"]), "approval identifier missing")
    demand(isinstance(decision.get("approved_by"), str) and bool(decision["approved_by"]), "reviewer identity missing")
    demand(isinstance(decision.get("approval_evidence"), str) and decision["approval_evidence"].startswith("https://"), "approval evidence missing")
    try:
        expiry = dt.datetime.fromisoformat(decision["expires_at"].replace("Z", "+00:00"))
        approved = dt.datetime.fromisoformat(decision["approved_at"].replace("Z", "+00:00"))
    except (KeyError, AttributeError, ValueError) as exc:
        raise DecisionDenied("invalid approval timestamps") from exc
    demand(expiry.tzinfo is not None and approved.tzinfo is not None and approved <= now < expiry, "approval outside validity period")
    expected = decision.get("findings")
    demand(isinstance(expected, list) and bool(expected), "approved findings inventory missing")
    approved_findings = set()
    for finding in expected:
        demand(isinstance(finding, dict), "invalid approved finding")
        key = (finding.get("cve"), finding.get("package"), finding.get("version"), finding.get("severity"))
        demand(isinstance(key[0], str) and bool(CVE.fullmatch(key[0])) and all(isinstance(v, str) and v for v in key), "invalid finding identity")
        demand(key not in approved_findings, "duplicate approved finding")
        approved_findings.add(key)
    demand(isinstance(report.get("Results"), list) and report["Results"], "missing Trivy results")
    observed = set()
    for result in report["Results"]:
        demand(isinstance(result, dict) and isinstance(result.get("Target"), str), "invalid scan result")
        demand(not result.get("Secrets"), "secret findings cannot be accepted")
        vulns = result.get("Vulnerabilities") or []
        demand(isinstance(vulns, list), "invalid vulnerability list")
        for vuln in vulns:
            demand(isinstance(vuln, dict), "invalid vulnerability")
            key = (vuln.get("VulnerabilityID"), vuln.get("PkgName"),
                   vuln.get("InstalledVersion"), vuln.get("Severity"))
            demand(key in approved_findings, "new or changed vulnerability requires approval")
            demand(not vuln.get("FixedVersion"), "fixed version available; remediate")
            demand(key not in observed, "duplicate scan finding")
            observed.add(key)
    demand(bool(observed), "no findings: use clean scan path")
    demand(observed == approved_findings, "approved inventory differs from scanned findings")
    return {"status": "accepted_residual_risk", "approval_id": decision["approval_id"],
            "image_digest": image_digest, "profile": profile, "architecture": architecture,
            "findings": len(observed), "expires_at": decision["expires_at"]}


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--decision", type=Path, required=True)
    p.add_argument("--trusted-decision-sha256", required=True)
    p.add_argument("--report", type=Path, required=True)
    p.add_argument("--digest", required=True)
    p.add_argument("--profile", required=True)
    p.add_argument("--architecture", required=True)
    p.add_argument("--environment", required=True)
    args = p.parse_args()
    try:
        result = evaluate(load_verified_decision(args.decision, args.trusted_decision_sha256),
                          json.loads(args.report.read_text()), image_digest=args.digest,
                          profile=args.profile, architecture=args.architecture,
                          environment=args.environment)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (DecisionDenied, OSError, ValueError, TypeError) as exc:
        print("SECURITY DENIED:", exc)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
