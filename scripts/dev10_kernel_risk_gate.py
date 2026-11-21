#!/usr/bin/env python3
"""Fail-closed runtime evaluator for the protected DEV-10 development decision.

The decision is effective only when its exact file bytes match the separately
provisioned repository Actions variable. This evaluator does not create or
approve that trust anchor. It accepts only the decision's exact finding
identities in the ADR-authorised development CI contexts.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import sys

REPOSITORY = "baobab-platform/baobab-dev"
IMAGE_REPOSITORY = "ghcr.io/baobab-platform/baobab-dev"
DECISION_PATH = "security/decisions/development/foundation.json"
EVIDENCE_LOCK_PATH = "security/decisions/development/foundation-eight-image-evidence-lock.json"
VARIABLE_NAME = "DEV10_PROTECTED_DECISION_SHA256"
EXPECTED_EXPIRY = "2026-11-26T00:00:00Z"
PROFILES = frozenset({"final", "frontend", "frontend-e2e", "infra"})
PLATFORMS = frozenset({"linux/amd64", "linux/arm64"})
CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
PR_URL = re.compile(
    r"^https://github\.com/baobab-platform/baobab-dev/pull/[1-9][0-9]*$"
)


class RiskGateError(ValueError):
    """A fail-closed DEV-10 runtime decision error."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RiskGateError(message)


def parse_utc(value: str, label: str) -> dt.datetime:
    require(isinstance(value, str) and bool(value), f"{label} is missing")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RiskGateError(f"{label} is not an ISO-8601 timestamp") from exc
    require(parsed.tzinfo is not None, f"{label} must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def load_decision(decision_path: Path, evidence_lock_path: Path,
                  protected_sha256: str, now: dt.datetime | None = None) -> dict:
    """Authenticate exact decision bytes, then validate the bounded contract."""
    require(isinstance(protected_sha256, str)
            and re.fullmatch(r"[a-f0-9]{64}", protected_sha256) is not None,
            f"{VARIABLE_NAME} is missing or malformed")
    raw = decision_path.read_bytes()
    actual_sha256 = hashlib.sha256(raw).hexdigest()
    require(actual_sha256 == protected_sha256,
            "decision bytes do not match the protected trust anchor")
    lock_raw = evidence_lock_path.read_bytes()
    try:
        decision = json.loads(raw)
        lock = json.loads(lock_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RiskGateError("decision or evidence lock is not valid UTF-8 JSON") from exc

    expected_fields = {
        "schema_version", "record_type", "status", "revoked_at", "repository",
        "image_repository", "environment", "execution_scope", "profiles",
        "architectures", "prepared_by", "prepared_by_id", "approval_evidence",
        "expires_at", "findings", "finding_count", "notes", "evidence_lock_sha256",
    }
    require(isinstance(decision, dict) and set(decision) == expected_fields,
            "decision fields differ from the protected schema")
    require(decision["schema_version"] == 2
            and decision["record_type"] == "proposed_approved_form",
            "unsupported decision schema or record type")
    require(decision["status"] == "approved" and decision["revoked_at"] is None,
            "decision is not approved or has been revoked")
    require(decision["repository"] == REPOSITORY
            and decision["image_repository"] == IMAGE_REPOSITORY
            and decision["environment"] == "development",
            "decision repository, image or environment scope mismatch")
    require(decision["execution_scope"] == {
        "pull_request_base": "main",
        "push_ref": "refs/heads/main",
        "pull_request_head_repository": REPOSITORY,
    }, "decision execution scope widened or malformed")
    require(set(decision["profiles"]) == PROFILES and len(decision["profiles"]) == 4,
            "decision profile inventory mismatch")
    require(set(decision["architectures"]) == PLATFORMS
            and len(decision["architectures"]) == 2,
            "decision architecture inventory mismatch")
    require(isinstance(decision["prepared_by"], str) and decision["prepared_by"].strip()
            and type(decision["prepared_by_id"]) is int and decision["prepared_by_id"] > 0,
            "decision preparer identity is missing")
    require(isinstance(decision["approval_evidence"], str)
            and PR_URL.fullmatch(decision["approval_evidence"]) is not None,
            "decision approval evidence URL is malformed")
    require(decision["expires_at"] == EXPECTED_EXPIRY,
            "decision expiry differs from the bounded approved contract")
    now = now or dt.datetime.now(dt.timezone.utc)
    require(now.tzinfo is not None and parse_utc(decision["expires_at"], "decision expiry") > now,
            "decision is expired")
    require(isinstance(decision["notes"], str) and decision["notes"].strip(),
            "decision rationale is missing")

    require(isinstance(decision["evidence_lock_sha256"], str)
            and re.fullmatch(r"[a-f0-9]{64}", decision["evidence_lock_sha256"]) is not None,
            "decision evidence-lock digest is malformed")
    require(hashlib.sha256(lock_raw).hexdigest() == decision["evidence_lock_sha256"],
            "evidence-lock bytes do not match the decision")
    require(isinstance(lock, dict)
            and lock.get("schema") == "dev10-current-head-eight-image-scan-lock-v1"
            and lock.get("repository") == REPOSITORY
            and lock.get("pr") == 74
            and lock.get("source_commit")
            and re.fullmatch(r"[a-f0-9]{64}", lock.get("normalized_inventory_sha256", "")),
            "evidence lock contract is malformed")
    artifacts = lock.get("artifacts")
    expected_artifacts = {(profile, platform) for profile in PROFILES for platform in PLATFORMS}
    require(isinstance(artifacts, list) and len(artifacts) == 8,
            "evidence lock must contain all eight profile/architecture artifacts")
    actual_artifacts = set()
    for artifact in artifacts:
        require(isinstance(artifact, dict), "malformed evidence-lock artifact")
        identity = (artifact.get("profile"), artifact.get("architecture"))
        require(identity not in actual_artifacts
                and identity[0] in PROFILES and identity[1] in PLATFORMS,
                "duplicate or unsupported evidence-lock artifact")
        actual_artifacts.add(identity)
        require(type(artifact.get("artifact_id")) is int and artifact["artifact_id"] > 0
                and type(artifact.get("finding_count")) is int
                and artifact["finding_count"] == 30
                and re.fullmatch(r"[a-f0-9]{64}", artifact.get("archive_sha256", "")) is not None
                and re.fullmatch(r"[a-f0-9]{64}", artifact.get("findings_sha256", "")) is not None,
                "evidence-lock artifact metadata is incomplete")
    require(actual_artifacts == expected_artifacts,
            "evidence lock does not cover all four profiles and both architectures")

    findings = decision["findings"]
    require(isinstance(findings, list) and len(findings) == 30
            and decision["finding_count"] == 30,
            "decision must contain exactly thirty findings")
    allowed = {}
    for finding in findings:
        require(isinstance(finding, dict)
                and set(finding) == {"cve", "package", "version", "severity", "type"},
                "malformed decision finding")
        cve = finding.get("cve")
        require(isinstance(cve, str) and CVE.fullmatch(cve) is not None,
                "malformed CVE identity in decision")
        identity = (finding["package"], finding["version"],
                    finding["severity"], finding["type"])
        require(cve not in allowed, "duplicate CVE in decision")
        require(identity[0] == "linux-libc-dev" and identity[1] == "7.0.0-44.44"
                and identity[2] in {"HIGH", "CRITICAL"} and identity[3] == "ubuntu",
                "decision contains an out-of-scope package, version, severity or ecosystem")
        allowed[cve] = identity
    require(len(allowed) == 30
            and sum(item[2] == "CRITICAL" for item in allowed.values()) == 3
            and sum(item[2] == "HIGH" for item in allowed.values()) == 27,
            "decision severity split or unique finding count differs from 27 HIGH / 3 CRITICAL")
    return {"document": decision, "allowed": allowed, "sha256": actual_sha256}


def validate(report: dict, authenticated: dict, *, target: str, platform: str,
             event: str, ref: str, repository: str, pr_number: int,
             pr_base: str = "", head_repository: str = "",
             now: dt.datetime | None = None) -> dict:
    decision = authenticated["document"]
    require(repository == REPOSITORY, "outside Baobab development repository")
    if event == "pull_request":
        require(pr_number > 0 and ref == f"refs/pull/{pr_number}/merge"
                and pr_base == "main" and head_repository == REPOSITORY,
                "risk decision applies only to same-repository pull requests targeting main")
    elif event == "push":
        require(pr_number == 0 and ref == "refs/heads/main",
                "risk decision applies only to pushes to main")
    else:
        raise RiskGateError("risk decision is not valid for this event")
    require(target in decision["profiles"] and platform in decision["architectures"],
            "unapproved profile or architecture")
    now = now or dt.datetime.now(dt.timezone.utc)
    require(now.tzinfo is not None
            and parse_utc(decision["expires_at"], "decision expiry") > now,
            "decision is expired")

    results = report.get("Results")
    require(isinstance(results, list) and results,
            "missing complete Trivy Results inventory")
    observed = set()
    for result in results:
        require(isinstance(result, dict) and isinstance(result.get("Target"), str),
                "invalid Trivy target")
        secrets = result.get("Secrets") or []
        require(isinstance(secrets, list) and not secrets,
                "secret findings cannot be risk accepted")
        vulns = result.get("Vulnerabilities") or []
        require(isinstance(vulns, list), "invalid Trivy vulnerabilities")
        for finding in vulns:
            require(isinstance(finding, dict), "invalid Trivy finding")
            cve = finding.get("VulnerabilityID")
            require(isinstance(cve, str) and CVE.fullmatch(cve) is not None,
                    "unrecognised security finding")
            require(result.get("Type") == "ubuntu",
                    "finding OS ecosystem is outside the approved decision")
            identity = (
                finding.get("PkgName"), finding.get("InstalledVersion"),
                finding.get("Severity"), result.get("Type"),
            )
            require(cve in authenticated["allowed"],
                    "unapproved HIGH/CRITICAL CVE: " + cve)
            require(identity == authenticated["allowed"][cve],
                    "finding package, version, severity or ecosystem differs from the decision: " + cve)
            require(not finding.get("FixedVersion"),
                    "supported fixed-version signal; remediate instead: " + cve)
            require(cve not in observed, "duplicate or ambiguous CVE finding: " + cve)
            observed.add(cve)
    require(observed, "Trivy reported a failing scan without an eligible vulnerability inventory")
    return {
        "decision": "development_risk_accepted_not_remediated",
        "authority": "exact-byte protected development decision; not remediation or VEX not_affected",
        "decision_sha256": authenticated["sha256"],
        "package": "linux-libc-dev",
        "version": "7.0.0-44.44",
        "profile": target,
        "platform": platform,
        "known_cves_observed": len(observed),
        "critical": sum(authenticated["allowed"][cve][2] == "CRITICAL" for cve in observed),
        "expiry_utc": decision["expires_at"],
        "scope": "development CI only; no tag, release, publication, signing, promotion, staging or production authority",
        "technical_applicability": "under_investigation",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-trivy", type=Path, required=True)
    parser.add_argument("--decision", type=Path, default=Path(DECISION_PATH))
    parser.add_argument("--evidence-lock", type=Path, default=Path(EVIDENCE_LOCK_PATH))
    parser.add_argument("--protected-decision-sha256", default="")
    parser.add_argument("--target", required=True)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--event", required=True)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--pr-number", type=int, default=0)
    parser.add_argument("--pr-base", default="")
    parser.add_argument("--head-repository", default="")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        authenticated = load_decision(
            args.decision, args.evidence_lock, args.protected_decision_sha256
        )
        report = json.loads(args.raw_trivy.read_text())
        decision = validate(
            report, authenticated, target=args.target, platform=args.platform,
            event=args.event, ref=args.ref, repository=args.repository,
            pr_number=args.pr_number, pr_base=args.pr_base,
            head_repository=args.head_repository,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(decision, indent=2, sort_keys=True) + "\n")
        print("::warning::DEV-10 exact-byte development risk accepted, NOT REMEDIATED:",
              decision["known_cves_observed"], "matching kernel-header findings;",
              "expiry", decision["expiry_utc"])
        return 0
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print("::error::DEV-10 security risk acceptance DENIED:", str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
