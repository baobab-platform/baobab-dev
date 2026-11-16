#!/usr/bin/env python3
"""Evaluate an approved DEV-10 risk policy against one exact GHCR image digest."""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import sys

DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
CVE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
PROFILES = frozenset(("final", "frontend", "frontend-e2e", "infra"))
ARCHES = frozenset(("linux/amd64", "linux/arm64"))
SEVERITIES = frozenset(("HIGH", "CRITICAL"))
REPOSITORY = "baobab-platform/baobab-dev"
IMAGE_REPOSITORY = f"ghcr.io/{REPOSITORY}"
TRIVY_VERSION = "0.73.0"
EXECUTION_SCOPE = {"pull_request_base": "main", "pull_request_head_repository": REPOSITORY, "push_ref": "refs/heads/main"}


class DecisionDenied(ValueError):
    """The scan or policy does not satisfy the protected risk contract."""


def validate_execution_context(decision: dict, *, event: str, ref: str,
                               base_ref: str = "", head_repository: str = "") -> None:
    """Restrict exceptions to PRs targeting main and pushes to main."""
    demand(decision.get("execution_scope") == EXECUTION_SCOPE,
           "risk decision execution scope is missing or broader than development main")
    if event == "pull_request":
        demand(base_ref == "main", "risk decision applies only to pull requests targeting main")
        demand(head_repository == REPOSITORY,
               "fork pull requests are outside the reusable development-risk scope")
        demand(re.fullmatch(r"refs/pull/[1-9][0-9]*/merge", ref) is not None,
               "pull request merge ref is invalid")
        return
    if event == "push":
        demand(ref == "refs/heads/main" and not base_ref
               and head_repository == REPOSITORY,
               "risk decision applies only to pushes to development main")
        return
    raise DecisionDenied(
        "risk decision is unavailable to tags, releases, dispatch, schedules or deployments"
    )


def demand(condition: bool, reason: str) -> None:
    if not condition:
        raise DecisionDenied(reason)


def verify_decision_bytes(raw: bytes, trusted_sha256: str) -> tuple[dict, str]:
    """Authenticate exact policy bytes against a protected, independently managed hash."""
    demand(isinstance(raw, bytes), "risk decision must be supplied as raw file bytes")
    demand(isinstance(trusted_sha256, str)
           and re.fullmatch(r"[a-f0-9]{64}", trusted_sha256) is not None,
           "missing or invalid protected policy SHA-256")
    actual = hashlib.sha256(raw).hexdigest()
    demand(actual == trusted_sha256, "decision bytes differ from protected approval")
    decision = json.loads(raw)
    demand(isinstance(decision, dict), "invalid decision document")
    return decision, actual


def load_verified_decision(path: Path, trusted_sha256: str) -> tuple[dict, str]:
    """Load a policy file and authenticate its exact bytes against the trust anchor."""
    return verify_decision_bytes(path.read_bytes(), trusted_sha256)


def _timestamp(decision: dict, field: str) -> dt.datetime:
    value = decision.get(field)
    demand(isinstance(value, str) and bool(value), f"{field} is missing")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise DecisionDenied(f"{field} is invalid") from exc
    demand(parsed.tzinfo is not None, f"{field} must include a timezone")
    return parsed


def _finding_key(finding: dict) -> tuple[str, str, str, str, str]:
    demand(isinstance(finding, dict), "invalid vulnerability finding")
    cve, package, version, severity, package_type = (
        finding.get("cve"), finding.get("package"),
        finding.get("version"), finding.get("severity"),
        finding.get("type")
    )
    demand(isinstance(cve, str) and CVE.fullmatch(cve) is not None,
           "invalid CVE identifier in finding")
    demand(all(isinstance(value, str) and value.strip()
               for value in (package, version, severity, package_type)),
           "finding package, version, severity or ecosystem type is missing")
    demand(severity in SEVERITIES, "only HIGH/CRITICAL findings may be risk accepted")
    return cve, package, version, severity, package_type


def _validate_scan_identity(report: dict, *, image_repository: str,
                            image_digest: str, architecture: str,
                            expected_trivy_version: str) -> None:
    demand(report.get("SchemaVersion") == 2, "unsupported or missing Trivy report schema")
    demand(report.get("ArtifactType") == "container_image", "Trivy report is not a container image scan")
    trivy = report.get("Trivy")
    demand(isinstance(trivy, dict) and trivy.get("Version") == expected_trivy_version,
           "unexpected Trivy version")
    metadata = report.get("Metadata")
    demand(isinstance(metadata, dict), "Trivy image metadata is missing")
    expected_ref = f"{image_repository}@{image_digest}"
    repo_digests = metadata.get("RepoDigests")
    demand(isinstance(repo_digests, list) and expected_ref in repo_digests,
           "Trivy report does not identify the exact requested GHCR digest")
    image_config = metadata.get("ImageConfig")
    demand(isinstance(image_config, dict), "Trivy image configuration metadata is missing")
    demand(image_config.get("os") == "linux", "scanned image operating system is not linux")
    demand(image_config.get("architecture") == architecture.split("/", 1)[1],
           "scanned image architecture differs from the requested architecture")


def evaluate(decision_bytes: bytes | None, report: dict, *, image_repository: str,
             image_digest: str, profile: str, architecture: str,
             environment: str, expected_trivy_version: str = TRIVY_VERSION,
             trusted_decision_sha256: str | None = None,
             report_sha256: str | None = None,
             event: str | None = None, ref: str | None = None,
             base_ref: str = "", head_repository: str | None = None,
             approval_id: str | None = None, approval_timestamp: str | None = None,
             approved_by_id: int | None = None,
             now: dt.datetime | None = None) -> dict:
    """Qualify a scan; a clean scan needs no risk decision."""
    now = now or dt.datetime.now(dt.timezone.utc)
    demand(now.tzinfo is not None, "timezone-aware clock required")
    demand(environment == "development", "risk decisions are development-only")
    demand(image_repository == IMAGE_REPOSITORY, "unapproved image repository")
    demand(isinstance(image_digest, str) and bool(DIGEST.fullmatch(image_digest)),
           "immutable image digest required")
    demand(profile in PROFILES and architecture in ARCHES, "unknown profile or architecture")
    demand(expected_trivy_version == TRIVY_VERSION, "unqualified Trivy version")
    demand(isinstance(report, dict), "invalid Trivy report")
    _validate_scan_identity(report, image_repository=image_repository,
                            image_digest=image_digest, architecture=architecture,
                            expected_trivy_version=expected_trivy_version)

    results = report.get("Results")
    demand(isinstance(results, list) and bool(results),
           "missing Trivy result inventory; scan cannot be treated as clean")
    observed: set[tuple[str, str, str, str, str]] = set()
    for result in results:
        demand(isinstance(result, dict) and isinstance(result.get("Target"), str),
               "invalid Trivy scan target")
        secrets = result.get("Secrets") or []
        demand(isinstance(secrets, list), "invalid Trivy secret findings")
        demand(not secrets, "secret findings cannot be risk accepted")
        vulnerabilities = result.get("Vulnerabilities") or []
        demand(isinstance(vulnerabilities, list), "invalid Trivy vulnerability list")
        for vulnerability in vulnerabilities:
            demand(isinstance(vulnerability, dict), "invalid Trivy vulnerability")
            key = _finding_key({
                "cve": vulnerability.get("VulnerabilityID"),
                "package": vulnerability.get("PkgName"),
                "version": vulnerability.get("InstalledVersion"),
                "severity": vulnerability.get("Severity"),
                "type": result.get("Type"),
            })
            demand(not vulnerability.get("FixedVersion"),
                   "a fixed version is available; remediate instead of accepting risk")
            # The same package advisory can appear under multiple Trivy targets.
            # It is one policy identity; preserve it once rather than false-failing.
            observed.add(key)

    common = {
        "image_repository": image_repository,
        "image_digest": image_digest,
        "profile": profile,
        "architecture": architecture,
        "environment": environment,
        "trivy_version": expected_trivy_version,
        "report_sha256": report_sha256,
    }
    if not observed:
        return {"status": "clean_no_exception_required", **common, "findings": 0}

    demand(isinstance(decision_bytes, bytes),
           "HIGH/CRITICAL findings exist but no protected risk decision was supplied")
    decision, policy_sha256 = verify_decision_bytes(
        decision_bytes, trusted_decision_sha256
    )
    # Development CI policies carry an explicit execution_scope and must be
    # bound to a pull_request->main or push->main event. Other, separately
    # governed decision records (for example release-digest records) retain
    # their own workflow-specific custody path and cannot inherit this policy.
    if "execution_scope" in decision:
        demand(isinstance(event, str) and isinstance(ref, str),
               "GitHub event/ref context is required for residual-risk acceptance")
        validate_execution_context(decision, event=event, ref=ref, base_ref=base_ref,
                                   head_repository=head_repository or "")
    demand(decision.get("schema_version") == 2, "unsupported risk decision schema")
    demand(decision.get("status") == "approved", "risk decision is not approved or has been revoked")
    demand(decision.get("revoked_at") in (None, ""), "risk decision has been revoked")
    demand(decision.get("repository") == REPOSITORY, "risk decision repository mismatch")
    demand(decision.get("image_repository") == image_repository,
           "image repository is outside the approved risk scope")
    demand(decision.get("environment") == environment,
           "environment is outside the approved risk scope")
    approved_profiles = decision.get("profiles")
    approved_architectures = decision.get("architectures")
    demand(isinstance(approved_profiles, list) and bool(approved_profiles)
           and all(item in PROFILES for item in approved_profiles),
           "invalid approved image profile scope")
    demand(isinstance(approved_architectures, list) and bool(approved_architectures)
           and all(item in ARCHES for item in approved_architectures),
           "invalid approved architecture scope")
    demand(profile in approved_profiles, "image profile is outside the approved risk scope")
    demand(architecture in approved_architectures,
           "architecture is outside the approved risk scope")

    prepared_by_id = decision.get("prepared_by_id")
    evidence = decision.get("approval_evidence")
    if "execution_scope" in decision:
        demand(isinstance(approval_id, str) and approval_id.strip()
               and isinstance(approval_timestamp, str) and approval_timestamp.strip(),
               "verified GitHub approval ID and timestamp are required")
        approved_at = _timestamp({"approved_at": approval_timestamp}, "approved_at")
    else:
        approval_id = decision.get("approval_id")
        demand(isinstance(approval_id, str) and approval_id.strip(), "approval identifier missing")
        approved_at = _timestamp(decision, "approved_at")
    if "execution_scope" in decision:
        demand(type(prepared_by_id) is int and prepared_by_id > 0
               and type(approved_by_id) is int and approved_by_id > 0
               and prepared_by_id != approved_by_id,
               "numeric maker-checker separation required")
    else:
        prepared_by = decision.get("prepared_by")
        approved_by = decision.get("approved_by")
        demand(isinstance(prepared_by, str) and prepared_by.strip()
               and isinstance(approved_by, str) and approved_by.strip()
               and prepared_by.casefold() != approved_by.casefold(),
               "maker-checker separation required")
    demand(isinstance(evidence, str)
           and re.fullmatch(
               rf"https://github\.com/{re.escape(REPOSITORY)}/pull/[1-9][0-9]*",
               evidence,
           ) is not None,
           "approval evidence must link to the merged protected decision pull request")

    expires_at = _timestamp(decision, "expires_at")
    demand(approved_at <= now < expires_at and approved_at < expires_at,
           "risk decision is not currently valid")

    expected_findings = decision.get("findings")
    demand(isinstance(expected_findings, list) and bool(expected_findings),
           "approved finding inventory is missing")
    approved: set[tuple[str, str, str, str, str]] = set()
    for finding in expected_findings:
        key = _finding_key(finding)
        demand(key not in approved, "duplicate finding in approved risk inventory")
        approved.add(key)

    unapproved = observed - approved
    demand(not unapproved,
           "new or changed vulnerability requires a separate security decision: "
           + ", ".join(sorted(item[0] for item in unapproved)))

    approved_by = decision.get("approved_by")
    return {
        "status": "accepted_residual_risk_not_remediated",
        "approval_id": approval_id,
        "approved_by_id": approved_by_id,
        "approved_by": approved_by,
        "policy_sha256": policy_sha256,
        "expires_at": decision["expires_at"],
        "approved_findings": len(approved),
        "observed_findings": len(observed),
        "findings": [dict(cve=a, package=b, version=c, severity=d, type=e)
                     for a, b, c, d, e in sorted(observed)],
        **common,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--decision", type=Path)
    parser.add_argument("--trusted-decision-sha256")
    parser.add_argument("--image-repository", required=True)
    parser.add_argument("--digest", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--architecture", required=True)
    parser.add_argument("--environment", required=True)
    parser.add_argument("--event", default="")
    parser.add_argument("--ref", default="")
    parser.add_argument("--base-ref", default="")
    parser.add_argument("--head-repository", default="")
    parser.add_argument("--approval-id")
    parser.add_argument("--approved-at")
    parser.add_argument("--approved-by-id", type=int)
    parser.add_argument("--expected-trivy-version", default=TRIVY_VERSION)
    parser.add_argument("--result-output", type=Path)
    args = parser.parse_args()

    try:
        raw_report = args.report.read_bytes()
        report = json.loads(raw_report)
        decision_bytes = None
        scan_results = report.get("Results") if isinstance(report, dict) else None
        has_findings = any(
            isinstance(item, dict) and bool(item.get("Vulnerabilities"))
            for item in (scan_results or [])
        )
        if has_findings:
            demand(args.decision is not None, "risk decision file is required for HIGH/CRITICAL findings")
            demand(args.trusted_decision_sha256 is not None,
                   "protected decision SHA-256 is required for HIGH/CRITICAL findings")
            decision_bytes = args.decision.read_bytes()
        result = evaluate(
            decision_bytes, report,
            image_repository=args.image_repository,
            image_digest=args.digest,
            profile=args.profile,
            architecture=args.architecture,
            environment=args.environment,
            expected_trivy_version=args.expected_trivy_version,
            trusted_decision_sha256=args.trusted_decision_sha256,
            report_sha256=hashlib.sha256(raw_report).hexdigest(),
            event=args.event, ref=args.ref, base_ref=args.base_ref,
            head_repository=args.head_repository,
            approval_id=args.approval_id, approval_timestamp=args.approved_at,
            approved_by_id=args.approved_by_id,
        )
        exit_code = 0
    except (DecisionDenied, OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        result = {"status": "denied", "reason": str(exc)}
        print("SECURITY DENIED:", exc, file=sys.stderr)
        exit_code = 2

    if args.result_output is not None:
        args.result_output.parent.mkdir(parents=True, exist_ok=True)
        args.result_output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
