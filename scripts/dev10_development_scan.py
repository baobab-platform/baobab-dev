#!/usr/bin/env python3
"""Enforce and explain the protected policy on one local development image."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlencode

from evaluate_protected_risk_decision import (
    ARCHES, DIGEST, EXECUTION_SCOPE, PROFILES, REPOSITORY, TRIVY_VERSION, DecisionDenied,
    demand, validate_execution_context, verify_decision_bytes,
)
from prepare_dev10_risk_inventory import FindingNeedsRemediation, finding_records, scan_findings
from provision_protected_risk_policy import (
    DECISION_PATH, OWNER_USER_ID, IndependentApprovalMissing, OwnerConcurrenceMissing, ProvisioningError,
)
from verify_protected_policy_hash import DecisionInactive, InventoryChanged, verify_policy
from verify_protected_risk_custody import verify_read_custody

FINDINGS_EXIT_CODE = 42
SHA256 = re.compile(r"[a-f0-9]{64}")
COMMIT = re.compile(r"[a-f0-9]{40}")
RUN_NUMBER = re.compile(r"[1-9][0-9]*")
PACKAGE_LABEL = re.compile(r"[a-zA-Z0-9@._:/+~=-]{1,100}")
REPO_URL = f"https://github.com/{REPOSITORY}"
OPERATING_GUIDE = f"{REPO_URL}/blob/main/docs/security/protected-artifact-risk-decisions.md"


class ScanBlocked(ValueError):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def inventory_summary(findings):
    packages = Counter((finding[1], finding[2]) for finding in findings)
    severities = Counter(finding[3] for finding in findings)
    return {"count": len(findings), "severity": dict(sorted(severities.items())), "packages": [
        {"package": name, "version": version, "count": count}
        for (name, version), count in sorted(packages.items())
    ]}


def scan_identity(report, args):
    metadata = report.get("Metadata") if isinstance(report, dict) else None
    demand(isinstance(metadata, dict), "Trivy image metadata is missing")
    image_config = metadata.get("ImageConfig")
    digest = metadata.get("ImageID")
    demand(isinstance(digest, str) and DIGEST.fullmatch(digest), "Trivy image config digest is missing")
    demand(isinstance(image_config, dict) and image_config.get("os") == "linux"
           and image_config.get("architecture") == args.architecture.split("/", 1)[1],
           "Trivy image platform differs from the build platform")
    if args.image_config_digest:
        demand(digest == args.image_config_digest, "Trivy scanned a different local image config")
    results = report.get("Results")
    demand(isinstance(results, list) and any(isinstance(result, dict)
               and result.get("Class") == "os-pkgs" and result.get("Type") == "ubuntu"
               for result in results), "Ubuntu package scan coverage is missing")
    return {"image_config_digest": digest, "image_archive_sha256": args.archive_sha256}


def review_request(args, evidence, change):
    observed, approved = change.observed, change.approved
    findings = [dict(finding, disposition="pending", supporting_evidence=[])
                for finding in finding_records(observed - approved)]
    covered = finding_records(observed & approved)
    request = {
        **evidence, "schema": "baobab.dev10.risk-review-request.v1", "status": "review_required",
        "accountable_owner_id": OWNER_USER_ID, "proposed_expires_at": None,
        "findings_requiring_disposition": findings,
        "already_covered": covered, "covered_findings": len(covered),
        "new_or_changed_findings": len(findings),
    }
    path = args.evidence_dir / "risk-review-request.json"
    write_json(path, request)
    evidence["review_request_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()


def evaluate(args, env, evidence):
    if args.scan_exit_code not in (0, FINDINGS_EXIT_CODE):
        raise ScanBlocked("technical_scan_failure", "Trivy did not complete successfully.")
    raw = args.report.read_bytes()
    report = json.loads(raw)
    evidence.update(scan_identity(report, args))
    evidence["raw_trivy_sha256"] = hashlib.sha256(raw).hexdigest()
    trivy = report.get("Trivy")
    demand(isinstance(trivy, dict) and trivy.get("Version") == TRIVY_VERSION,
           "Trivy report does not identify the pinned scanner version")
    evidence["trivy_version"] = TRIVY_VERSION
    subprocess.run([sys.executable, str(Path(__file__).with_name("summarize-trivy-vulnerabilities.py")),
                    str(args.report), str(args.evidence_dir / "findings.json"),
                    args.profile, args.architecture], check=True)
    for field, name in (("sanitized_trivy_sha256", "trivy-vulnerabilities.json"),
                        ("findings_sha256", "findings.json")):
        evidence[field] = hashlib.sha256((args.evidence_dir / name).read_bytes()).hexdigest()
    try:
        observed = scan_findings(report, scanner_version=TRIVY_VERSION)
    except FindingNeedsRemediation as exc:
        raise ScanBlocked("remediation_required", str(exc)) from exc
    demand(bool(observed) == (args.scan_exit_code == FINDINGS_EXIT_CODE),
           "Trivy exit status disagrees with its finding inventory")
    evidence["observed"] = inventory_summary(observed)
    if not observed:
        return "clean", "The scan completed with zero blocking findings."

    context = dict(event=env.get("GITHUB_EVENT_NAME", ""), ref=env.get("GITHUB_REF", ""),
                   base_ref=env.get("GITHUB_BASE_REF", ""),
                   head_repository=env.get("POLICY_HEAD_REPOSITORY", ""))
    try:
        demand(env.get("GITHUB_REPOSITORY") == REPOSITORY, "repository is outside the development scope")
        validate_execution_context({"execution_scope": EXECUTION_SCOPE}, **context)
    except DecisionDenied as exc:
        raise ScanBlocked("outside_development_scope", str(exc)) from exc

    anchor = env.get("TRUSTED_POLICY_SHA", "")
    decision_path = Path(DECISION_PATH)
    if not anchor or not decision_path.is_file():
        raise ScanBlocked("awaiting_activation", "Verify merged custody and provision the decision SHA-256.")
    if not SHA256.fullmatch(anchor):
        raise ScanBlocked("policy_configuration_invalid", "The configured decision SHA-256 is malformed.")
    decision_bytes = decision_path.read_bytes()
    if hashlib.sha256(decision_bytes).hexdigest() != anchor:
        raise ScanBlocked("awaiting_activation", "Decision bytes differ from the active trust anchor.")
    token = env.get("GITHUB_TOKEN")
    logins = [item.strip() for item in env.get("TRUSTED_APPROVERS", "").split(",") if item.strip()]
    if not token or not logins:
        raise ScanBlocked("policy_configuration_invalid", "GitHub custody credentials or trusted reviewers are missing.")
    try:
        decision, decision_sha = verify_decision_bytes(decision_bytes, anchor)
        custody = verify_read_custody(token, decision, DECISION_PATH, logins)
        demand(custody["merged_decision_sha256"] == decision_sha,
               "local decision bytes differ from verified merged custody")
        evidence["custody"] = custody
        acceptance = verify_policy(
            decision, decision_sha, observed, profile=args.profile, architecture=args.architecture,
            approval_id=custody["approval_id"], approval_timestamp=custody["approved_at"],
            approved_by_id=custody["approved_by_id"], **context,
        )
    except OwnerConcurrenceMissing as exc:
        raise ScanBlocked("awaiting_owner_concurrence", str(exc)) from exc
    except IndependentApprovalMissing as exc:
        raise ScanBlocked("awaiting_independent_approval", str(exc)) from exc
    except InventoryChanged as exc:
        evidence["approved"] = inventory_summary(exc.approved)
        evidence["out_of_scope"] = inventory_summary(exc.observed - exc.approved)
        review_request(args, evidence, exc)
        raise ScanBlocked("inventory_changed", str(exc)) from exc
    except DecisionInactive as exc:
        raise ScanBlocked("decision_inactive", str(exc)) from exc
    except (ProvisioningError, ValueError, KeyError) as exc:
        raise ScanBlocked("policy_verification_failed", str(exc) if isinstance(exc, DecisionDenied)
                          else "Protected decision or live custody verification failed.") from exc
    write_json(args.evidence_dir / "dev10-protected-risk-acceptance.json", acceptance)
    return "covered", "Verified development-only residual-risk acceptance applies."


def write_step_summary(path, evidence):
    lines = ["## DEV-10 development image security scan", "",
             f"**{evidence['status'].replace('_', ' ').capitalize()}** · {evidence['message']}", "",
             f"- Scope: `{evidence['profile']}` on `{evidence['architecture']}`",
             f"- Scanned source: `{evidence['source_sha']}`"]
    for label, key in (("Observed", "observed"), ("Approved", "approved"), ("Outside decision", "out_of_scope")):
        if key in evidence:
            inventory = evidence[key]
            counts = ", ".join(f"{count} {severity}" for severity, count in inventory["severity"].items())
            lines.append(f"- {label}: {inventory['count']} exact findings" + (f" ({counts})" if counts else ""))
            if key in {"observed", "approved"}:
                for item in inventory["packages"][:8]:
                    package, version = item["package"], item["version"]
                    if PACKAGE_LABEL.fullmatch(package) and PACKAGE_LABEL.fullmatch(version):
                        lines.append(f"  - `{package}={version}` · {item['count']}")
    if "review_request_sha256" in evidence:
        run_url = f"{REPO_URL}/actions/runs/{evidence['run_id']}/attempts/{evidence['run_attempt']}"
        parameters = urlencode({
            "title": f"DEV-10 risk review: {evidence['source_sha'][:12]} {evidence['profile']} {evidence['architecture']}",
            "assignees": "bjnabs",
            "body": f"Scan evidence: {run_url}\n\nScanned source: `{evidence['source_sha']}`\n"
                    f"Image config digest: `{evidence['image_config_digest']}`\n"
                    f"Review request SHA-256: `{evidence['review_request_sha256']}`\n\n"
                    "Use `risk-review-request.json` to record a disposition and evidence for each finding. "
                    "Resolve fixes first. Prepare any proposed residual-risk treatment in a dedicated decision PR.",
        })
        lines += ["", f"[Open the owner review request]({REPO_URL}/issues/new?{parameters})"]
    lines += ["", f"[Risk decision operating guide]({OPERATING_GUIDE})", ""]
    with path.open("a", encoding="utf-8") as output:
        output.write("\n".join(lines))


def main(argv=None, *, env=None):
    env = os.environ if env is None else env
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--scan-exit-code", type=int, required=True)
    parser.add_argument("--profile", choices=sorted(PROFILES), required=True)
    parser.add_argument("--architecture", choices=sorted(ARCHES), required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    image = parser.add_mutually_exclusive_group(required=True)
    image.add_argument("--image-config-digest")
    image.add_argument("--archive-sha256")
    args = parser.parse_args(argv)
    args.evidence_dir.mkdir(parents=True, exist_ok=True)
    evidence = {"schema": "baobab.dev10.development-scan.v1", "profile": args.profile,
                "architecture": args.architecture, "source_sha": env.get("GITHUB_SHA", ""),
                "pull_request_head_sha": env.get("POLICY_HEAD_SHA") or None,
                "run_id": env.get("GITHUB_RUN_ID", ""), "run_attempt": env.get("GITHUB_RUN_ATTEMPT", ""),
                "environment": "development", "repository": REPOSITORY,
                "scan_exit_code": args.scan_exit_code}
    try:
        demand(COMMIT.fullmatch(evidence["source_sha"]) and RUN_NUMBER.fullmatch(evidence["run_id"])
               and RUN_NUMBER.fullmatch(evidence["run_attempt"]), "invalid GitHub source or run identity")
        demand(evidence["pull_request_head_sha"] is None or COMMIT.fullmatch(evidence["pull_request_head_sha"]),
               "invalid pull request source identity")
        demand((args.image_config_digest and DIGEST.fullmatch(args.image_config_digest))
               or (args.archive_sha256 and SHA256.fullmatch(args.archive_sha256)), "invalid local image identity")
        status, message = evaluate(args, env, evidence)
    except ScanBlocked as exc:
        status, message = exc.status, str(exc)
    except DecisionDenied as exc:
        status, message = "technical_scan_failure", str(exc)
    except (OSError, ValueError, subprocess.CalledProcessError):
        status, message = "technical_scan_failure", "The Trivy report could not be read or retained."
    evidence.update(status=status, message=message)
    write_json(args.evidence_dir / "gate-result.json", evidence)
    if env.get("GITHUB_STEP_SUMMARY"):
        write_step_summary(Path(env["GITHUB_STEP_SUMMARY"]), evidence)
    if status in {"clean", "covered"}:
        print(f"DEV-10 scan {status}: {message}")
        return 0
    print(f"::error::DEV-10 scan {status}: {message} See the scan evidence and job summary.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
