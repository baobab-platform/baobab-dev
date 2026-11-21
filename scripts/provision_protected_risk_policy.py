#!/usr/bin/env python3
"""Authenticate and provision the exact merged DEV-10 development policy hash.

This is an explicit custodian operation. It never approves or merges a decision.
It verifies the merged decision PR, its exact-head effective independent review,
complete numeric contributor custody, and byte-for-byte continuity between the
approved PR head and current main before creating the repository Actions
variable. Existing different values are never overwritten.
"""
import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import re
import sys
import urllib.parse
from pathlib import Path

from custody_independence import (
    REPOSITORY, CustodyError, _safe_detail, collect_pr, is_positive_id,
    latest_user_reviews, require_independent, resolve_trusted_user_ids, rest_user_id,
)
from github_api_transport import GitHubAPIError, rest_request
from evaluate_protected_risk_decision import DecisionDenied, validate_decision_evidence_lock

DECISION_PATH = "security/decisions/development/foundation.json"
VARIABLE_NAME = "DEV10_PROTECTED_DECISION_SHA256"
OWNER_USER_ID = 350241706  # @wekhason; accountable owner per PR #74 handover
EXPECTED_EXPIRY = "2026-11-26T00:00:00Z"
BASE_FINDINGS = frozenset({
    ("CVE-2022-50240", "linux-libc-dev", "7.0.0-43.43", "HIGH", "ubuntu"),
    ("CVE-2025-40190", "linux-libc-dev", "7.0.0-43.43", "HIGH", "ubuntu"),
    ("CVE-2026-68103", "linux-libc-dev", "7.0.0-43.43", "HIGH", "ubuntu"),
    ("CVE-2026-72198", "linux-libc-dev", "7.0.0-43.43", "HIGH", "ubuntu"),
    ("CVE-2026-74578", "linux-libc-dev", "7.0.0-43.43", "HIGH", "ubuntu"),
    ("CVE-2026-89805", "linux-libc-dev", "7.0.0-43.43", "HIGH", "ubuntu"),
    ("CVE-2026-98376", "linux-libc-dev", "7.0.0-43.43", "HIGH", "ubuntu"),
    ("CVE-2026-98420", "linux-libc-dev", "7.0.0-43.43", "HIGH", "ubuntu"),
})
EXTENDED_FINDINGS = BASE_FINDINGS | frozenset({
    ("CVE-2026-98869", "linux-libc-dev", "7.0.0-43.43", "HIGH", "ubuntu"),
    ("CVE-2026-98890", "linux-libc-dev", "7.0.0-43.43", "HIGH", "ubuntu"),
    ("CVE-2026-99083", "linux-libc-dev", "7.0.0-43.43", "HIGH", "ubuntu"),
    ("CVE-2026-112366", "picomatch", "4.0.5", "HIGH", "node-pkg"),
})
EXPECTED_SCOPE = {
    "pull_request_base": "main",
    "push_ref": "refs/heads/main",
    "pull_request_head_repository": REPOSITORY,
}
EXPECTED_FIELDS = {
    "schema_version", "record_type", "status", "revoked_at", "repository",
    "image_repository", "environment", "execution_scope", "profiles",
    "architectures", "prepared_by", "prepared_by_id", "approval_evidence",
    "expires_at", "findings", "finding_count", "notes",
}
EXPECTED_FIELDS_WITH_EVIDENCE_LOCK = EXPECTED_FIELDS | {"evidence_lock_sha256"}



class ProvisioningError(RuntimeError):
    """A fail-closed policy provisioning error."""


def require(condition, message):
    if not condition:
        raise ProvisioningError(message)


def parse_utc(value, label):
    require(isinstance(value, str) and bool(value), f"{label} is missing")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProvisioningError(f"{label} is not an ISO-8601 timestamp") from exc
    require(parsed.tzinfo is not None, f"{label} must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def validate_decision(decision, *, decision_pr, now=None):
    """Validate the exact approved policy contract before any API mutation."""
    require(isinstance(decision, dict), "decision must be a JSON object")
    require(
        set(decision) in (EXPECTED_FIELDS, EXPECTED_FIELDS_WITH_EVIDENCE_LOCK),
        "decision fields differ from the approved schema",
    )
    require(decision["schema_version"] == 2, "unsupported decision schema version")
    require(decision["record_type"] == "proposed_approved_form",
            "decision record type is not the approved-form candidate")
    require(decision["status"] == "approved" and decision["revoked_at"] is None,
            "decision is not approved or has been revoked")
    require(decision["repository"] == REPOSITORY, "decision repository mismatch")
    require(decision["image_repository"] == "ghcr.io/" + REPOSITORY,
            "decision image repository mismatch")
    require(decision["environment"] == "development", "decision is not development-only")
    require(decision["execution_scope"] == EXPECTED_SCOPE, "decision execution scope widened")
    require(set(decision["profiles"]) == {"final", "frontend", "frontend-e2e", "infra"}
            and len(decision["profiles"]) == 4, "decision profile inventory mismatch")
    require(set(decision["architectures"]) == {"linux/amd64", "linux/arm64"}
            and len(decision["architectures"]) == 2, "decision architecture inventory mismatch")
    require(decision["expires_at"] == EXPECTED_EXPIRY, "decision expiry differs from approved record")
    require(parse_utc(decision["expires_at"], "decision expiry") > (now or dt.datetime.now(dt.timezone.utc)),
            "decision is expired")
    require(type(decision["prepared_by_id"]) is int and decision["prepared_by_id"] > 0,
            "numeric preparer identity missing")
    require(isinstance(decision["prepared_by"], str) and decision["prepared_by"].strip(),
            "preparer login missing")
    expected_url = f"https://github.com/{REPOSITORY}/pull/{decision_pr}"
    require(decision["approval_evidence"] == expected_url,
            "approval evidence does not identify the decision PR")
    require(type(decision["finding_count"]) is int,
            "finding count is not an integer")
    require(isinstance(decision["notes"], str) and decision["notes"].strip(),
            "decision rationale is missing")

    findings = decision["findings"]
    require(isinstance(findings, list)
            and decision["finding_count"] == len(findings)
            and len(findings) in (8, 12),
            "finding inventory count differs from the bounded approved shape")
    observed = set()
    for finding in findings:
        require(isinstance(finding, dict)
                and set(finding) == {"cve", "package", "version", "severity", "type"},
                "malformed approved finding")
        identity = (
            finding["cve"], finding["package"], finding["version"],
            finding["severity"], finding["type"],
        )
        require(identity not in observed, "duplicate approved finding")
        observed.add(identity)
    require(len(observed) == len(findings)
            and observed in (BASE_FINDINGS, EXTENDED_FINDINGS),
            "approved inventory differs from the exact eight- or twelve-finding reviewed set")
    try:
        validate_decision_evidence_lock(decision)
    except DecisionDenied as exc:
        raise ProvisioningError(str(exc)) from exc
    return decision


def api_request(token, method, path, payload=None, allowed_status=()):
    try:
        return rest_request(token, method, path, payload, allowed_status)
    except GitHubAPIError as exc:
        raise ProvisioningError(str(exc)) from None


def paginated(token, path):
    results = []
    for page in range(1, 101):
        separator = "&" if "?" in path else "?"
        _, payload = api_request(token, "GET", f"{path}{separator}per_page=100&page={page}")
        require(isinstance(payload, list) and len(payload) <= 100,
                "GitHub pagination returned an invalid page")
        results.extend(payload)
        if len(payload) < 100:
            return results
    raise ProvisioningError("GitHub API pagination exceeded the 10,000-record safety limit")


def contents_bytes(token, path, ref):
    encoded_path = urllib.parse.quote(path, safe="/")
    query = urllib.parse.urlencode({"ref": ref})
    _, payload = api_request(token, "GET", f"/repos/{REPOSITORY}/contents/{encoded_path}?{query}")
    require(isinstance(payload, dict) and payload.get("type") == "file",
            f"{path} is not a regular repository file at {ref}")
    require(payload.get("encoding") == "base64" and isinstance(payload.get("content"), str),
            f"{path} is not available as base64 repository content at {ref}")
    try:
        encoded = re.sub(r"\s+", "", payload["content"])
        return base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ProvisioningError(f"{path} has invalid GitHub content encoding") from exc


def resolve_trusted_reviewers(token, logins):
    def fetch_user(login):
        return api_request(token, "GET", f"/users/{login}")[1]

    try:
        return resolve_trusted_user_ids(logins, fetch_user)
    except CustodyError as exc:
        raise ProvisioningError(str(exc)) from None


def verify_owner_concurrence(comments, *, merged_at, owner_user_id=OWNER_USER_ID):
    """Require attributable concurrence from the decision's owner before merge."""
    require(isinstance(comments, list), "decision PR issue-comment history is unavailable")
    merge_time = parse_utc(merged_at, "decision PR merge timestamp")
    qualifying = []
    for comment in comments:
        if not isinstance(comment, dict):
            continue
        user = comment.get("user") or {}
        body = comment.get("body")
        if (not isinstance(user, dict) or user.get("id") != owner_user_id
                or not isinstance(body, str)
                or "owner concurrence is hereby recorded" not in body.casefold()
                or "new reusable policy" not in body.casefold()):
            continue
        require(user.get("type") == "User" and is_positive_id(user.get("id")),
                "owner concurrence requires a typed numeric GitHub User")
        comment_id = comment.get("id")
        require(is_positive_id(comment_id),
                "owner concurrence comment ID is missing")
        created = parse_utc(comment.get("created_at"), "owner concurrence created_at")
        updated = parse_utc(comment.get("updated_at"), "owner concurrence updated_at")
        require(created <= updated <= merge_time,
                "owner concurrence must be created and last edited before the decision PR merge")
        qualifying.append((updated, comment_id, created))
    require(bool(qualifying),
            "attributable pre-merge owner concurrence is missing from the decision PR")
    updated, comment_id, created = max(qualifying, key=lambda item: (item[0], item[1]))
    return {
        "owner_id": owner_user_id,
        "owner_comment_id": comment_id,
        "owner_concurrence_at": created.isoformat().replace("+00:00", "Z"),
    }


def select_independent_approval(reviews, *, head, trusted_reviewers, author_id,
                                contributors, merged_at=None):
    """Select a trusted reviewer whose latest effective approval is on this exact head."""
    try:
        latest = latest_user_reviews(reviews)
    except CustodyError as exc:
        raise ProvisioningError(str(exc)) from None
    merge_time = parse_utc(merged_at, "decision PR merge timestamp") if merged_at else None

    qualifying = []
    for reviewer_id, (submitted, review_id, review) in latest.items():
        if review["state"] != "APPROVED" or review.get("commit_id") != head:
            continue
        if merge_time is not None and submitted > merge_time:
            continue
        if reviewer_id not in trusted_reviewers:
            continue
        try:
            require_independent(reviewer_id, set(trusted_reviewers), author_id, contributors)
        except ValueError:
            continue
        qualifying.append((submitted, review_id, reviewer_id, review))
    require(bool(qualifying),
            "no current-head APPROVED review by a trusted independent numeric reviewer")
    _, review_id, reviewer_id, review = max(
        qualifying, key=lambda item: (item[0], item[1])
    )
    return {
        "approval_id": f"github-review-{review_id}",
        "approved_by_id": reviewer_id,
        "reviewer": (review.get("user") or {}).get("login"),
        "approved_at": review["submitted_at"],
    }


def verify_merged_custody(token, decision, decision_pr, expected_head_sha, trusted_reviewers,
                          *, decision_path=DECISION_PATH):
    require(decision.get("approval_evidence") ==
            f"https://github.com/{REPOSITORY}/pull/{decision_pr}",
            "decision approval evidence does not identify the decision PR")
    base = f"/repos/{REPOSITORY}/pulls/{decision_pr}"
    _, pull = api_request(token, "GET", base)
    require(isinstance(pull, dict), "decision pull request metadata is unavailable")
    require(pull.get("state") == "closed" and pull.get("merged") is True
            and isinstance(pull.get("merged_at"), str),
            "decision PR must be merged and closed")
    base_ref = pull.get("base")
    base_repo = base_ref.get("repo") if isinstance(base_ref, dict) else None
    require(isinstance(base_repo, dict) and base_repo.get("full_name") == REPOSITORY
            and base_ref.get("ref") == "main", "decision PR must target this repository's main branch")
    head_ref = pull.get("head")
    head_repo = head_ref.get("repo") if isinstance(head_ref, dict) else None
    require(isinstance(head_repo, dict) and head_repo.get("full_name") == REPOSITORY,
            "decision PR must originate from this repository")
    head = head_ref.get("sha")
    require(isinstance(head, str) and head == expected_head_sha
            and re.fullmatch(r"[a-f0-9]{40}", head),
            "decision PR head differs from the explicitly approved expected head")
    merge_sha = pull.get("merge_commit_sha")
    require(isinstance(merge_sha, str) and re.fullmatch(r"[a-f0-9]{40}", merge_sha),
            "decision PR merge commit is unavailable")

    try:
        author_id = rest_user_id(pull.get("user"), "decision PR author")
    except CustodyError as exc:
        raise ProvisioningError(str(exc)) from None
    require(is_positive_id(decision.get("prepared_by_id")) and author_id == decision["prepared_by_id"],
            "decision PR author numeric identity differs from the recorded preparer")
    # The immutable numeric user ID is authoritative. prepared_by is
    # display metadata and may legitimately change if the account is renamed.

    files = paginated(token, base + "/files")
    require(any(isinstance(item, dict) and item.get("filename") == decision_path
                and item.get("status") in ("added", "modified")
                for item in files),
            "decision PR did not add or modify the protected decision file")

    # The approved PR bytes must match both the merge commit and current main.
    approved_bytes = contents_bytes(token, decision_path, head)
    merge_bytes = contents_bytes(token, decision_path, merge_sha)
    main_bytes = contents_bytes(token, decision_path, "main")
    require(approved_bytes == merge_bytes == main_bytes,
            "approved PR-head, merge-commit and current-main decision bytes differ")
    try:
        current_decision = json.loads(main_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProvisioningError("merged decision file is not valid UTF-8 JSON") from exc
    require(current_decision == decision,
            "decision content changed between validation and main-branch read")

    # Ensure the merge commit is an ancestor of current main, not merely a
    # historical PR whose bytes were independently copied onto main.
    _, comparison = api_request(
        token, "GET",
        f"/repos/{REPOSITORY}/compare/{merge_sha}...main",
    )
    merge_base = comparison.get("merge_base_commit") if isinstance(comparison, dict) else None
    require(isinstance(merge_base, dict) and merge_base.get("sha") == merge_sha
            and comparison.get("status") in ("ahead", "identical"),
            "decision PR merge commit is not an ancestor of current main")

    comments = paginated(
        token, f"/repos/{REPOSITORY}/issues/{decision_pr}/comments"
    )
    owner_concurrence = verify_owner_concurrence(comments, merged_at=pull["merged_at"])
    reviews = paginated(token, base + "/reviews")
    author_id_graphql, contributors = collect_pr(token, decision_pr, head)
    require(author_id_graphql == author_id,
            "REST and GraphQL decision PR author identities disagree")
    approval = select_independent_approval(
        reviews, head=head, trusted_reviewers=trusted_reviewers,
        author_id=author_id, contributors=contributors, merged_at=pull["merged_at"],
    )
    return {
        **approval,
        **owner_concurrence,
        "decision_pr": decision_pr,
        "decision_pr_head": head,
        "merge_commit_sha": merge_sha,
        "contributor_count": len(contributors),
    }


def provision_variable(token, policy_sha256):
    path = f"/repos/{REPOSITORY}/actions/variables/{VARIABLE_NAME}"
    status, current = api_request(token, "GET", path, allowed_status=(404,))
    if status == 200:
        require(isinstance(current, dict), "existing policy variable response is malformed")
        require(current.get("value") == policy_sha256,
                "a different policy trust anchor is already provisioned; refusing overwrite")
        return "already_provisioned"

    create_path = f"/repos/{REPOSITORY}/actions/variables"
    status, _ = api_request(
        token, "POST", create_path,
        {"name": VARIABLE_NAME, "value": policy_sha256},
        allowed_status=(409, 422),
    )
    if status in (409, 422):
        # A concurrent provisioner may have won the create race. Accept only
        # the exact same value; never overwrite a different anchor.
        verify_status, current = api_request(token, "GET", path, allowed_status=(404,))
        require(verify_status == 200 and isinstance(current, dict)
                and current.get("value") == policy_sha256,
                "concurrent provisioning created a different or unreadable trust anchor")
        return "already_provisioned"

    verify_status, current = api_request(token, "GET", path, allowed_status=(404,))
    require(verify_status == 200 and isinstance(current, dict)
            and current.get("value") == policy_sha256,
            "GitHub did not persist the exact provisioned trust anchor")
    return "provisioned"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-head-sha", required=True,
                        help="exact decision-PR head SHA approved for provisioning")
    parser.add_argument("--decision", type=Path, default=Path(DECISION_PATH))
    parser.add_argument("--token-env", default="GH_TOKEN")
    parser.add_argument("--trusted-approvers-env", default="DEV10_SECURITY_APPROVER_LOGINS")
    parser.add_argument("--dry-run", action="store_true",
                        help="verify all custody and hash inputs without changing the repository variable")
    args = parser.parse_args()

    try:
        require(re.fullmatch(r"[a-f0-9]{40}", args.expected_head_sha) is not None,
                "expected decision head must be a lowercase 40-character commit SHA")
        require(args.decision.as_posix() == DECISION_PATH,
                "only the fixed protected development decision path may be provisioned")
        if os.environ.get("GITHUB_REPOSITORY"):
            require(os.environ["GITHUB_REPOSITORY"] == REPOSITORY,
                    "provisioning must run in the canonical repository")
        if os.environ.get("GITHUB_REF"):
            require(os.environ["GITHUB_REF"] == "refs/heads/main",
                    "provisioning may run only from the main branch")

        token = os.environ.get(args.token_env, "")
        require(bool(token), f"{args.token_env} authentication token is required")
        raw = args.decision.read_bytes()
        decision = json.loads(raw)
        match = re.fullmatch(
            rf"https://github\.com/{re.escape(REPOSITORY)}/pull/([1-9][0-9]*)",
            decision.get("approval_evidence", "") if isinstance(decision, dict) else "",
        )
        require(match is not None, "decision approval evidence URL is invalid")
        decision_pr = int(match.group(1))
        validate_decision(decision, decision_pr=decision_pr)

        logins = [
            item.strip() for item in os.environ.get(args.trusted_approvers_env, "").split(",")
            if item.strip()
        ]
        trusted_reviewers = resolve_trusted_reviewers(token, logins)
        custody = verify_merged_custody(
            token, decision, decision_pr, args.expected_head_sha, trusted_reviewers
        )
        policy_sha256 = hashlib.sha256(raw).hexdigest()
        if args.dry_run:
            status = "verified_not_provisioned"
        else:
            status = provision_variable(token, policy_sha256)
        result = {
            "status": status,
            "repository": REPOSITORY,
            "variable": VARIABLE_NAME,
            "policy_sha256": policy_sha256,
            "decision_pr": decision_pr,
            "decision_pr_head": custody["decision_pr_head"],
            "merge_commit_sha": custody["merge_commit_sha"],
            "approval_id": custody["approval_id"],
            "approved_by_id": custody["approved_by_id"],
            "owner_id": custody["owner_id"],
            "owner_comment_id": custody["owner_comment_id"],
            "owner_concurrence_at": custody["owner_concurrence_at"],
            "reviewer": custody["reviewer"],
            "approved_at": custody["approved_at"],
            "expires_at": decision["expires_at"],
            "contributor_count": custody["contributor_count"],
        }
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ProvisioningError, OSError, ValueError, TypeError, KeyError,
            json.JSONDecodeError) as exc:
        print(f"DEV-10 POLICY PROVISIONING DENIED: {_safe_detail(str(exc), 600)}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
