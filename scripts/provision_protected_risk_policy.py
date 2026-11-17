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
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from custody_independence import collect_pr, require_independent, uid

REPOSITORY = "baobab-platform/baobab-dev"
DECISION_PATH = "security/decisions/development/foundation.json"
VARIABLE_NAME = "DEV10_PROTECTED_DECISION_SHA256"
OWNER_USER_ID = 49340314  # @bjnabs; accountable owner recorded in ADR-DEV10-001
API_ROOT = "https://api.github.com"
API_VERSION = "2022-11-28"
EXPECTED_EXPIRY = "2026-11-26T00:00:00Z"
EXPECTED_CVES = {
    "CVE-2022-50240", "CVE-2025-40190", "CVE-2026-68103",
    "CVE-2026-72198", "CVE-2026-74578", "CVE-2026-89805",
    "CVE-2026-98376", "CVE-2026-98420",
}
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
    require(set(decision) == EXPECTED_FIELDS, "decision fields differ from the approved schema")
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
    require(type(decision["finding_count"]) is int and decision["finding_count"] == 8,
            "finding count differs from approved inventory")
    require(isinstance(decision["notes"], str) and decision["notes"].strip(),
            "decision rationale is missing")

    findings = decision["findings"]
    require(isinstance(findings, list) and len(findings) == 8,
            "exact eight-finding inventory is required")
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
    require({item[0] for item in observed} == EXPECTED_CVES,
            "approved CVE set differs from the eight reviewed findings")
    require(all(item[1:] == ("linux-libc-dev", "7.0.0-43.43", "HIGH", "ubuntu")
                for item in observed),
            "approved package, version, severity or ecosystem differs")
    return decision


def api_request(token, method, path, payload=None, allowed_status=()):
    url = path if path.startswith("https://") else API_ROOT + path
    data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    request = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
        "X-GitHub-Api-Version": API_VERSION,
        "User-Agent": "baobab-dev-dev10-policy-provisioner",
    })
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read()
            status = response.status
    except urllib.error.HTTPError as exc:
        if exc.code in allowed_status:
            return exc.code, None
        # Never include response bodies, which may contain sensitive metadata.
        raise ProvisioningError(f"GitHub API {method} returned HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise ProvisioningError(f"GitHub API {method} request failed") from exc
    if status not in (200, 201, 204) and status not in allowed_status:
        raise ProvisioningError(f"GitHub API {method} returned HTTP {status}")
    if not raw:
        return status, None
    try:
        return status, json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ProvisioningError("GitHub API returned invalid JSON") from exc


def paginated(token, path):
    results = []
    for page in range(1, 101):
        separator = "&" if "?" in path else "?"
        _, payload = api_request(token, "GET", f"{path}{separator}per_page=100&page={page}")
        require(isinstance(payload, list), "GitHub pagination returned a non-list response")
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
        return base64.b64decode(payload["content"], validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ProvisioningError(f"{path} has invalid GitHub content encoding") from exc


def resolve_trusted_reviewers(token, logins):
    require(bool(logins), "DEV10_SECURITY_APPROVER_LOGINS is empty")
    identities = {}
    for login in logins:
        require(re.fullmatch(r"[A-Za-z0-9-]{1,39}", login) is not None,
                "trusted reviewer login has invalid syntax")
        _, user = api_request(token, "GET", f"/users/{urllib.parse.quote(login, safe='')}")
        require(isinstance(user, dict)
                and isinstance(user.get("login"), str)
                and user["login"].casefold() == login.casefold(),
                "trusted reviewer login resolution mismatch")
        user_id = user.get("id")
        require(type(user_id) is int and user_id > 0, "trusted reviewer has no numeric GitHub ID")
        identities[user_id] = user["login"]
    require(bool(identities), "no trusted numeric reviewer identities resolved")
    return identities


def verify_owner_concurrence(comments, *, merged_at):
    """Require attributable owner concurrence posted and last edited before merge."""
    require(isinstance(comments, list), "decision PR issue-comment history is unavailable")
    merge_time = parse_utc(merged_at, "decision PR merge timestamp")
    qualifying = []
    for comment in comments:
        if not isinstance(comment, dict):
            continue
        user = comment.get("user") or {}
        body = comment.get("body")
        if (user.get("id") != OWNER_USER_ID or not isinstance(body, str)
                or "owner concurrence is hereby recorded" not in body.casefold()
                or "new reusable policy" not in body.casefold()):
            continue
        comment_id = comment.get("id")
        require(type(comment_id) is int and comment_id > 0,
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
        "owner_id": OWNER_USER_ID,
        "owner_comment_id": comment_id,
        "owner_concurrence_at": created.isoformat().replace("+00:00", "Z"),
    }


def select_independent_approval(reviews, *, head, trusted_reviewers, author_id, contributors):
    """Select a trusted reviewer whose latest effective approval is on this exact head."""
    require(isinstance(reviews, list), "review history must be a complete list")
    latest = {}
    for review in reviews:
        require(isinstance(review, dict), "malformed pull-request review")
        if review.get("state") == "PENDING":
            continue
        reviewer = review.get("user") or {}
        reviewer_id = reviewer.get("id")
        require(type(reviewer_id) is int and reviewer_id > 0,
                "review contains an unresolved numeric reviewer identity")
        state = review.get("state")
        require(state in ("APPROVED", "COMMENTED", "CHANGES_REQUESTED", "DISMISSED"),
                "review contains an unknown effective state")
        review_id = review.get("id")
        require(type(review_id) is int and review_id > 0, "review ID is missing")
        submitted = parse_utc(review.get("submitted_at"), "review submitted_at")
        candidate = (submitted, review_id, state, review)
        if reviewer_id not in latest or candidate[:2] > latest[reviewer_id][:2]:
            latest[reviewer_id] = candidate

    qualifying = []
    for reviewer_id, (submitted, review_id, state, review) in latest.items():
        if state != "APPROVED" or review.get("commit_id") != head:
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


def verify_merged_custody(token, decision, decision_pr, expected_head_sha, trusted_reviewers):
    base = f"/repos/{REPOSITORY}/pulls/{decision_pr}"
    _, pull = api_request(token, "GET", base)
    require(isinstance(pull, dict), "decision pull request metadata is unavailable")
    require(pull.get("state") == "closed" and pull.get("merged") is True
            and isinstance(pull.get("merged_at"), str),
            "decision PR must be merged and closed")
    require((pull.get("base") or {}).get("ref") == "main"
            and ((pull.get("base") or {}).get("repo") or {}).get("full_name") == REPOSITORY,
            "decision PR must target this repository's main branch")
    head = (pull.get("head") or {}).get("sha")
    require(head == expected_head_sha and re.fullmatch(r"[a-f0-9]{40}", head or "") is not None,
            "decision PR head differs from the explicitly approved expected head")
    require(((pull.get("head") or {}).get("repo") or {}).get("full_name") == REPOSITORY,
            "decision PR must originate from this repository")
    merge_sha = pull.get("merge_commit_sha")
    require(isinstance(merge_sha, str) and re.fullmatch(r"[a-f0-9]{40}", merge_sha),
            "decision PR merge commit is unavailable")

    author = pull.get("user") or {}
    author_id = author.get("id")
    require(type(author_id) is int and author_id == decision["prepared_by_id"],
            "decision PR author numeric identity differs from the recorded preparer")
    # The immutable numeric user ID is authoritative. prepared_by is
    # display metadata and may legitimately change if the account is renamed.

    files = paginated(token, base + "/files")
    require(any(item.get("filename") == DECISION_PATH
                and item.get("status") in ("added", "modified")
                for item in files),
            "decision PR did not add or modify the protected decision file")

    # The approved PR bytes must still be the exact bytes present on main.
    approved_bytes = contents_bytes(token, DECISION_PATH, head)
    main_bytes = contents_bytes(token, DECISION_PATH, "main")
    require(approved_bytes == main_bytes,
            "merged main decision bytes differ from the independently approved PR head")
    require(hashlib.sha256(approved_bytes).hexdigest() == hashlib.sha256(main_bytes).hexdigest(),
            "decision byte continuity check failed")
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
    require(isinstance(comparison, dict)
            and comparison.get("status") in ("ahead", "identical")
            and ((comparison.get("merge_base_commit") or {}).get("sha") == merge_sha),
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
        author_id=author_id, contributors=contributors,
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
            "reviewer": custody["reviewer"],
            "approved_at": custody["approved_at"],
            "expires_at": decision["expires_at"],
            "contributor_count": custody["contributor_count"],
        }
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ProvisioningError, OSError, ValueError, TypeError, KeyError,
            json.JSONDecodeError) as exc:
        print(f"DEV-10 POLICY PROVISIONING DENIED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
