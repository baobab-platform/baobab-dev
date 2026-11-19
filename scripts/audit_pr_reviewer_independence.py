#!/usr/bin/env python3
"""Read-only audit of current PR reviewers against complete GitHub commit custody.

This reports contributor independence only. It does not establish trust, approval,
branch protection, or authorization to merge or release.
"""
import argparse
import json
import os
import re
import subprocess
from pathlib import Path

from custody_independence import (
    GITHUB_WEB_FLOW_ID, REPOSITORY, CustodyError, collect_pr, is_positive_id,
    _fetch_commit_records, _numeric_user_id, _rest_commit_committer_user_id, _same_timestamp,
    require_independent, rest_user_id,
)
from github_api_transport import trace_requests
from provision_protected_risk_policy import (
    ProvisioningError, api_request, paginated,
    select_independent_approval, verify_owner_concurrence,
)

IndependenceError = CustodyError
HISTORICAL_HEAD = "f9fd73d4e848a7c4d3bcfbe28651e06149cdcb6d"
HISTORICAL_SERVICE_COMMIT = "dad5dc64031d05b7e7d93345f1ea553abea6c70e"


def classify_reviewer(user, author_id, contributors):
    if not isinstance(user, dict):
        raise IndependenceError("reviewer identity is missing")
    login = user.get("login")
    if not isinstance(login, str) or not re.fullmatch(r"[A-Za-z0-9-]{1,39}(?:\[bot\])?", login):
        raise IndependenceError("reviewer login is missing or invalid")
    reviewer_id = user.get("id")
    if not is_positive_id(reviewer_id):
        raise IndependenceError("unresolved numeric GitHub reviewer identity")
    if user.get("type") in ("Bot", "App"):
        return {"login": login, "status": "non-human-reviewer"}
    rest_user_id(user, "reviewer")
    if reviewer_id == GITHUB_WEB_FLOW_ID:
        return {"login": login, "status": "service-user"}
    try:
        require_independent(reviewer_id, {reviewer_id}, author_id, contributors)
    except IndependenceError:
        if reviewer_id == author_id:
            reason = "pull-request author"
        elif reviewer_id in contributors:
            reason = "commit author, co-author, or committer"
        else:
            reason = "not independent"
        return {"login": login, "status": "not-independent", "reason": reason}
    return {"login": login, "status": "independent"}


def audit(token, number):
    endpoint = f"/repos/{REPOSITORY}/pulls/{number}"
    _, pull = api_request(token, "GET", endpoint)
    if not isinstance(pull, dict):
        raise IndependenceError("PR metadata is unavailable")
    head = (pull.get("head") or {}).get("sha")
    if not isinstance(head, str) or not re.fullmatch(r"[0-9a-f]{40}", head):
        raise IndependenceError("pull request head SHA is unavailable")
    reviews = paginated(token, endpoint + "/reviews")
    expected_head = os.environ.get("EXPECTED_HEAD_SHA")
    if expected_head and expected_head != head:
        raise IndependenceError("PR head differs from the triggering event SHA")
    base_sha = (pull.get("base") or {}).get("sha")
    expected_count = pull.get("commits")
    if (not isinstance(base_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", base_sha)
            or not is_positive_id(expected_count)):
        raise IndependenceError("PR base SHA or commit count is unavailable")
    subprocess.run([
        "git", "fetch", "--no-tags", "origin",
        f"refs/pull/{number}/head:refs/remotes/origin/pr-{number}",
    ], check=True, capture_output=True, text=True)
    subprocess.run(["git", "fetch", "--no-tags", "origin", base_sha],
                   check=True, capture_output=True, text=True)
    fetched_head = subprocess.run(
        ["git", "rev-parse", f"refs/remotes/origin/pr-{number}"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    if fetched_head != head:
        raise IndependenceError("fetched PR ref differs from GitHub head SHA")
    revision_list = subprocess.run(
        ["git", "rev-list", "--reverse", "--topo-order", f"{base_sha}..{head}"],
        check=True, capture_output=True, text=True,
    ).stdout.splitlines()
    if len(revision_list) != expected_count or not revision_list or head not in revision_list:
        raise IndependenceError("local full-history commit range differs from GitHub PR metadata")
    author_id, contributors = collect_pr(token, number, head, revision_list)
    api_author_id = rest_user_id(pull.get("user"), "PR author")
    if author_id != api_author_id:
        raise IndependenceError("REST and GraphQL PR author identities disagree")
    reviewers = {}
    seen_review_ids = set()
    for review in reviews:
        if not isinstance(review, dict):
            raise IndependenceError("malformed review record")
        review_id = review.get("id")
        if not is_positive_id(review_id) or review_id in seen_review_ids:
            raise IndependenceError("numeric review identity is missing or duplicated")
        seen_review_ids.add(review_id)
        user = review.get("user")
        result = classify_reviewer(user, author_id, contributors)
        previous = reviewers.get(user["id"])
        if previous and previous["status"] != result["status"]:
            raise IndependenceError("conflicting account type for a numeric reviewer")
        reviewers[user["id"]] = result
    return {
        "pull_request": number,
        "head_sha": head,
        "commit_count": len(revision_list),
        "contributor_count": len(contributors),
        "review_count": len(reviews),
        "reviewers": [reviewers[reviewer_id] for reviewer_id in sorted(reviewers)],
        "note": "Independence results are not approval or trust decisions.",
    }


def historical_custody(token):
    """Corroborate the recorded #76 witness using authenticated read-only APIs."""
    repo = f"/repos/{REPOSITORY}"
    _, pull = api_request(token, "GET", repo + "/pulls/76")
    if (not isinstance(pull, dict) or pull.get("merged") is not True
            or (pull.get("head") or {}).get("sha") != HISTORICAL_HEAD
            or pull.get("merged_at") != "2026-11-17T03:36:58Z"
            or pull.get("commits") != 94):
        raise IndependenceError("historical PR #76 metadata differs from the recorded witness")
    author, contributors = collect_pr(token, 76, HISTORICAL_HEAD)
    if (rest_user_id(pull.get("user"), "historical PR author") != author
            or author != 350241706 or contributors != {350241706, 356890520, GITHUB_WEB_FLOW_ID}):
        raise IndependenceError("historical PR #76 contributor identities differ from the recorded witness")
    record, = _fetch_commit_records(token, [HISTORICAL_SERVICE_COMMIT])
    actor = record.get("committer")
    expected_committer = {"name": "GitHub", "email": "noreply@github.com", "date": "2026-11-17T01:29:58Z"}
    if (not isinstance(actor, dict) or "user" not in actor
            or actor.get("name") != expected_committer["name"]
            or actor.get("email") != expected_committer["email"]
            or not _same_timestamp(actor.get("date"), expected_committer["date"])):
        raise IndependenceError("historical service commit metadata differs from the recorded witness")
    service_id = _rest_commit_committer_user_id(token, HISTORICAL_SERVICE_COMMIT, expected_committer)
    if (service_id != GITHUB_WEB_FLOW_ID
            or _numeric_user_id(record.get("author"), "historical merge author") != 356890520
            or (actor["user"] is not None and _numeric_user_id(actor, "historical committer") != service_id)):
        raise IndependenceError("historical merge author or service committer differs from the recorded witness")
    reviews = paginated(token, repo + "/pulls/76/reviews")
    approval = select_independent_approval(
        reviews, head=HISTORICAL_HEAD, trusted_reviewers={356890520, 356900102},
        author_id=author, contributors=contributors, merged_at=pull["merged_at"],
    )
    if approval["approval_id"] != "github-review-5932308847" or approval["approved_by_id"] != 356900102:
        raise IndependenceError("historical PR #76 approval differs from the recorded witness")
    owner = verify_owner_concurrence(paginated(token, repo + "/issues/76/comments"), merged_at=pull["merged_at"])
    if owner["owner_comment_id"] != 6924572973:
        raise IndependenceError("historical PR #76 owner concurrence differs from the recorded witness")
    return {
        "pull_request": 76, "head_sha": HISTORICAL_HEAD, "commit_count": 94,
        "contributor_ids": sorted(contributors), "review_count": len(reviews),
        "service_commit_sha": HISTORICAL_SERVICE_COMMIT, "service_committer_id": service_id,
        "approved_head": HISTORICAL_HEAD, "approval_id": approval["approval_id"],
        "approved_by_id": approval["approved_by_id"], "approved_at": approval["approved_at"],
        **owner,
    }


def main():
    parser = argparse.ArgumentParser()
    scope = parser.add_mutually_exclusive_group(required=True)
    scope.add_argument("--pr-number", type=int)
    scope.add_argument("--historical", action="store_true")
    parser.add_argument("--output", type=Path, help="retain a read-only, sanitized Actions receipt")
    args = parser.parse_args()
    if args.pr_number is not None and args.pr_number < 1:
        parser.error("PR number must be positive")
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        parser.error("GITHUB_TOKEN is required for live GitHub custody")
    try:
        with trace_requests() as requests:
            if args.historical:
                result = historical_custody(token)
            else:
                result = audit(token, args.pr_number)
        if args.output:
            run_id = os.environ.get("GITHUB_RUN_ID", "")
            attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
            if not all(re.fullmatch(r"[1-9][0-9]{0,19}", value) for value in (run_id, attempt)):
                raise IndependenceError("Actions run and attempt are required for a custody receipt")
            result.update(
                schema="dev10.github-custody-observation.v1",
                run_id=int(run_id), run_attempt=int(attempt), api_requests=requests,
            )
    except (ProvisioningError, IndependenceError) as exc:
        parser.error(str(exc))
    except (OSError, subprocess.CalledProcessError):
        parser.error("could not read the complete local PR Git history")
    serialized = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(serialized + "\n", encoding="utf-8")
    print(serialized)


if __name__ == "__main__":
    main()
