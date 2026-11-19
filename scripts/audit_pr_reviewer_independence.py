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

from custody_independence import (
    GITHUB_WEB_FLOW_ID, REPOSITORY, CustodyError, collect_pr, is_positive_id,
    require_independent, rest_user_id,
)
from provision_protected_risk_policy import ProvisioningError, api_request, paginated

IndependenceError = CustodyError


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
        "contributor_count": len(contributors),
        "reviewers": [reviewers[reviewer_id] for reviewer_id in sorted(reviewers)],
        "note": "Independence results are not approval or trust decisions.",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pr-number", type=int, required=True)
    args = parser.parse_args()
    if args.pr_number < 1:
        parser.error("PR number must be positive")
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        parser.error("GITHUB_TOKEN is required for live GitHub custody")
    try:
        result = audit(token, args.pr_number)
    except (ProvisioningError, IndependenceError) as exc:
        parser.error(str(exc))
    except (OSError, subprocess.CalledProcessError):
        parser.error("could not read the complete local PR Git history")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
