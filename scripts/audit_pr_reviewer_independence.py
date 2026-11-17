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
import urllib.request

from custody_independence import collect_pr, require_independent, CustodyError

IndependenceError = CustodyError


def uid(node):
    value = (node or {}).get("databaseId")
    if type(value) is not int or value <= 0:
        raise CustodyError("unresolved numeric GitHub user identity")
    return value


def fetch(url, token):
    request = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def classify_reviewer(user, author_id, contributors):
    login = (user or {}).get("login")
    if not isinstance(login, str) or not login:
        raise IndependenceError("reviewer login is missing")
    reviewer_id = uid({"databaseId": (user or {}).get("id")})
    if (user or {}).get("type") != "User":
        return {"login": login, "status": "non-human-reviewer"}
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
    api = "https://api.github.com/repos/baobab-platform/baobab-dev"
    pull = fetch(f"{api}/pulls/{number}", token)
    head = (pull.get("head") or {}).get("sha")
    if not isinstance(head, str) or not re.fullmatch(r"[0-9a-f]{40}", head):
        raise IndependenceError("pull request head SHA is unavailable")
    reviews = fetch(f"{api}/pulls/{number}/reviews?per_page=100", token)
    if not isinstance(reviews, list) or len(reviews) >= 100:
        raise IndependenceError("complete review history required; pagination not exhausted")
    expected_head = os.environ.get("EXPECTED_HEAD_SHA")
    if expected_head and expected_head != head:
        raise IndependenceError("PR head differs from the triggering event SHA")
    base_sha = (pull.get("base") or {}).get("sha")
    expected_count = pull.get("commits")
    if not isinstance(base_sha, str) or type(expected_count) is not int or expected_count <= 0:
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
    author_id, contributors = collect_pr(token, number, head)
    api_author_id = uid({"databaseId": (pull.get("user") or {}).get("id")})
    if author_id != api_author_id:
        raise IndependenceError("REST and GraphQL PR author identities disagree")
    reviewers = {}
    for review in reviews:
        if not isinstance(review, dict):
            raise IndependenceError("malformed review record")
        review_id = review.get("id")
        if type(review_id) is not int or review_id <= 0:
            raise IndependenceError("numeric review identity is missing")
        user = review.get("user") or {}
        reviewer_id = uid({"databaseId": user.get("id")})
        result = classify_reviewer(user, author_id, contributors)
        result["id"] = reviewer_id
        reviewers[reviewer_id] = result
    return {
        "pull_request": number,
        "head_sha": head,
        "contributor_count": len(contributors),
        "reviewers": [
            {key: value for key, value in result.items() if key != "id"}
            for result in sorted(reviewers.values(), key=lambda item: item["id"])
        ],
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
    print(json.dumps(audit(token, args.pr_number), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
