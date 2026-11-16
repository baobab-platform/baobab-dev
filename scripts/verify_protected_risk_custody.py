#!/usr/bin/env python3
"""Verify protected risk-policy approval custody using live GitHub REST evidence.

Runs only in trusted default-branch workflows. GITHUB_TOKEN needs pull-requests:read.
This verifies recorded reviewer approval and merged custody, not branch ruleset
configuration; ruleset and CODEOWNERS enforcement require separate admin audit.
"""
import argparse
import datetime as dt
import json
import os
import re
import urllib.request
from pathlib import Path
from custody_independence import collect_pr, require_independent, uid


def require(ok, message):
    if not ok:
        raise ValueError(message)


def fetch(url, token):
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    with urllib.request.urlopen(req, timeout=20) as response:
        return json.load(response)


def verify(decision, pull, reviews, files, *, trusted_approver_ids, decision_path=None,
           contributor_custody=None):
    require(pull.get("merged_at") and pull.get("base", {}).get("ref") == "main",
            "approval PR must be merged into protected main")
    require(pull.get("state") == "closed", "approval PR must be closed and merged")
    maker_id = decision.get("prepared_by_id")
    require(type(maker_id) is int and maker_id > 0,
            "numeric decision preparer identity missing")
    author_id = uid({"databaseId": (pull.get("user") or {}).get("id")})
    require(author_id == maker_id,
            "decision preparer numeric identity differs from approval PR author")
    require(isinstance(trusted_approver_ids, (set, frozenset)) and trusted_approver_ids,
            "independently configured trusted reviewer identities are unavailable")
    require(decision.get("approval_evidence") ==
            pull.get("html_url"), "decision approval PR mismatch")
    require(any(f.get("filename") == decision_path
                and f.get("status") in ("added", "modified")
                for f in files) if decision_path else any(
                    f.get("filename", "").startswith("security/decisions/")
                    and f.get("status") in ("added", "modified") for f in files),
            "approval PR did not change the selected protected decision record")
    head = pull.get("head", {}).get("sha")
    require(isinstance(head, str) and re.fullmatch(r"[a-f0-9]{40}", head),
            "merged approval PR head is unavailable")
    require(isinstance(reviews, list) and len(reviews) < 100,
            "complete approval review history required")
    latest = {}
    for review in reviews:
        require(isinstance(review, dict), "malformed review evidence")
        actor_id = uid({"databaseId": (review.get("user") or {}).get("id")})
        state = review.get("state")
        if state == "PENDING":
            continue
        require(state in ("APPROVED", "COMMENTED", "CHANGES_REQUESTED", "DISMISSED"),
                "unknown effective review state")
        require(bool(review.get("submitted_at")), "review timestamp missing")
        previous = latest.get(actor_id)
        if previous is None or (review["submitted_at"], review.get("id", 0)) > (
                previous["submitted_at"], previous.get("id", 0)):
            latest[actor_id] = review
    qualifying = []
    for candidate_id, candidate in latest.items():
        if candidate.get("state") != "APPROVED" or candidate.get("commit_id") != head:
            continue
        try:
            require_independent(candidate_id, trusted_approver_ids, author_id, contributor_ids)
        except ValueError:
            continue
        submitted_at = candidate.get("submitted_at")
        try:
            candidate_time = dt.datetime.fromisoformat(submitted_at.replace("Z", "+00:00"))
        except (AttributeError, ValueError) as exc:
            raise ValueError("GitHub approval timestamp is invalid") from exc
        require(candidate_time.tzinfo is not None,
                "GitHub approval timestamp must include a timezone")
        qualifying.append((candidate_time, candidate.get("id", 0), candidate_id, candidate))
    require(bool(qualifying),
            "no trusted, independent approval at the merged decision PR head")
    _, _, reviewer_id, approved = max(qualifying, key=lambda item: (item[0], item[1]))
    # Strict numeric identity check is mandatory for live custody. Unit tests
    # can inject a fully enumerated contributor snapshot.
    require(contributor_custody is not None,
            "complete numeric contributor custody required")
    enumerated_author_id, contributor_ids = contributor_custody
    require(enumerated_author_id == author_id,
            "REST and GraphQL decision PR author identities disagree")
    reviewer_id = uid({"databaseId": (approved.get("user") or {}).get("id")})
    require_independent(reviewer_id, trusted_approver_ids, author_id, contributor_ids)
    review_id = approved.get("id")
    require(type(review_id) is int and review_id > 0, "numeric GitHub approval review ID missing")
    submitted_at = approved.get("submitted_at")
    require(isinstance(submitted_at, str), "GitHub approval timestamp missing")
    try:
        approval_time = dt.datetime.fromisoformat(submitted_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("GitHub approval timestamp is invalid") from exc
    require(approval_time.tzinfo is not None, "GitHub approval timestamp must include a timezone")
    return {
        "approval_id": f"github-review-{review_id}",
        "approved_at": approval_time.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "approved_by_id": reviewer_id,
        "approval_pr": decision.get("approval_evidence"),
        "approval_pr_head": head,
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--decision", type=Path, required=True)
    p.add_argument("--trusted-approvers", required=True,
                   help="comma-separated independently provisioned GitHub logins")
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    token = os.environ["GITHUB_TOKEN"]
    decision = json.loads(args.decision.read_text())
    decision_path = args.decision.as_posix()
    require(decision_path.startswith("security/decisions/") and ".." not in args.decision.parts,
            "decision must be a protected repository-relative path")
    evidence = decision.get("approval_evidence", "")
    match = re.fullmatch(r"https://github\.com/baobab-platform/baobab-dev/pull/([1-9][0-9]*)", evidence)
    require(match is not None, "invalid approval evidence URL")
    base = "https://api.github.com/repos/baobab-platform/baobab-dev/pulls/" + match.group(1)
    pull = fetch(base, token)
    reviews = fetch(base + "/reviews?per_page=100", token)
    files = fetch(base + "/files?per_page=100", token)
    require(len(reviews) < 100 and len(files) < 100,
            "pagination required: refuse incomplete approval evidence")
    author_id, contributors = collect_pr(token, int(match.group(1)), pull["head"]["sha"])
    approver_ids = set()
    for login in [x.strip() for x in args.trusted_approvers.split(",") if x.strip()]:
        identity = fetch("https://api.github.com/users/" + login, token)
        require(identity.get("login", "").casefold() == login.casefold(),
                "trusted reviewer login resolution mismatch")
        approver_ids.add(uid({"databaseId": identity.get("id")}))
    result = verify(decision, pull, reviews, files,
                    decision_path=decision_path,
                    contributor_custody=(author_id, contributors),
                    trusted_approver_ids=approver_ids)
    result["status"] = "approval_custody_verified"
    result["reviewer"] = result.get("reviewer")
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
