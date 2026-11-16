#!/usr/bin/env python3
"""Verify protected risk-policy approval custody using live GitHub REST evidence.

Runs only in trusted default-branch workflows. GITHUB_TOKEN needs pull-requests:read.
This verifies recorded reviewer approval and merged custody, not branch ruleset
configuration; ruleset and CODEOWNERS enforcement require separate admin audit.
"""
import argparse
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


def verify(decision, pull, reviews, files, *, trusted_approvers, decision_path=None,
           contributor_custody=None):
    require(pull.get("merged_at") and pull.get("base", {}).get("ref") == "main",
            "approval PR must be merged into protected main")
    require(pull.get("state") == "closed", "approval PR must be closed and merged")
    maker = decision.get("prepared_by", "").casefold()
    checker = decision.get("approved_by", "").casefold()
    require(maker and checker and maker != checker, "maker-checker separation missing")
    require(pull.get("user", {}).get("login", "").casefold() == maker,
            "decision preparer differs from approval PR author")
    require(checker in {x.casefold() for x in trusted_approvers},
            "reviewer is not in independently configured trusted approvers")
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
        actor = (review.get("user") or {}).get("login", "").casefold()
        state = review.get("state")
        if not actor or state == "PENDING":
            continue
        require(state in ("APPROVED", "COMMENTED", "CHANGES_REQUESTED", "DISMISSED"),
                "unknown effective review state")
        require(bool(review.get("submitted_at")), "review timestamp missing")
        previous = latest.get(actor)
        if previous is None or (review["submitted_at"], review.get("id", 0)) > (
                previous["submitted_at"], previous.get("id", 0)):
            latest[actor] = review
    approved = latest.get(checker)
    require(approved is not None and approved.get("state") == "APPROVED"
            and approved.get("commit_id") == head,
            "no current independent approval on merged head")
    # Strict numeric identity check is mandatory for live custody. Unit tests
    # can inject a fully enumerated contributor snapshot.
    require(contributor_custody is not None,
            "complete numeric contributor custody required")
    author_id, contributor_ids, trusted_ids = contributor_custody
    reviewer_id = uid({"databaseId": (approved.get("user") or {}).get("id")})
    require_independent(reviewer_id, trusted_ids, author_id, contributor_ids)



def main():
    p = argparse.ArgumentParser()
    p.add_argument("--decision", type=Path, required=True)
    p.add_argument("--trusted-approvers", required=True,
                   help="comma-separated independently provisioned GitHub logins")
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
    verify(decision, pull, reviews, files,
           trusted_approvers=[x.strip() for x in args.trusted_approvers.split(",") if x.strip()],
           decision_path=decision_path,
           contributor_custody=(author_id, contributors, approver_ids))
    print(json.dumps({"status": "approval_custody_verified", "approval_pr": evidence,
                      "reviewer": decision["approved_by"], "merged_head": pull["head"]["sha"]}))


if __name__ == "__main__":
    main()
