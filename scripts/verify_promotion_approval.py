#!/usr/bin/env python3
"""Fail-closed DEV-10 release approval evidence from GitHub deployment reviews.

The deployment-approvals endpoint does not return submitted_at. Evidence
therefore records immutable numeric User IDs for the reviewer, original
workflow actor and rerun-triggering actor, without fabricating a timestamp.
No token, secrets, or untrusted free-text comments are persisted.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re

from custody_independence import (
    GITHUB_WEB_FLOW_ID, REPOSITORY, CustodyError, is_positive_id, rest_user_id,
)
from github_api_transport import GitHubAPIError, rest_request
from provision_protected_risk_policy import OWNER_USER_ID
from release_tag_policy import classify

ENVIRONMENT = "dev10-release-promotion"


class EvidenceError(ValueError):
    pass


def _positive_id(value, label):
    if not is_positive_id(value):
        raise EvidenceError(f"{label} must be a positive numeric GitHub user ID")
    return value


def _login(value, label):
    if not isinstance(value, str) or not re.fullmatch(
        r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?", value
    ):
        raise EvidenceError(f"{label} is not a valid GitHub login")
    return value


def attest(
    reviews: object, *, run_id: int, attempt: int, actor: str, actor_id: int,
    triggering_actor: str, triggering_actor_id: int, tag: str, eligible_ids: set[int] | None = None,
) -> dict:
    if not isinstance(reviews, list):
        raise EvidenceError("missing deployment review response")
    if type(run_id) is not int or run_id <= 0:
        raise EvidenceError("workflow run ID must be positive")
    if type(attempt) is not int or attempt <= 0:
        raise EvidenceError("workflow run attempt must be positive")
    actor_id = _positive_id(actor_id, "original workflow actor")
    triggering_actor_id = _positive_id(triggering_actor_id, "rerun-triggering actor")
    actor = _login(actor, "original workflow actor login")
    triggering_actor = _login(triggering_actor, "rerun-triggering actor login")
    if not isinstance(tag, str) or classify(tag) is None:
        raise EvidenceError("invalid release tag")

    approved = {}
    account_types = {}
    for item in reviews:
        if not isinstance(item, dict):
            raise EvidenceError("malformed deployment review record")
        state = item.get("state")
        if state not in ("approved", "rejected"):
            raise EvidenceError("deployment review has an unknown state")
        environments = item.get("environments")
        if not isinstance(environments, list) or any(
            not isinstance(environment, dict)
            or not isinstance(environment.get("name"), str)
            for environment in environments
        ):
            raise EvidenceError("deployment review has malformed environment evidence")
        if not any(environment.get("name") == ENVIRONMENT for environment in environments):
            continue
        # A rejected protected-environment deployment review cannot be
        # overridden by an earlier approval in this unordered API response.
        # The endpoint has no trustworthy attempt-bound timestamps to prove
        # that a later approval superseded a rejection.
        if state == "rejected":
            raise EvidenceError("protected deployment review includes a rejection")
        reviewer = item.get("user")
        if not isinstance(reviewer, dict):
            raise EvidenceError("approved deployment review has no reviewer identity")
        reviewer_type = reviewer.get("type")
        if reviewer_type not in ("User", "Bot"):
            raise EvidenceError("approved deployment reviewer is not a typed GitHub User")
        reviewer_id = _positive_id(reviewer.get("id"), "deployment reviewer")
        if account_types.setdefault(reviewer_id, reviewer_type) != reviewer_type:
            raise EvidenceError("conflicting account type for a numeric deployment reviewer")
        if reviewer_type == "Bot" or reviewer_id == GITHUB_WEB_FLOW_ID:
            # Automation and wait-timer records are not independent approvals.
            continue
        login = _login(reviewer.get("login"), "deployment reviewer login")
        if reviewer_id in (actor_id, triggering_actor_id) or (eligible_ids is not None and reviewer_id not in eligible_ids):
            continue
        approved.setdefault(reviewer_id, set()).add(login)

    if not approved:
        raise EvidenceError(
            "no independent eligible deployment review for protected environment"
        )
    # More than one independent reviewer may be present. Preserve every
    # eligible immutable ID instead of silently discarding all but the lowest.
    # This is evidence, not a declaration that a GitHub User is a human.
    reviewers = [
        {"reviewer_id": reviewer_id,
         "reviewer_logins": sorted(logins, key=str.casefold)}
        for reviewer_id, logins in sorted(approved.items())
    ]
    return {
        "schema": "dev10.promotion-approval.v2",
        "environment": ENVIRONMENT,
        "run_id": run_id,
        "run_attempt": attempt,
        "tag": tag,
        "initiator": {"id": actor_id, "login": actor},
        "triggering_actor": {"id": triggering_actor_id, "login": triggering_actor},
        "approval": reviewers[0],
        "eligible_approvals": reviewers,
    }


def collect_run_approval(token, *, run_id, attempt, head_sha, actor, actor_id, tag, eligible_ids):
    """Bind actor IDs to the exact Publish run attempt before reading approvals."""
    _positive_id(run_id, "workflow run ID")
    _positive_id(attempt, "workflow run attempt")
    if attempt != 1:
        raise EvidenceError("GitHub deployment review history has no attempt binding; protected rerun refused")
    if not eligible_ids or any(not is_positive_id(reviewer) for reviewer in eligible_ids):
        raise EvidenceError("no authorized independent release reviewer appointments")
    _positive_id(actor_id, "original workflow actor")
    if (not isinstance(head_sha, str) or not re.fullmatch(r"[a-f0-9]{40}", head_sha)
            or not isinstance(tag, str) or classify(tag) is None):
        raise EvidenceError("release source SHA or tag is invalid")
    endpoint = f"/repos/{REPOSITORY}/actions/runs/{run_id}"
    _, run = rest_request(token, "GET", f"{endpoint}/attempts/{attempt}")
    if not isinstance(run, dict):
        raise EvidenceError("missing workflow run attempt evidence")
    repository = run.get("repository")
    if (type(run.get("id")) is not int or run["id"] != run_id
            or type(run.get("run_attempt")) is not int or run["run_attempt"] != attempt
            or not isinstance(repository, dict) or repository.get("full_name") != REPOSITORY
            or run.get("path") != ".github/workflows/publish.yml" or run.get("event") != "push"
            or run.get("head_sha") != head_sha or run.get("head_branch") != tag):
        raise EvidenceError("workflow run attempt does not match the protected release source")
    triggering_actor = run.get("triggering_actor")
    original_id = rest_user_id(run.get("actor"), "original workflow actor")
    triggering_id = rest_user_id(triggering_actor, "rerun-triggering actor")
    if (original_id != actor_id or triggering_id != original_id
            or GITHUB_WEB_FLOW_ID in (original_id, triggering_id)):
        raise EvidenceError("workflow actor IDs conflict with the release run context")
    _, reviews = rest_request(token, "GET", f"{endpoint}/approvals")
    return attest(
        reviews, run_id=run_id, attempt=attempt, actor=actor, actor_id=original_id,
        triggering_actor=triggering_actor.get("login"), triggering_actor_id=triggering_id, tag=tag,
        eligible_ids=eligible_ids,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--attempt", type=int, required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--actor", required=True)
    parser.add_argument("--actor-id", type=int, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--environment-evidence", type=Path, required=True)
    parser.add_argument("--contributors", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    token = os.environ.get("GITHUB_TOKEN")
    if not token or os.environ.get("GITHUB_REPOSITORY") != REPOSITORY:
        parser.error("promotion approval requires GitHub authentication for the canonical repository")
    try:
        environment = json.loads(args.environment_evidence.read_text())
        contributors = json.loads(args.contributors)
        if (not isinstance(environment, dict) or environment.get("environment") != ENVIRONMENT
                or environment.get("release_tag") != args.tag):
            raise EvidenceError("release environment receipt differs from the exact release")
        appointed = environment.get("reviewer_ids")
        for identities in (contributors, appointed):
            if (not isinstance(identities, list) or not identities or any(not is_positive_id(i) for i in identities)
                    or len(set(identities)) != len(identities)):
                raise EvidenceError("missing or malformed exact release contributor/reviewer identities")
        result = collect_run_approval(
            token, run_id=args.run_id, attempt=args.attempt, head_sha=args.head_sha,
            actor=args.actor, actor_id=args.actor_id, tag=args.tag,
            eligible_ids=set(appointed) - (set(contributors) | {OWNER_USER_ID}),
        )
    except (CustodyError, GitHubAPIError, ValueError, OSError) as exc:
        parser.error(str(exc))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
