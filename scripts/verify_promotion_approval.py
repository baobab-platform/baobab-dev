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
from pathlib import Path
import re

ENVIRONMENT = "dev10-release-promotion"


class EvidenceError(ValueError):
    pass


def _positive_id(value, label):
    if type(value) is not int or value <= 0:
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
    triggering_actor: str, triggering_actor_id: int, tag: str,
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
    if not isinstance(tag, str) or not tag.strip():
        raise EvidenceError("release tag is missing")

    approved = {}
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
        if reviewer_type == "Bot":
            continue
        if reviewer_type != "User":
            raise EvidenceError("approved deployment reviewer is not a typed GitHub User")
        reviewer_id = _positive_id(reviewer.get("id"), "deployment reviewer")
        login = _login(reviewer.get("login"), "deployment reviewer login")
        if reviewer_id in (actor_id, triggering_actor_id):
            continue
        approved.setdefault(reviewer_id, set()).add(login)

    if not approved:
        raise EvidenceError(
            "no independent human-approved deployment review for protected environment"
        )
    reviewer_id = sorted(approved)[0]
    return {
        "schema": "dev10.promotion-approval.v2",
        "environment": ENVIRONMENT,
        "run_id": run_id,
        "run_attempt": attempt,
        "tag": tag,
        "initiator": {"id": actor_id, "login": actor},
        "triggering_actor": {"id": triggering_actor_id, "login": triggering_actor},
        "approval": {
            "reviewer_id": reviewer_id,
            "reviewer_logins": sorted(approved[reviewer_id], key=str.casefold),
        },
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--reviews", type=Path, required=True)
    p.add_argument("--run-id", type=int, required=True)
    p.add_argument("--attempt", type=int, required=True)
    p.add_argument("--actor", required=True)
    p.add_argument("--actor-id", type=int, required=True)
    p.add_argument("--triggering-actor", required=True)
    p.add_argument("--triggering-actor-id", type=int, required=True)
    p.add_argument("--tag", required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    try:
        result = attest(
            json.loads(a.reviews.read_text()), run_id=a.run_id, attempt=a.attempt,
            actor=a.actor, actor_id=a.actor_id,
            triggering_actor=a.triggering_actor,
            triggering_actor_id=a.triggering_actor_id, tag=a.tag,
        )
    except (ValueError, OSError) as exc:
        p.error(str(exc))
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
