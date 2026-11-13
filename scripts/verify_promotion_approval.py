#!/usr/bin/env python3
"""Fail-closed DEV-10 release approval evidence from GitHub deployment reviews.

Input is GitHub REST deployment approvals for the current workflow run.
Only independently approved human entries for the protected environment count.
GitHub's deployment approvals endpoint does not return submitted_at; record the
reviewer identity and run identity, never fabricate an approval timestamp.
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


def attest(reviews: object, *, run_id: int, attempt: int, actor: str, tag: str) -> dict:
    if not isinstance(reviews, list):
        raise EvidenceError("missing deployment review response")
    approved = []
    for item in reviews:
        if not isinstance(item, dict) or item.get("state") != "approved":
            continue
        environments = item.get("environments")
        if not isinstance(environments, list) or not any(
            isinstance(e, dict) and e.get("name") == ENVIRONMENT for e in environments
        ):
            continue
        reviewer = item.get("user")
        login = reviewer.get("login") if isinstance(reviewer, dict) else None
        if not isinstance(login, str) or not login or login.casefold() == actor.casefold():
            continue
        # GitHub REST GET /actions/runs/{run_id}/approvals does not include
        # submitted_at. Never require or synthesize an unsupported timestamp.
        # An automation/wait-timer entry is not a human approval.
        if reviewer.get("type") == "Bot" or login.casefold().endswith("[bot]"):
            continue
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?", login):
            continue
        approved.append({"reviewer": login})
    if not approved:
        raise EvidenceError("no independent human-approved deployment review for protected environment")
    return {
        "schema": "dev10.promotion-approval.v1",
        "environment": ENVIRONMENT,
        "run_id": run_id,
        "run_attempt": attempt,
        "tag": tag,
        "initiator": actor,
        "approval": sorted(approved, key=lambda x: x["reviewer"].casefold())[0],
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--reviews", type=Path, required=True)
    p.add_argument("--run-id", type=int, required=True)
    p.add_argument("--attempt", type=int, required=True)
    p.add_argument("--actor", required=True)
    p.add_argument("--tag", required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    try:
        result = attest(json.loads(a.reviews.read_text()), run_id=a.run_id,
                        attempt=a.attempt, actor=a.actor, tag=a.tag)
    except (ValueError, OSError) as exc:
        p.error(str(exc))
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
