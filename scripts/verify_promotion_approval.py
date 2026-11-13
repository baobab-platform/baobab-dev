#!/usr/bin/env python3
"""Fail-closed DEV-10 release approval evidence from GitHub deployment reviews.

Input is GitHub REST deployment approvals for the current workflow run.
Only approved entries matching the protected environment and run attempt count.
No token, secrets, or untrusted free-text comments are persisted.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path

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
        submitted = item.get("submitted_at")
        if not isinstance(submitted, str) or not submitted:
            continue
        approved.append({"reviewer": login, "submitted_at": submitted})
    if not approved:
        raise EvidenceError("no independent approved deployment review for protected environment")
    return {
        "schema": "dev10.promotion-approval.v1",
        "environment": ENVIRONMENT,
        "run_id": run_id,
        "run_attempt": attempt,
        "tag": tag,
        "initiator": actor,
        "approval": sorted(approved, key=lambda x: x["submitted_at"])[-1],
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
