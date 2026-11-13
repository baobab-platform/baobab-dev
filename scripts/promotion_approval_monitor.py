#!/usr/bin/env python3
"""Read-only pending protected-deployment monitor and deterministic escalation.

Produces notification decisions only. Never calls deployment approval APIs.
"""
import argparse
import json
from datetime import datetime, timezone

ENV = "dev10-release-promotion"


def decide(runs, now, reminder_minutes=15, escalate_minutes=45, expire_minutes=120):
    notices = []
    for run in runs:
        if not isinstance(run, dict) or run.get("status") != "waiting" or run.get("environment") != ENV:
            continue
        created = run.get("created_at")
        try:
            start = datetime.fromisoformat(created.replace("Z", "+00:00"))
            age = (now - start).total_seconds() / 60
        except (ValueError, TypeError, AttributeError):
            continue
        if age < 0:
            continue
        level = ("EXPIRED_REQUIRES_MANUAL_CANCELLATION" if age >= expire_minutes else
                 "ESCALATE" if age >= escalate_minutes else
                 "REMIND" if age >= reminder_minutes else "PENDING")
        notices.append({"run_id": run.get("id"), "url": run.get("html_url"),
                        "age_minutes": int(age), "level": level})
    return notices


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--runs", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--reminder", type=int, default=15)
    p.add_argument("--escalate", type=int, default=45)
    p.add_argument("--expire", type=int, default=120)
    a = p.parse_args()
    if not (0 < a.reminder < a.escalate < a.expire):
        p.error("require 0 < reminder < escalation < expiry")
    with open(a.runs) as f:
        runs = json.load(f)
    if not isinstance(runs, dict) or not isinstance(runs.get("workflow_runs"), list):
        p.error("missing workflow runs")
    result = decide(runs["workflow_runs"], datetime.now(timezone.utc),
                    a.reminder, a.escalate, a.expire)
    with open(a.output, "w") as f:
        json.dump(result, f, indent=2)


if __name__ == "__main__":
    main()
