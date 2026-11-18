#!/usr/bin/env python3
"""Read-only GII-05 exact-head decision review qualification.

Consumes separately captured GitHub evidence; does not authenticate, fetch,
provision, approve, merge, or infer identity from mutable login strings.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

EXPECTED_HEAD = "f9fd73d4e848a7c4d3bcfbe28651e06149cdcb6d"


class QualificationError(ValueError):
    pass


def _require(ok: bool, reason: str) -> None:
    if not ok:
        raise QualificationError(reason)


def _id(value: object) -> bool:
    return type(value) is int and value > 0


def _instant(value: object) -> datetime:
    _require(isinstance(value, str), "missing review timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise QualificationError("invalid review timestamp") from exc
    _require(parsed.tzinfo is not None, "review timestamp lacks timezone")
    return parsed.astimezone(timezone.utc)


def qualify(evidence: dict) -> dict:
    """Return only eligible final-head reviewers; refuse incomplete custody."""
    _require(isinstance(evidence, dict), "evidence must be an object")
    _require(evidence.get("pr") == 76 and evidence.get("head_sha") == EXPECTED_HEAD,
             "wrong decision PR or final head")
    author = evidence.get("author_id")
    contributors = evidence.get("contributor_ids")
    trusted = evidence.get("trusted_reviewer_ids")
    reviews = evidence.get("reviews")
    _require(_id(author), "missing immutable PR author ID")
    _require(isinstance(contributors, list) and len(contributors) > 0
             and all(_id(v) for v in contributors), "incomplete contributor IDs")
    _require(isinstance(trusted, list) and len(trusted) > 0
             and all(_id(v) for v in trusted), "missing trusted reviewer IDs")
    _require(evidence.get("history_complete") is True,
             "complete paginated contributor history is not attested")
    _require(isinstance(reviews, list) and reviews, "missing review history")
    excluded = set(contributors) | {author}
    latest = {}
    for review in reviews:
        _require(isinstance(review, dict), "malformed review")
        rid = review.get("reviewer_id")
        _require(_id(rid), "review has no immutable reviewer ID")
        _require(review.get("state") in ("APPROVED", "CHANGES_REQUESTED", "COMMENTED", "DISMISSED"),
                 "unknown review state")
        sha = review.get("commit_sha")
        _require(isinstance(sha, str) and len(sha) == 40
                 and all(c in "0123456789abcdef" for c in sha),
                 "review commit SHA is missing or malformed")
        stamp = _instant(review.get("submitted_at"))
        key = (stamp, review.get("review_id"))
        _require(type(key[1]) is int and key[1] > 0, "review numeric ID is missing")
        prior = latest.get(rid)
        if prior is None or key > prior[0]:
            latest[rid] = (key, review)
    eligible = sorted(
        rid for rid, (_, review) in latest.items()
        if rid in trusted and rid not in excluded
        and review["state"] == "APPROVED"
        and review["commit_sha"] == EXPECTED_HEAD
    )
    _require(eligible, "no independent current-head trusted approval established")
    return {"pr": 76, "head_sha": EXPECTED_HEAD, "eligible_reviewer_ids": eligible,
            "excluded_contributor_reviewer_ids": sorted(set(latest) & excluded)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = qualify(json.loads(args.evidence.read_text(encoding="utf-8")))
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
