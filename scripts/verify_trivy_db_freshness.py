#!/usr/bin/env python3
"""DEV-10 R5: fail-closed Trivy vulnerability/Java DB freshness evidence.

A restored CI cache is never proof that the DB is recent. The caller must first
run `trivy image --download-db-only` and, separately,
`trivy image --download-java-db-only`, each without skip-update switches.
Read the actual Trivy DB metadata, not the cache key or the filesystem mtime.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sys


class InvalidDatabase(ValueError):
    pass


def parse_timestamp(raw: object, name: str) -> datetime:
    if not isinstance(raw, str) or not raw.strip():
        raise InvalidDatabase(f"{name}: missing timestamp")
    try:
        t = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InvalidDatabase(f"{name}: invalid timestamp") from exc
    if t.tzinfo is None:
        raise InvalidDatabase(f"{name}: naive timestamp")
    return t.astimezone(timezone.utc)


def qualify(cache: Path, *, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise InvalidDatabase("wall clock must be timezone-aware")
    evidence = {"schema": "baobab.dev10.trivy-db-freshness.v1",
                "checked_at": now.isoformat(), "databases": {}}
    # Max bounds are deliberately stricter than Trivy's own hourly
    # post-download backoff. Java's source DB is normally less frequent.
    for directory, max_age_h in (("db", 36), ("java-db", 72)):
        meta_path = cache / directory / "metadata.json"
        if not meta_path.is_file():
            raise InvalidDatabase(f"{directory}: metadata missing")
        try:
            raw = meta_path.read_bytes()
            doc = json.loads(raw)
        except (OSError, UnicodeError, ValueError) as exc:
            raise InvalidDatabase(f"{directory}: malformed metadata") from exc
        if not isinstance(doc, dict):
            raise InvalidDatabase(f"{directory}: metadata not an object")
        version = doc.get("Version")
        if not isinstance(version, int) or isinstance(version, bool) or version <= 0:
            raise InvalidDatabase(f"{directory}: invalid schema version")
        updated = parse_timestamp(doc.get("UpdatedAt"), directory + ".UpdatedAt")
        next_update = parse_timestamp(doc.get("NextUpdate"), directory + ".NextUpdate")
        downloaded = parse_timestamp(doc.get("DownloadedAt"), directory + ".DownloadedAt")
        if updated > now + timedelta(minutes=10):
            raise InvalidDatabase(f"{directory}: update time is in the future")
        if downloaded > now + timedelta(minutes=10):
            raise InvalidDatabase(f"{directory}: download time is in the future")
        if updated < now - timedelta(hours=max_age_h):
            raise InvalidDatabase(f"{directory}: stale UpdatedAt ({updated.isoformat()})")
        if next_update <= now:
            raise InvalidDatabase(f"{directory}: NextUpdate expired ({next_update.isoformat()})")
        if next_update > now + timedelta(days=7):
            raise InvalidDatabase(f"{directory}: implausible NextUpdate")
        evidence["databases"][directory] = {
            "version": version, "updated_at": updated.isoformat(),
            "next_update": next_update.isoformat(),
            "downloaded_at": downloaded.isoformat(),
            "metadata_sha256": hashlib.sha256(raw).hexdigest(),
            "max_age_hours": max_age_h,
        }
    return evidence


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cache", type=Path, required=True)
    ap.add_argument("--evidence", type=Path, required=True)
    args = ap.parse_args()
    try:
        evidence = qualify(args.cache)
        args.evidence.parent.mkdir(parents=True, exist_ok=True)
        args.evidence.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
        for name, db in evidence["databases"].items():
            print(f"Fresh {name}: updated={db['updated_at']}, next={db['next_update']}, "
                  f"metadata sha256={db['metadata_sha256']}")
        return 0
    except InvalidDatabase as exc:
        print(f"::error::Trivy database freshness proof DENIED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
