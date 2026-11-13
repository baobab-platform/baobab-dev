#!/usr/bin/env python3
"""DEV-10 GA gate: compare all four immutable candidate digests with qualified RC.

No 'same source SHA' shortcut: image equality is established only by OCI digest.
The RC qualification record is an independently supplied, immutable JSON
manifest and must be traceable to an earlier successful release run.
"""
from __future__ import annotations
import argparse
import json
import re
from pathlib import Path

TARGETS = ("final", "frontend", "frontend-e2e", "infra")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


class ContinuityError(ValueError):
    pass


def qualify(rc: dict, ga: dict) -> dict:
    if not isinstance(rc, dict) or not isinstance(ga, dict):
        raise ContinuityError("missing RC/GA manifest")
    rc_tag, ga_tag = rc.get("release_tag"), ga.get("release_tag")
    if not isinstance(ga_tag, str) or not re.fullmatch(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", ga_tag):
        raise ContinuityError("GA tag is not strict SemVer")
    if not isinstance(rc_tag, str) or not re.fullmatch(re.escape(ga_tag) + r"-rc\.[1-9][0-9]*", rc_tag):
        raise ContinuityError("RC and GA version families differ")
    if rc.get("source_sha") != ga.get("source_sha") or not re.fullmatch(r"[0-9a-f]{40}", str(rc.get("source_sha", ""))):
        raise ContinuityError("RC and GA source revision mismatch")
    if rc.get("qualified") is not True or not isinstance(rc.get("qualification_ref"), str) or not rc["qualification_ref"]:
        raise ContinuityError("RC qualification evidence missing")
    if not isinstance(rc.get("run_id"), int) or rc["run_id"] <= 0:
        raise ContinuityError("RC workflow run identity missing")
    rc_images, ga_images = rc.get("images"), ga.get("images")
    if not isinstance(rc_images, dict) or not isinstance(ga_images, dict) or set(rc_images) != set(TARGETS) or set(ga_images) != set(TARGETS):
        raise ContinuityError("all four profiles required")
    for target in TARGETS:
        a, b = rc_images[target], ga_images[target]
        if not isinstance(a, str) or not DIGEST.fullmatch(a) or a != b:
            raise ContinuityError(f"unqualified or differing image digest: {target}")
    return {"schema": "dev10.rc-ga-continuity.v1", "release_tag": ga_tag,
            "qualified_rc": rc_tag, "rc_run_id": rc["run_id"],
            "source_sha": rc["source_sha"], "qualification_ref": rc["qualification_ref"],
            "images": {target: ga_images[target] for target in TARGETS},
            "result": "EXACT_DIGEST_CONTINUITY_VERIFIED"}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--rc", required=True, type=Path)
    p.add_argument("--ga", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    a = p.parse_args()
    try:
        result = qualify(json.loads(a.rc.read_text()), json.loads(a.ga.read_text()))
    except (OSError, ValueError) as exc:
        p.error(str(exc))
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
