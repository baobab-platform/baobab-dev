#!/usr/bin/env python3
"""DEV-10 release tag contract. Only GA and numbered RC channels are authorised.

This policy governs release eligibility, not temporary CVE risk acceptance:
the latter remains independently scoped to the explicitly approved versions.
"""
from __future__ import annotations
import argparse
import re

NUM = r"(?:0|[1-9][0-9]*)"
PATTERN = re.compile(rf"v(?P<major>{NUM})\.(?P<minor>{NUM})\.(?P<patch>{NUM})(?:-rc\.(?P<rc>[1-9][0-9]*))?\Z", re.ASCII)


def classify(tag: str) -> str | None:
    match = PATTERN.fullmatch(tag)
    if not match:
        return None
    return "rc" if match.group("rc") is not None else "ga"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    parser.add_argument("--kind", choices=("any", "rc", "ga"), default="any")
    args = parser.parse_args()
    kind = classify(args.tag)
    if kind is None or (args.kind != "any" and kind != args.kind):
        parser.error(f"unauthorised DEV-10 release tag: {args.tag!r}")
    print(kind)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
