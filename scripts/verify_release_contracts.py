#!/usr/bin/env python3
"""DEV-10 R5: parse a GitHub Release's advertised GHCR contract fail-closed.

The release body is untrusted, free-form presentation text. An omitted target,
a duplicated target, a foreign registry, or a tag/digest mismatch must never
become a green registry-integrity result by checking only the first record.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

IMAGE = "ghcr.io/baobab-platform/baobab-dev"
TARGETS = ("final", "frontend", "frontend-e2e", "infra")
HEADER = re.compile(r"(?m)^\*\*(?P<target>[^*\r\n]+):\*\*\s*$")
PULL = re.compile(r"(?m)^docker pull\s+(?P<ref>\S+)\s*$")
DIGEST = re.compile(r"(?m)^Verify \(digest `(?P<digest>sha256:[0-9a-f]{64})`\):\s*$")
# RCs are real versioned development-image releases, never GA aliases.
TAG = re.compile(r"^v(?P<version>(?:[0-9]+\.[0-9]+\.[0-9]+|1\.5\.0-rc\.[1-9][0-9]*))$")


class ContractError(ValueError):
    pass


def parse_contracts(body: str, release_tag: str) -> list[tuple[str, str, str]]:
    version_match = TAG.fullmatch(release_tag)
    if not version_match:
        raise ContractError("not a stable semver or approved v1.5.0-rc.N release")
    version = version_match.group("version")
    headers = list(HEADER.finditer(body))
    if len(headers) != len(TARGETS):
        raise ContractError(f"expected exactly {len(TARGETS)} target headers; found {len(headers)}")
    found = {}
    for index, match in enumerate(headers):
        target = match.group("target")
        if target not in TARGETS:
            raise ContractError(f"unrecognized release target: {target}")
        if target in found:
            raise ContractError(f"duplicate target: {target}")
        end = headers[index + 1].start() if index + 1 < len(headers) else len(body)
        chunk = body[match.end():end]
        pulls = PULL.findall(chunk)
        digests = DIGEST.findall(chunk)
        if len(pulls) != 1 or len(digests) != 1:
            raise ContractError(f"{target}: requires exactly one pull ref and digest")
        ref, digest = pulls[0], digests[0]
        expected_tag = version if target == "final" else f"{version}-{target}"
        expected_ref = f"{IMAGE}:{expected_tag}"
        if ref != expected_ref:
            raise ContractError(f"{target}: expected exact ref {expected_ref}, got {ref}")
        found[target] = (target, ref, digest)
    if set(found) != set(TARGETS):
        raise ContractError(f"missing advertised profiles: {sorted(set(TARGETS) - set(found))}")
    if len({row[2] for row in found.values()}) != len(TARGETS):
        raise ContractError("release target digests are not distinct")
    return [found[target] for target in TARGETS]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-body", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        contracts = parse_contracts(args.release_body.read_text(), args.tag)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text("".join("\t".join(contract) + "\n" for contract in contracts))
        print(json.dumps({"schema": "baobab.dev10.release-contract.v1",
                          "release_tag": args.tag, "targets": len(contracts),
                          "contracts": [dict(target=t, ref=r, digest=d) for t, r, d in contracts]},
                         indent=2))
        return 0
    except (ContractError, OSError) as exc:
        print(f"::error::Release contract DENIED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
