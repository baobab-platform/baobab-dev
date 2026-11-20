#!/usr/bin/env python3
"""Join protected release authorization, registry readback and security decisions."""

import argparse
import csv
import hashlib
import json
from pathlib import Path

from verify_release_artifact_contract import BASE, TARGETS, validate


def load(path):
    return json.loads(path.read_bytes())


def require(condition, message):
    if not condition:
        raise ValueError(message)


def assemble(tag, channel, source, run_id, evidence, candidates):
    images = validate(candidates, tag, channel)
    approval = load(evidence / "approval.json")
    require(approval.get("tag") == tag and approval.get("run_id") == run_id
            and approval.get("run_attempt") == 1, "protected approval has the wrong release identity")
    with (evidence / "promotion.tsv").open(newline="") as journal:
        rows = list(csv.DictReader(journal, delimiter="\t"))
    expected_result = "PROMOTED_FOUR_RC_VERSIONS_NO_ALIASES" if channel == "rc" else "PROMOTED_FOUR_TARGETS_AND_ALIASES"
    require(rows and rows[-1]["result"] == expected_result and rows[-1]["tag"] == tag,
            "registry promotion is incomplete")
    moved = {(row["tag"], row["digest"]) for row in rows
             if row["phase"] == "version" and row["result"] == "VERIFIED"}
    output = {}
    for target in TARGETS:
        candidate = load(candidates / (target + ".json"))
        digest = images[target]
        image_tag = candidate["tag"]
        signer_tag = candidate.get("signer_tag", tag)
        readback = load(evidence / "registry" / (target + ".json"))
        require((image_tag.removeprefix(BASE), digest) in moved
                and readback.get("status") == "STRICT_SIGNED_NATIVE_CONTENT_VERIFIED"
                and readback.get("release_tag") == tag and readback.get("signer_tag") == signer_tag
                and readback.get("source_sha") == source and readback.get("image") == BASE[:-1] + "@" + digest,
                "registry, signer or source readback mismatch for " + target)
        for arch in ("amd64", "arm64"):
            child = readback["native"][arch]["image_digest"]
            security = load(evidence / "security" / f"{target}-{arch}.json")
            require(security == {"status": "no-high-critical-findings", "digest": child},
                    "missing exact child security decision for " + target + "/" + arch)
        output[target] = {"tag": image_tag, "digest": digest, "registry_readback": readback,
                          "security_status": "unfiltered-clean"}
    return {
        "schema": "baobab.dev10.release-evidence.v1", "release_tag": tag, "source_sha": source,
        "workflow_run_id": run_id, "publication_channel": channel, "authorization": approval,
        "inputs": {name: hashlib.sha256(Path(name).read_bytes()).hexdigest()
                   for name in ("config/versions.yaml", "config/versions.lock", ".python-version")},
        "profiles": output, "release_risk_decision": "no-high-critical-findings",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--channel", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--candidates", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = assemble(args.tag, args.channel, args.source, args.run_id, args.evidence, args.candidates)
        (args.evidence / "release-evidence.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
