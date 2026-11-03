#!/usr/bin/env python3
"""Independent, read-only GHCR proof for BOTH signed native image architectures.

Use only immutable index/child digests. A valid Cosign signature of *one*
attestation does not prove the second native architecture's BuildKit
provenance or its full package inventory is still present.

The embedded BuildKit SPDX document includes file-level metadata; publish.yml
signs its deterministic file-trimmed projection. Reproduce that projection
exactly and compare its canonical content with independently Cosign-verified
signed statements, without permitting incomplete or ambiguous manifests.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Callable

from verify_signed_release_predicates import qualify as verify_predicates

IMAGE = "ghcr.io/baobab-platform/baobab-dev"
INDEX_REF = re.compile(r"^ghcr\.io/baobab-platform/baobab-dev@sha256:[a-f0-9]{64}$")
SHA = re.compile(r"^[a-f0-9]{40}$")
TAG = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
PLATFORMS = ("amd64", "arm64")
SLSA = "https://slsa.dev/provenance/v1"
SPDX = "https://spdx.dev/Document"
TRIM_NOTE = (
    "File-level cataloging (SPDX 'files' array and per-file ownership "
    "relationships) intentionally omitted from this attestation to keep the "
    "predicate within Sigstore Rekor's practical size limits. Every package "
    "below remains fully declared with complete purl/version/license "
    "metadata — nothing was removed from the package list, only the "
    "per-file evidence layer beneath it. Re-scan the published image "
    "directly with Syft (file.metadata.selection: all) for file-level detail."
)


class RegistryProofError(ValueError):
    pass


def require(value: bool, error: str) -> None:
    if not value:
        raise RegistryProofError(error)


def parse_object(raw: str, what: str) -> dict:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RegistryProofError(f"{what}: invalid JSON") from exc
    require(isinstance(value, dict), f"{what}: expected JSON object")
    return value


def checked_digest(value: object, what: str) -> str:
    require(isinstance(value, str) and DIGEST.fullmatch(value) is not None,
            f"{what}: invalid SHA256 digest")
    return value


def native_index(index: dict) -> dict[str, tuple[str, str]]:
    require(isinstance(index, dict), "missing OCI index")
    manifests = index.get("manifests")
    require(isinstance(manifests, list) and len(manifests) == 4,
            "expected exactly two native images plus two attestation siblings")
    result = {}
    for arch in PLATFORMS:
        images = [m for m in manifests
                  if isinstance(m, dict)
                  and m.get("platform", {}).get("os") == "linux"
                  and m.get("platform", {}).get("architecture") == arch]
        require(len(images) == 1, f"linux/{arch}: expected one image descriptor")
        child = checked_digest(images[0].get("digest"), f"linux/{arch} child")
        siblings = [m for m in manifests
                    if isinstance(m, dict)
                    and m.get("annotations", {}).get("vnd.docker.reference.type") == "attestation-manifest"
                    and m.get("annotations", {}).get("vnd.docker.reference.digest") == child]
        require(len(siblings) == 1, f"linux/{arch}: expected one attached manifest")
        sibling = checked_digest(siblings[0].get("digest"), f"linux/{arch} attestation")
        require(child != sibling, "image may not be its own attestation sibling")
        result[arch] = (child, sibling)
    used = {digest for pair in result.values() for digest in pair}
    require(len(used) == 4, "duplicate or shared native/attestation manifests")
    require({m.get("digest") for m in manifests} == used,
            "orphan/unexpected OCI image descriptor")
    return result


def statement_digest(attestation: dict, predicate_type: str) -> str:
    layers = attestation.get("layers")
    require(isinstance(layers, list), "invalid attestation manifest layers")
    matches = [layer for layer in layers
               if isinstance(layer, dict) and
               layer.get("annotations", {}).get("in-toto.io/predicate-type") == predicate_type]
    require(len(matches) == 1,
            f"expected exactly one BuildKit layer for {predicate_type}; got {len(matches)}")
    return checked_digest(matches[0].get("digest"), predicate_type)


def trim_spdx(raw: dict) -> dict:
    require(isinstance(raw, dict) and isinstance(raw.get("packages"), list),
            "BuildKit SPDX package inventory absent")
    files = raw.get("files") or []
    relationships = raw.get("relationships") or []
    require(isinstance(files, list) and isinstance(relationships, list),
            "invalid SPDX file or relationship inventory")
    ids = set()
    for item in files:
        require(isinstance(item, dict) and isinstance(item.get("SPDXID"), str),
                "malformed SPDX file identifier")
        require(item["SPDXID"] not in ids, "duplicate SPDX file identifier")
        ids.add(item["SPDXID"])
    output = copy.deepcopy(raw)
    output.pop("files", None)
    output["relationships"] = []
    for relation in relationships:
        require(isinstance(relation, dict), "malformed SPDX relationship")
        if relation.get("spdxElementId") not in ids and relation.get("relatedSpdxElement") not in ids:
            output["relationships"].append(relation)
    output["comment"] = TRIM_NOTE
    require(output["packages"] == raw["packages"], "package inventory was modified")
    return output


def run_cli(argv: list[str]) -> str:
    try:
        proc = subprocess.run(argv, check=True, text=True, capture_output=True,
                              timeout=120)
        return proc.stdout
    except (subprocess.SubprocessError, OSError) as exc:
        raise RegistryProofError(f"read-only remote verification command failed: {argv[0]} {argv[1]}") from exc


def verify(image: str, tag: str, expected_sha: str,
           runner: Callable[[list[str]], str] = run_cli) -> dict:
    require(bool(INDEX_REF.fullmatch(image)), "must verify exact Baobab GHCR index digest")
    require(bool(TAG.fullmatch(tag)), "expected stable release tag")
    require(bool(SHA.fullmatch(expected_sha)), "expected 40-character release source SHA")
    index = parse_object(runner(["crane", "manifest", image]), "OCI index")
    targets = native_index(index)
    raw_provenance, raw_sbom = [], []
    evidence = {}
    for arch in PLATFORMS:
        child, sibling = targets[arch]
        child_ref = IMAGE + "@" + child
        sibling_ref = IMAGE + "@" + sibling
        # Independently read the actual child and config, not just references
        # inside a manifest whose blobs might have been garbage collected.
        child_manifest = parse_object(runner(["crane", "manifest", child_ref]),
                                      arch + " child manifest")
        require(isinstance(child_manifest.get("layers"), list),
                arch + ": image layers not resolvable")
        config = parse_object(runner(["crane", "config", child_ref]),
                              arch + " image config")
        actual_sha = (config.get("config") or {}).get("Labels", {}).get(
            "org.opencontainers.image.revision")
        require(actual_sha == expected_sha,
                arch + ": image revision differs from protected release tag source")
        att = parse_object(runner(["crane", "manifest", sibling_ref]),
                           arch + " attestation manifest")
        provenance_blob = statement_digest(att, SLSA)
        sbom_blob = statement_digest(att, SPDX)
        raw_p = parse_object(
            runner(["crane", "blob", IMAGE + "@" + provenance_blob]), arch + " provenance blob")
        raw_s = parse_object(
            runner(["crane", "blob", IMAGE + "@" + sbom_blob]), arch + " SBOM blob")
        require(raw_p.get("predicateType") == SLSA
                and isinstance(raw_p.get("predicate"), dict), arch + ": wrong provenance statement")
        require(raw_s.get("predicateType") == SPDX
                and isinstance(raw_s.get("predicate"), dict), arch + ": wrong SPDX statement")
        raw_provenance.append(raw_p["predicate"])
        raw_sbom.append(trim_spdx(raw_s["predicate"]))
        evidence[arch] = {"image_digest": child, "attestation_digest": sibling,
                          "revision": actual_sha,
                          "buildkit_slsa_blob": provenance_blob,
                          "buildkit_spdx_blob": sbom_blob}

    # The identity is exact to this repository's stable-tag publishing file.
    # cosign verify-attestation performs actual cryptographic verification;
    # parse_verified only consumes the resulting *verified* stdout.
    identity = ("https://github.com/baobab-platform/baobab-dev/"
                ".github/workflows/publish.yml@refs/tags/" + tag)
    base = ["--certificate-identity", identity,
            "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
            "--output", "json", image]
    signed_p = runner(["cosign", "verify-attestation", "--type", "slsaprovenance1"] + base)
    signed_s = runner(["cosign", "verify-attestation", "--type", "spdxjson"] + base)
    signed = verify_predicates(raw_provenance, raw_sbom, signed_p, signed_s)
    return {"schema": "baobab.dev10.readonly-registry-native-qualification.v1",
            "image": image, "release_tag": tag, "source_sha": expected_sha,
            "native": evidence, "signed_predicate_evidence": signed}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--image", required=True)
    p.add_argument("--tag", required=True)
    p.add_argument("--expected-sha", required=True)
    p.add_argument("--evidence", type=Path, required=True)
    a = p.parse_args()
    try:
        result = verify(a.image, a.tag, a.expected_sha)
        a.evidence.parent.mkdir(parents=True, exist_ok=True)
        a.evidence.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
        print("Native AMD64/ARM64 image revision, BuildKit SLSA/SPDX and signed content VALID")
        return 0
    except (RegistryProofError, ValueError, TypeError, OSError) as exc:
        print("::error::Read-only registry native attestation check DENIED:", exc,
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
