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

from release_tag_policy import classify

from verify_signed_release_predicates import (
    PredicateError, fingerprint, parse_verified, qualify as verify_predicates,
)
from verify_legacy_provenance import (
    LegacyProofError, LEGACY_INDICES, LEGACY_TAG, qualify_legacy,
)

IMAGE = "ghcr.io/baobab-platform/baobab-dev"
INDEX_REF = re.compile(r"^ghcr\.io/baobab-platform/baobab-dev@sha256:[a-f0-9]{64}$")
SHA = re.compile(r"^[a-f0-9]{40}$")
NUM = r"(?:0|[1-9][0-9]*)"
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
    def __init__(self, message: str, diagnostic: dict | None = None):
        super().__init__(message)
        self.diagnostic = diagnostic or {}


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
                  and isinstance(m.get("platform"), dict)
                  and m["platform"].get("os") == "linux"
                  and m["platform"].get("architecture") == arch]
        require(len(images) == 1, f"linux/{arch}: expected one image descriptor")
        child = checked_digest(images[0].get("digest"), f"linux/{arch} child")
        siblings = [m for m in manifests
                    if isinstance(m, dict)
                    and isinstance(m.get("annotations"), dict)
                    and m["annotations"].get("vnd.docker.reference.type") == "attestation-manifest"
                    and m["annotations"].get("vnd.docker.reference.digest") == child]
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
               if isinstance(layer, dict)
               and isinstance(layer.get("annotations"), dict)
               and layer["annotations"].get("in-toto.io/predicate-type") == predicate_type]
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


def command_category(argv: list[str]) -> tuple[str, str]:
    tool = Path(argv[0]).name if argv else "unknown"
    operation = argv[1] if len(argv) > 1 else "unknown"
    if tool == "cosign" and operation == "verify-attestation":
        return "cosign_verify_attestation", operation
    if tool == "cosign" and operation == "verify":
        return "cosign_image_signature", operation
    if tool == "crane":
        return "registry_read", operation
    return "external_verifier", operation


def classify_cli_failure(argv: list[str], exit_status: int | None, stderr: str) -> dict:
    category, operation = command_category(argv)
    lower = stderr.lower()
    if any(token in lower for token in ("unknown flag", "unknown command", "unsupported predicate", "unsupported media type")):
        code, safe = "cosign_cli_or_predicate_incompatible", "Cosign CLI or attestation type is incompatible"
    elif "predicate type" in lower and any(token in lower for token in ("no matching", "not found", "mismatch")):
        code, safe = "cosign_predicate_type_mismatch", "Signed attestation predicate type does not match the verifier contract"
    elif any(token in lower for token in ("no matching certificates", "certificate identity", "oidc issuer", "issuer mismatch")):
        code, safe = "oidc_identity_or_issuer_mismatch", "Cosign certificate identity or OIDC issuer mismatch"
    elif any(token in lower for token in ("unauthorized", "status code 401", "http 401")):
        code, safe = "registry_authentication_rejected", "Registry authentication rejected"
    elif any(token in lower for token in ("forbidden", "status code 403", "http 403")):
        code, safe = "registry_authorization_rejected", "Registry authorization rejected"
    elif any(token in lower for token in ("429", "rate limit", "too many requests")):
        code, safe = "registry_rate_limited", "Registry rate limited the verification request"
    elif any(token in lower for token in ("timeout", "deadline exceeded", "connection reset", "temporary failure", "503", "unexpected eof")):
        code, safe = "transient_registry_or_network_failure", "Transient registry or network failure"
    elif any(token in lower for token in ("no matching signatures", "no signatures found", "no matching attestations", "manifest_unknown", "not found", "404", "referrer")):
        code, safe = "signature_or_referrer_not_found", "Expected signature, attestation or registry referrer not found"
    else:
        code, safe = "unclassified_external_verifier_failure", "External verifier failed; raw stderr intentionally withheld"
    return {
        "command_category": category,
        "command_operation": operation,
        "exit_status": exit_status,
        "error_code": code,
        "safe_stderr": safe,
    }


def run_cli(argv: list[str]) -> str:
    try:
        proc = subprocess.run(argv, check=False, text=True, capture_output=True, timeout=120)
    except subprocess.TimeoutExpired as exc:
        stderr = exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        diagnostic = classify_cli_failure(argv, None, stderr + " timeout")
        raise RegistryProofError(
            f"read-only remote verification failed: {diagnostic['command_category']}/"
            f"{diagnostic['error_code']} (timeout)", diagnostic
        ) from exc
    except OSError as exc:
        category, operation = command_category(argv)
        diagnostic = {
            "command_category": category,
            "command_operation": operation,
            "exit_status": None,
            "error_code": "verifier_tool_unavailable",
            "safe_stderr": "Verifier executable or operating-system process unavailable",
        }
        raise RegistryProofError(
            f"read-only remote verification failed: {category}/verifier_tool_unavailable",
            diagnostic,
        ) from exc
    if proc.returncode != 0:
        diagnostic = classify_cli_failure(argv, proc.returncode, proc.stderr or "")
        raise RegistryProofError(
            f"read-only remote verification failed: {diagnostic['command_category']}/"
            f"{diagnostic['error_code']} (exit {proc.returncode})", diagnostic
        )
    return proc.stdout


def parse_verified_signature(raw: str, expected_digest: str) -> dict:
    try:
        records = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RegistryProofError("cosign signature verifier returned invalid JSON") from exc
    require(isinstance(records, list) and bool(records),
            "cosign signature verifier returned no verified signatures")
    expected_hex = expected_digest.removeprefix("sha256:")
    for record in records:
        critical = record.get("critical") if isinstance(record, dict) else None
        image = critical.get("image") if isinstance(critical, dict) else None
        observed = image.get("docker-manifest-digest") if isinstance(image, dict) else None
        observed_hex = observed.removeprefix("sha256:") if isinstance(observed, str) else None
        require(observed_hex == expected_hex,
                "verified Cosign signature subject differs from immutable OCI index digest")
    return {"status": "VERIFIED", "signature_count": len(records),
            "subject_digest": expected_digest}


def verify(image: str, tag: str, expected_sha: str,
           runner: Callable[[list[str]], str] = run_cli,
           signer_tag: str | None = None) -> dict:
    require(bool(INDEX_REF.fullmatch(image)), "must verify exact Baobab GHCR index digest")
    require(classify(tag) is not None, "expected stable semver or numbered RC release tag")
    signer_tag = signer_tag or tag
    require(classify(signer_tag) is not None, "expected stable semver or numbered RC signer tag")
    release_rc = re.fullmatch(rf"^(v{NUM}\.{NUM}\.{NUM})-rc\.[1-9][0-9]*$", tag)
    signer_rc = re.fullmatch(rf"^(v{NUM}\.{NUM}\.{NUM})-rc\.[1-9][0-9]*$", signer_tag)
    if release_rc:
        require(signer_tag == tag, "an RC release must be signed by its own exact tag")
    else:
        require(signer_tag == tag or (signer_rc is not None and signer_rc.group(1) == tag),
                "GA signer must be the same-version RC tag or the exact GA tag")
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
        image_config = config.get("config")
        labels = image_config.get("Labels") if isinstance(image_config, dict) else None
        require(isinstance(labels, dict), arch + ": OCI revision labels are absent")
        actual_sha = labels.get("org.opencontainers.image.revision")
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
                ".github/workflows/publish.yml@refs/tags/" + signer_tag)
    base = ["--certificate-identity", identity,
            "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
            "--output", "json", image]
    digest = image.split("@", 1)[1]
    signature_output = runner(["cosign", "verify"] + base)
    signature_evidence = parse_verified_signature(signature_output, digest)
    signed_p = runner(["cosign", "verify-attestation", "--type", "slsaprovenance1"] + base)
    signed_s = runner(["cosign", "verify-attestation", "--type", "spdxjson"] + base)
    status = "STRICT_SIGNED_NATIVE_CONTENT_VERIFIED"
    try:
        signed = verify_predicates(raw_provenance, raw_sbom, signed_p, signed_s,
                                   expected_subject=digest)
    except PredicateError as exc:
        # Fingerprints, counts and types only: never put raw BuildKit provenance,
        # SPDX records, certificates or private inputs into CI logs.
        groups = (
            ("slsa", SLSA, raw_provenance, signed_p),
            ("spdx", SPDX, raw_sbom, signed_s),
        )
        diagnostics: dict = {}
        for name, kind, expected, verified in groups:
            item = {"embedded_sha256": [fingerprint(p) for p in expected]}
            try:
                item["signed_sha256"] = parse_verified(verified, kind, digest)
            except PredicateError as suberror:
                item["signed_error"] = str(suberror)
            diagnostics[name] = item

        # Only the FOUR immutable v1.4.4 releases used Cosign's old typed
        # SLSA v1 writer. The historical writer drops unrecognized proto
        # fields, so exact full-predicate equivalence is impossible. Require
        # independently verified OIDC signatures, matching SPDX content,
        # matching schema-known SLSA content and the pinned index/source.
        # A new/rebound release NEVER qualifies for this path.
        if tag == LEGACY_TAG and digest in LEGACY_INDICES:
            try:
                signed = qualify_legacy(
                    digest, tag, expected_sha, raw_provenance, raw_sbom,
                    signed_p, signed_s,
                )
                status = signed["status"]
            except LegacyProofError as legacy_exc:
                raise RegistryProofError(
                    "historical signed SLSA schema-known fields also differ; "
                    "no typed-serializer compatibility accepted: "
                    + str(legacy_exc) + "; digests="
                    + json.dumps(diagnostics, sort_keys=True)) from legacy_exc
        else:
            raise RegistryProofError(
                "signed-to-BuildKit predicate binding failed; strict R5 "
                "verification required: "
                + json.dumps(diagnostics, sort_keys=True)) from exc

    return {"schema": "baobab.dev10.readonly-registry-native-qualification.v1",
            "status": status, "image": image,
            "release_tag": tag, "signer_tag": signer_tag, "source_sha": expected_sha,
            "native": evidence, "image_signature_evidence": signature_evidence,
            "signed_predicate_evidence": signed}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--image", required=True)
    p.add_argument("--tag", required=True)
    p.add_argument("--signer-tag")
    p.add_argument("--expected-sha", required=True)
    p.add_argument("--evidence", type=Path, required=True)
    a = p.parse_args()
    try:
        result = verify(a.image, a.tag, a.expected_sha, signer_tag=a.signer_tag)
        a.evidence.parent.mkdir(parents=True, exist_ok=True)
        a.evidence.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
        if result["status"] != "STRICT_SIGNED_NATIVE_CONTENT_VERIFIED":
            print("::warning::Historical pinned v1.4.4: both native signed "
                  "SPDX documents and schema-known SLSA fields verified; "
                  "Cosign typed SLSA discarded unknown fields at signing. "
                  "Not full-content equivalent and NOT R5 release qualification.")
        else:
            print("Native AMD64/ARM64 revision, SLSA/SPDX full signed content VALID")
        return 0
    except (RegistryProofError, ValueError, TypeError, OSError) as exc:
        # Retain a bounded negative artifact, even when nothing qualified.
        # This is not a PASS or a waiver of missing two-platform signatures.
        historical_baseline = a.tag == "v1.5.1"
        report = {
            "schema": "baobab.dev10.readonly-registry-native-qualification.v1",
            "status": "HISTORICAL_BASELINE_UNQUALIFIED" if historical_baseline else "DENIED",
            "image": a.image,
            "release_tag": a.tag,
            "signer_tag": a.signer_tag or a.tag,
            "error": str(exc),
            "failure": getattr(exc, "diagnostic", None) or {
                "command_category": "qualification",
                "command_operation": "predicate_or_subject_validation",
                "exit_status": None,
                "error_code": "strict_qualification_failed",
                "safe_stderr": "Strict qualification requirements were not met",
            },
        }
        try:
            a.evidence.parent.mkdir(parents=True, exist_ok=True)
            a.evidence.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
        except OSError as write_exc:
            # Keep the original verifier denial authoritative even when
            # evidence storage itself is unavailable. Do not echo file
            # contents, tokens, raw attestation material or private paths.
            print("::warning::Could not persist DENIED evidence ("
                  + type(write_exc).__name__ + "); qualification still failed",
                  file=sys.stderr)
        if historical_baseline:
            print("::warning::HISTORICAL_BASELINE_UNQUALIFIED: v1.5.1 is not counted as strict R5 release qualification",
                  file=sys.stderr)
        else:
            print("::error::Read-only registry native attestation check DENIED:", exc,
                  file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
