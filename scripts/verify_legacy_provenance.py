#!/usr/bin/env python3
"""NARROW v1.4.4 Cosign typed/protobuf SLSA compatibility verification.

Historical Cosign --type slsaprovenance1 used a typed protobuf writer:
  - it renamed runDetails.metadata.invocationID -> invocationId;
  - protobuf deserialization discarded *unknown* schema fields;
  - protobuf JSON serialization omits empty/default fields.

New Baobab R5 releases MUST use exact canonical-URI signing and byte-semantic
full predicate comparison instead. Do not use this legacy projection for
future images. Verify signed subjects, provenance identity, schema-known
field preservation, SPDX content and both native architectures first.

Reference: sigstore/cosign v3.1.4 pkg/cosign/attestation/attestation.go
generateSLSAProvenanceStatementSLSA1 (DiscardUnknown=true).
"""
from __future__ import annotations

import base64
import json
from typing import Any

from verify_signed_release_predicates import PredicateError, fingerprint, parse_verified

SLSA = "https://slsa.dev/provenance/v1"
SPDX = "https://spdx.dev/Document"

# Exact historical v1.4.4 index identities. This is an explicit compatibility
# boundary, not a broad major/minor range or a release-risk waiver.
LEGACY_INDICES = {
    "sha256:9603f0e7402aa85771e904db1c20f2ecc02f705131b266cb4ec3d1c24ea58ae4",
    "sha256:1b3165067912eacbca96b576efb67e0428850b1ff1a953aa9013127a01635371",
    "sha256:eb9c401cea16c4f333c28b250dd455e505752dfc6d11e9779a182a02bc207213",
    "sha256:0f73f3e6093ab5c955cbbb341e5731681ee4283cae75f13c56f3e38373467ecc",
}
LEGACY_TAG = "v1.4.4"
LEGACY_SOURCE = "aa2b726ebb53a1b893e49d44ccac3ca29e2dd5ee"

# Frozen FULL-content SHA256 fingerprints independently read from the signed
# Cosign DSSE envelopes and original per-platform BuildKit attestations on
# 2026-11-03, workflow run 41617788874. This documents *what* v1.4.4 signed
# and embedded, including the two profiles where Cosign's typed SLSA conversion
# is not faithfully reproduced by the simplified public-schema projection.
# Neither source nor signed digest can drift unnoticed. Only the four known
# immutable OCI release indices, exact source SHA and separately authenticated
# Sigstore subjects qualify; this NEVER permits mismatched future R5 releases.
HISTORIC_SLSA_FINGERPRINTS = {
    "sha256:9603f0e7402aa85771e904db1c20f2ecc02f705131b266cb4ec3d1c24ea58ae4": {
        "embedded": ("cee4d5171f1c759f573bac45ccfd34f1d49abb885cc37beefa6934b3303777c4",
                     "23f83dd67c915436c103886eed92017721a8f24d623f431960360b6ef42c8bbd"),
        "signed": ("34948b189ed0b2c91f29fe66e4919ec1453368fd5047783b7fa6a03c00b40099",
                   "2227f39e7990fa32804e58bac8b5bfebd6e3b47d6890d7a4e41cc0b592124876"),
    },
    "sha256:1b3165067912eacbca96b576efb67e0428850b1ff1a953aa9013127a01635371": {
        "embedded": ("17c6f2bb946c426371179f746ae9be41df5dd59476831782cd42b762e6c0bfa1",
                     "c33b3fb74422f23c7ed184e0d8b6ef9b844ed6b939365abb2b5677784a94f54c"),
        "signed": ("e6da2943721b2d8ade84050425bfb4001b13211cb0361f282771400c7f6ec557",
                   "edf61651bd54576867e888ec18ded729a4669c173843d76c3afd1406ccc4d0b8"),
    },
    "sha256:eb9c401cea16c4f333c28b250dd455e505752dfc6d11e9779a182a02bc207213": {
        "embedded": ("cd494d29d64940224003c804123abb969b9216c6c30214af2a110a147b213b48",
                     "68500e5bca47c08726f23359964b5ce666a14a1bb36015e0914092dec1d3b3da"),
        "signed": ("01827f24a230844f434b5ad2a8391569d00ebaaf60f37e8fbba364780fc9654f",
                   "8b721446438eb060b0a8a549d85f8954c3ec2c0a3f0ba02c3b5b867dea8b6c1b"),
    },
    "sha256:0f73f3e6093ab5c955cbbb341e5731681ee4283cae75f13c56f3e38373467ecc": {
        "embedded": ("7372bac64bb40565bfa59a90312becf1a3f2328a656b7b08d3bdde156bd7d902",
                     "72635a26c6b6aefe7af363704cb4bb8d59af7f916df34ad1a29f485290874bbb"),
        "signed": ("a0a6668e4f0125cc7dc193ccc234d6d0edc7f7ef7aa750e17cc90cf56a9f557a",
                   "0d76440579fa0748ce35fb7bb5ef1179024b204598f964d0131ded826d207c07"),
    },
}

# The public protobuf schema in in-toto/attestation v1. Scope only the
# schema-known fields; arbitrary JSON maps (parameters, annotations)
# remain fully compared, not truncated to named keys.
SCHEMA = {
    "provenance": {"buildDefinition": "definition", "runDetails": "run"},
    "definition": {"buildType": None, "externalParameters": "any",
                   "internalParameters": "any", "resolvedDependencies": ["resource"]},
    "run": {"builder": "builder", "metadata": "metadata",
            "byproducts": ["resource"]},
    "builder": {"id": None, "version": "any",
                "builderDependencies": ["resource"]},
    "metadata": {"invocationId": None, "startedOn": None, "finishedOn": None},
    "resource": {"name": None, "uri": None, "digest": "any", "content": None,
                 "downloadLocation": None, "mediaType": None,
                 "annotations": "any"},
}


class LegacyProofError(PredicateError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise LegacyProofError(message)


def canonical_empty(value: Any) -> Any:
    """SLSA v1 specifies unset/null/empty fields as equivalent."""
    if isinstance(value, dict):
        return {k: v for k, x in value.items()
                if (v := canonical_empty(x)) not in (None, "", [], {})}
    if isinstance(value, list):
        return [v for x in value
                if (v := canonical_empty(x)) not in (None, "", [], {})]
    return value


def project(raw: Any, schema: Any, path: str = "predicate") -> dict | list | Any:
    if schema is None or schema == "any":
        return canonical_empty(raw)
    if isinstance(schema, list):
        require(isinstance(raw, list), path + ": expected repeated resource list")
        return [project(item, schema[0], path + "[]") for item in raw]
    require(isinstance(raw, dict), path + ": expected object")
    fields = SCHEMA[schema]
    # Preserve only fields Cosign's historic typed SLSA provenance writer
    # could preserve. Unknown fields must NOT become accepted new R5 data.
    value = {}
    for key, field_schema in fields.items():
        name = key
        if key == "invocationId" and path == "predicate.runDetails.metadata":
            if "invocationID" in raw:
                require("invocationId" not in raw,
                        "ambiguous historical invocationID / invocationId")
                name = "invocationID"
        if name in raw:
            value[key] = project(raw[name], field_schema, path + "." + key)
    return canonical_empty(value)


def decoded_statements(raw: str, predicate_type: str, index_digest: str) -> list[dict]:
    try:
        document = json.loads(raw)
        records = document if isinstance(document, list) else [document]
    except ValueError:
        try:
            records = [json.loads(line) for line in raw.splitlines() if line.strip()]
        except ValueError as exc:
            raise LegacyProofError("unreadable verified Cosign DSSE output") from exc
    require(len(records) == 2, "expected exactly two independently verified signed statements")
    statements = []
    for rec in records:
        require(isinstance(rec, dict) and isinstance(rec.get("payload"), str),
                "missing verified signed payload")
        try:
            statement = json.loads(base64.b64decode(rec["payload"], validate=True))
        except (ValueError, UnicodeError) as exc:
            raise LegacyProofError("invalid signed payload JSON") from exc
        require(isinstance(statement, dict) and statement.get("predicateType") == predicate_type,
                "signed predicateType differs from required schema")
        subjects = statement.get("subject")
        require(isinstance(subjects, list) and len(subjects) == 1
                and isinstance(subjects[0], dict)
                and subjects[0].get("digest") == {"sha256": index_digest[7:]},
                "legacy signed statement does not reference exact OCI index")
        require(isinstance(statement.get("predicate"), dict),
                "signed predicate content absent")
        statements.append(statement["predicate"])
    return statements


def qualify_legacy(
    image_digest: str, tag: str, source_sha: str,
    embedded_slsa: list[dict], embedded_spdx: list[dict],
    verified_slsa: str, verified_spdx: str,
) -> dict:
    require(tag == LEGACY_TAG and image_digest in LEGACY_INDICES
            and source_sha == LEGACY_SOURCE,
            "legacy typed-Cosign allowance only for four pinned v1.4.4 indices")
    require(len(embedded_slsa) == len(embedded_spdx) == 2,
            "legacy requires both native provenance and SPDX records")
    # SBOM predicates used an untyped Struct serializer and already match
    # exactly. No SPDX relaxation is allowed even for this old release.
    spdx_hashes = [fingerprint(p) for p in embedded_spdx]
    require(len(set(spdx_hashes)) == 2, "duplicate platform SPDX records")
    signed_spdx_hashes = parse_verified(verified_spdx, SPDX, image_digest)
    require(sorted(spdx_hashes) == sorted(signed_spdx_hashes),
            "historical SPDX contents/subjects mismatch")
    signed_slsa = decoded_statements(verified_slsa, SLSA, image_digest)
    projected_embedded = [project(p, "provenance") for p in embedded_slsa]
    projected_signed = [project(p, "provenance") for p in signed_slsa]
    for predicate in projected_embedded + projected_signed:
        definition = predicate.get("buildDefinition") or {}
        builder = (predicate.get("runDetails") or {}).get("builder") or {}
        require(isinstance(definition.get("buildType"), str)
                and bool(definition["buildType"])
                and isinstance(builder.get("id"), str) and bool(builder["id"]),
                "SLSA buildType/builder identity missing")
    expected = [fingerprint(p) for p in projected_embedded]
    actual = [fingerprint(p) for p in projected_signed]
    require(len(set(expected)) == 2 and len(set(actual)) == 2,
            "duplicate/indistinguishable native provenance")
    semantic_match = sorted(expected) == sorted(actual)
    # Verify immutable full-content evidence in addition to the typed schema
    # projection, even when Cosign has a historical serialization mismatch.
    # A schema mismatch is NOT silently converted to a semantic PASS: retain
    # its own explicit legacy fingerprint qualification and review warning.
    history = HISTORIC_SLSA_FINGERPRINTS.get(image_digest)
    require(history is not None and set(HISTORIC_SLSA_FINGERPRINTS) == LEGACY_INDICES,
            "historical release content pinning not configured")
    embedded_hashes = [fingerprint(p) for p in embedded_slsa]
    signed_hashes = [fingerprint(p) for p in signed_slsa]
    require(sorted(embedded_hashes) == sorted(history["embedded"]),
            "historical BuildKit full-content fingerprint changed")
    require(sorted(signed_hashes) == sorted(history["signed"]),
            "historical signed SLSA full-content fingerprint changed")
    return {
        "status": ("LEGACY_SLSA_PROTOBUF_COMPATIBLE_NOT_FULL_CONTENT_EQUIVALENCE"
                   if semantic_match else
                   "LEGACY_SLSA_EXACT_FINGERPRINTS_PINNED_NOT_SEMANTICALLY_EQUAL"),
        "slsa_schema_known_equivalent": semantic_match,
        "historical_source": LEGACY_SOURCE,
        "policy_scope": "PINNED v1.4.4 ONLY; never release approval for R5",
        "signed_native_slsa": 2, "signed_native_spdx": 2,
        "slsa_schema_known_hashes": {"amd64": expected[0], "arm64": expected[1]},
        "slsa_full_fingerprints_pinned": True,
    }
