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
import hashlib
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
    require(sorted(expected) == sorted(actual),
            "schema-known provenance fields differ after historical typed conversion")
    return {
        "status": "LEGACY_SLSA_PROTOBUF_COMPATIBLE_NOT_FULL_CONTENT_EQUIVALENCE",
        "historical_source": LEGACY_SOURCE,
        "policy_scope": "PINNED v1.4.4 ONLY; never release approval for R5",
        "signed_native_slsa": 2, "signed_native_spdx": 2,
        "slsa_schema_known_hashes": {"amd64": expected[0], "arm64": expected[1]},
    }
