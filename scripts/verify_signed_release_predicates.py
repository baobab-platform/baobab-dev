#!/usr/bin/env python3
"""Fail-closed comparison of signed Cosign attestations to BOTH BuildKit predicates.

Cosign's certificate check proves OIDC identity; an attestation's mere existence
does not prove it contains the two distinct AMD64/ARM64 SBOM/provenance
predicates extracted from the exact OCI index. Compare canonical JSON payloads
after Cosign has independently verified their signatures and issuer.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
from pathlib import Path
import sys


class PredicateError(ValueError):
    pass


def fingerprint(predicate: object) -> str:
    if not isinstance(predicate, dict) or not predicate:
        raise PredicateError("missing or invalid signed predicate content")
    canonical = json.dumps(predicate, sort_keys=True,
                           ensure_ascii=False, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def parse_verified(raw: str, predicate_type: str, subject_digest: str | None = None) -> list[str]:
    """Cosign JSON may be a list or newline-delimited JSON objects."""
    try:
        document = json.loads(raw)
        records = document if isinstance(document, list) else [document]
    except json.JSONDecodeError:
        try:
            records = [json.loads(line) for line in raw.splitlines() if line.strip()]
        except json.JSONDecodeError as exc:
            raise PredicateError("invalid Cosign verified JSON output") from exc
    if not records:
        raise PredicateError("no signed attestations")
    result = []
    for record in records:
        if not isinstance(record, dict):
            raise PredicateError("invalid verified statement")
        payload = record.get("payload")
        if isinstance(payload, str):
            try:
                statement = json.loads(base64.b64decode(payload, validate=True))
            except (ValueError, UnicodeError) as exc:
                raise PredicateError("invalid DSSE attestation payload") from exc
        elif isinstance(payload, dict):
            statement = payload
        else:
            raise PredicateError("Cosign output omitted signed DSSE payload")
        if not isinstance(statement, dict) or statement.get("predicateType") != predicate_type:
            raise PredicateError("unexpected signed predicate type")
        if subject_digest is not None:
            # Cosign verifies the envelope signature; enforce that its signed
            # in-toto subject is exactly the OCI index we inspected.
            subjects = statement.get("subject")
            if (not isinstance(subjects, list) or len(subjects) != 1
                    or not isinstance(subjects[0], dict)
                    or subjects[0].get("digest") != {"sha256": subject_digest[7:]}):
                raise PredicateError("signed in-toto subject digest does not match OCI index")
        result.append(fingerprint(statement.get("predicate")))
    return result


def qualify(provenance: list[dict], sbom: list[dict],
            verified_provenance: str, verified_sbom: str,
            expected_subject: str | None = None) -> dict:
    if len(provenance) != 2 or len(sbom) != 2:
        raise PredicateError("expected two architecture predicates per type")
    if expected_subject is not None and not re.fullmatch(r"sha256:[a-f0-9]{64}", expected_subject):
        raise PredicateError("invalid signed subject digest reference")
    types = (
        ("SLSA provenance", "https://slsa.dev/provenance/v1",
         provenance, verified_provenance),
        ("SPDX SBOM", "https://spdx.dev/Document", sbom, verified_sbom),
    )
    evidence = {"schema": "baobab.dev10.signed-multiarch-predicates.v1", "kinds": {}}
    for name, kind, expected, raw in types:
        expected_hashes = [fingerprint(x) for x in expected]
        if len(set(expected_hashes)) != 2:
            raise PredicateError(name + ": amd64 and arm64 predicates are identical")
        actual_hashes = parse_verified(raw, kind, expected_subject)
        if len(actual_hashes) != 2 or sorted(actual_hashes) != sorted(expected_hashes):
            raise PredicateError(name + ": signed predicates do not match both native architectures")
        evidence["kinds"][name] = {
            "amd64_sha256": expected_hashes[0], "arm64_sha256": expected_hashes[1],
            "verified_signed_statements": 2,
        }
    return evidence


def main() -> int:
    p = argparse.ArgumentParser()
    for kind in ("provenance", "sbom"):
        for platform in ("amd64", "arm64"):
            p.add_argument("--" + kind + "-" + platform, type=Path, required=True)
        p.add_argument("--verified-" + kind, type=Path, required=True)
    p.add_argument("--evidence", type=Path, required=True)
    p.add_argument("--expected-subject", required=True,
                   help="exact signed OCI index digest sha256:...")
    args = p.parse_args()
    try:
        evidence = qualify(
            [json.loads(args.provenance_amd64.read_text()),
             json.loads(args.provenance_arm64.read_text())],
            [json.loads(args.sbom_amd64.read_text()),
             json.loads(args.sbom_arm64.read_text())],
            args.verified_provenance.read_text(),
            args.verified_sbom.read_text(),
            args.expected_subject,
        )
        args.evidence.parent.mkdir(parents=True, exist_ok=True)
        args.evidence.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
        print("Verified exact, distinct AMD64 and ARM64 signed SLSA+SPDX predicates")
        return 0
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        print("::error::R5 signed-predicate content check DENIED:", exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
