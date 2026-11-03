"""Prove v1.4.4-only typed Cosign SLSA compatibility never extends to R5."""
from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import verify_legacy_provenance as legacy  # noqa: E402
from verify_signed_release_predicates import fingerprint  # noqa: E402

DIGEST = sorted(legacy.LEGACY_INDICES)[0]
SLSA = "https://slsa.dev/provenance/v1"
SPDX = "https://spdx.dev/Document"


def envelopes(kind: str, predicates: list[dict], index: str = DIGEST) -> str:
    result = []
    for predicate in predicates:
        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "ghcr.io/baobab-platform/baobab-dev",
                         "digest": {"sha256": index.removeprefix("sha256:")}}],
            "predicateType": kind,
            "predicate": predicate,
        }
        result.append({"payload": base64.b64encode(
            json.dumps(statement).encode()).decode(),
            "payloadType": "application/vnd.in-toto+json"})
    return json.dumps(result)


class LegacyProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.raw = [
            {"buildDefinition": {
                "buildType": "https://github.com/moby/buildkit/" + arch,
                "externalParameters": {"source": "git+" + arch},
                "buildkitUndeclaredField": {"sub": "historical-dropped"}},
             "runDetails": {
                "builder": {"id": "builder-" + arch},
                "metadata": {"invocationID": "build-" + arch,
                             "unusedHistorical": "also-dropped"},
                "oldCustomExtension": {"arch": arch}}}
            for arch in ("amd64", "arm64")
        ]
        self.projection = [legacy.project(x, "provenance") for x in self.raw]
        self.spdx = [{"SPDXID": "SPDXRef-DOCUMENT",
                      "packages": [{"name": arch}]}
                     for arch in ("amd64", "arm64")]
        # Substitute synthetic known history only inside this isolated test.
        # Production hashes remain fixed in source and cannot be inferred from
        # arbitrary signed content. Tests below verify mismatches are denied.
        fixture = {
            "embedded": tuple(fingerprint(p) for p in self.raw),
            "signed": tuple(fingerprint(p) for p in self.projection),
        }
        context = patch.dict(legacy.HISTORIC_SLSA_FINGERPRINTS,
                             {DIGEST: fixture})
        context.start()
        self.addCleanup(context.stop)

    def qualify(self, **kw):
        base = dict(image_digest=DIGEST, tag=legacy.LEGACY_TAG,
                    source_sha=legacy.LEGACY_SOURCE, embedded_slsa=self.raw,
                    embedded_spdx=self.spdx,
                    verified_slsa=envelopes(SLSA, self.projection),
                    verified_spdx=envelopes(SPDX, self.spdx))
        base.update(kw)
        return legacy.qualify_legacy(**base)

    def test_historical_proto_field_rename_and_unknown_drop(self):
        result = self.qualify()
        self.assertEqual(
            result["status"],
            "LEGACY_SLSA_PROTOBUF_COMPATIBLE_NOT_FULL_CONTENT_EQUIVALENCE")
        self.assertEqual(result["signed_native_slsa"], 2)
        self.assertEqual(result["signed_native_spdx"], 2)
        self.assertNotIn("buildkitUndeclaredField",
                         result["slsa_schema_known_hashes"])

    def test_incorrect_or_new_release_never_receives_legacy_treatment(self):
        for overrides in (
            {"tag": "v1.5.0"},
            {"image_digest": "sha256:" + "f" * 64},
            {"source_sha": "f" * 40},
        ):
            with self.subTest(overrides=overrides), self.assertRaises(legacy.LegacyProofError):
                self.qualify(**overrides)

    def test_full_spdx_must_still_match_and_subject_is_digest_bound(self):
        sbom = copy.deepcopy(self.spdx)
        sbom[1]["packages"][0]["name"] = "tampered"
        for overrides in (
            {"verified_spdx": envelopes(SPDX, sbom)},
            {"verified_slsa": envelopes(SLSA, self.projection, "sha256:" + "e" * 64)},
            {"verified_spdx": envelopes(SPDX, self.spdx[:1])},
        ):
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                self.qualify(**overrides)

    def test_core_buildtype_or_builder_mutation_denied(self):
        changed = copy.deepcopy(self.projection)
        changed[0]["buildDefinition"]["buildType"] = "different"
        with self.assertRaises(legacy.LegacyProofError):
            self.qualify(verified_slsa=envelopes(SLSA, changed))
        changed = copy.deepcopy(self.projection)
        changed[0]["runDetails"]["builder"]["id"] = "forged"
        with self.assertRaises(legacy.LegacyProofError):
            self.qualify(verified_slsa=envelopes(SLSA, changed))

    def test_empty_and_null_equivalence_per_slsa_v1(self):
        raw = copy.deepcopy(self.raw)
        raw[0]["runDetails"]["metadata"]["finishedOn"] = None
        signed = copy.deepcopy(self.projection)
        signed[0]["runDetails"]["metadata"]["finishedOn"] = ""
        self.assertEqual(legacy.project(raw[0], "provenance"),
                         legacy.project(signed[0], "provenance"))
        # Even schema-equivalent changes are not silently accepted against
        # pinned full historical evidence.
        with self.assertRaises(legacy.LegacyProofError):
            self.qualify(embedded_slsa=raw,
                         verified_slsa=envelopes(SLSA, signed))

    def test_signed_or_embedded_full_content_changed_but_schema_same_denied(self):
        raw = copy.deepcopy(self.raw)
        raw[0]["unknownHistoricalExtra"] = "changed"
        with self.assertRaises(legacy.LegacyProofError):
            self.qualify(embedded_slsa=raw)
        signed = copy.deepcopy(self.projection)
        signed[0]["unknownHistoricalExtra"] = "forged"
        with self.assertRaises(legacy.LegacyProofError):
            self.qualify(verified_slsa=envelopes(SLSA, signed))

    def test_historical_fingerprint_allowlist_has_exact_four_indices(self):
        self.assertEqual(set(legacy.HISTORIC_SLSA_FINGERPRINTS),
                         legacy.LEGACY_INDICES)
        for hashes in legacy.HISTORIC_SLSA_FINGERPRINTS.values():
            self.assertEqual(set(hashes), {"embedded", "signed"})
            for pair in hashes.values():
                self.assertEqual(len(pair), 2)
                self.assertTrue(all(len(d) == 64 for d in pair))

    def test_dual_native_required(self):
        with self.assertRaises(legacy.LegacyProofError):
            self.qualify(embedded_slsa=self.raw[:1])


if __name__ == "__main__":
    unittest.main()
