"""DEV-10 R5 signature-content qualification, without live GHCR publishing."""
import base64
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_signed_release_predicates",
    ROOT / "scripts/verify_signed_release_predicates.py")
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)

PROVENANCE = "https://slsa.dev/provenance/v1"
SBOM = "https://spdx.dev/Document"


def verified(kind, predicates):
    records = []
    for predicate in predicates:
        statement = {"_type": "https://in-toto.io/Statement/v1",
                     "predicateType": kind, "predicate": predicate,
                     "subject": [{"name": "image", "digest": {"sha256": "a" * 64}}]}
        payload = base64.b64encode(json.dumps(statement).encode()).decode()
        records.append({"payload": payload, "payloadType": "application/vnd.in-toto+json"})
    return json.dumps(records)


class SignedPredicateTests(unittest.TestCase):
    def setUp(self):
        self.provenance = [
            {"buildDefinition": {"externalParameters": {"architecture": arch}}}
            for arch in ("amd64", "arm64")
        ]
        self.sbom = [
            {"SPDXID": "SPDXRef-DOCUMENT", "packages": [{"name": "dep-" + arch}]}
            for arch in ("amd64", "arm64")
        ]

    def qualify(self, p=None, s=None, p_signed=None, s_signed=None):
        return mod.qualify(
            self.provenance, self.sbom,
            p_signed if p_signed is not None else verified(PROVENANCE, self.provenance),
            s_signed if s_signed is not None else verified(SBOM, self.sbom),
        )

    def test_both_distinct_architectures_required(self):
        result = self.qualify()
        for kind in ("SLSA provenance", "SPDX SBOM"):
            self.assertEqual(result["kinds"][kind]["verified_signed_statements"], 2)
            self.assertNotEqual(result["kinds"][kind]["amd64_sha256"],
                                result["kinds"][kind]["arm64_sha256"])

    def test_replaced_or_duplicate_architecture_refused(self):
        for p in (
            verified(PROVENANCE, [self.provenance[0]]),
            verified(PROVENANCE, [self.provenance[0], self.provenance[0]]),
            verified(PROVENANCE, [self.provenance[0], {"foreign": "unsigned"}]),
            verified(SBOM, self.provenance),
        ):
            with self.subTest(payload=p), self.assertRaises(mod.PredicateError):
                self.qualify(p_signed=p)
        with self.assertRaises(mod.PredicateError):
            mod.qualify([self.provenance[0], self.provenance[0]], self.sbom,
                        verified(PROVENANCE, self.provenance), verified(SBOM, self.sbom))

    def test_signed_statement_subject_is_exact_index_not_another_image(self):
        expected = "sha256:" + "a" * 64
        good = mod.qualify(self.provenance, self.sbom,
                           verified(PROVENANCE, self.provenance),
                           verified(SBOM, self.sbom),
                           expected_subject=expected)
        self.assertEqual(good["kinds"]["SLSA provenance"]["verified_signed_statements"], 2)
        for bad in ("sha256:" + "b" * 64, "sha256:bad", "", "a" * 64):
            with self.subTest(bad=bad), self.assertRaises(mod.PredicateError):
                mod.qualify(self.provenance, self.sbom,
                            verified(PROVENANCE, self.provenance),
                            verified(SBOM, self.sbom),
                            expected_subject=bad)

    def test_unsigned_or_unreadable_output_refused(self):
        for data in ("", "[]", "{}", '{"payload":"@@@"}', "not json"):
            with self.subTest(data=data), self.assertRaises(mod.PredicateError):
                self.qualify(p_signed=data)
        with self.assertRaises(mod.PredicateError):
            self.qualify(s_signed=verified(SBOM, self.sbom[:1]))


if __name__ == "__main__":
    unittest.main()
