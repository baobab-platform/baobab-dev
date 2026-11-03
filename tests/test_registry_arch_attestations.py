"""Read-only dual-architecture GHCR attestation proof and negative controls."""
from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from verify_registry_arch_attestations import (  # noqa: E402
    RegistryProofError, IMAGE, SLSA, SPDX, TRIM_NOTE,
    native_index, trim_spdx, verify,
)

TAG = "v1.5.0"
SHA = "9" * 40
INDEX = "sha256:" + "0" * 64
REF = IMAGE + "@" + INDEX


def digest(char: str) -> str:
    return "sha256:" + char * 64


def signed(predicate_type, predicates):
    records = []
    for predicate in predicates:
        value = {"_type": "https://in-toto.io/Statement/v1",
                 "predicateType": predicate_type,
                 "subject": [{"name": IMAGE, "digest": {"sha256": INDEX[7:]}}],
                 "predicate": predicate}
        records.append({"payload": base64.b64encode(json.dumps(value).encode()).decode(),
                        "payloadType": "application/vnd.in-toto+json"})
    return json.dumps(records)


class ReadOnlyRegistryProofTests(unittest.TestCase):
    def setUp(self):
        self.current_tag = TAG
        self.child = {"amd64": digest("a"), "arm64": digest("b")}
        self.sibling = {"amd64": digest("c"), "arm64": digest("d")}
        self.raw = {}
        self.slsa = {}
        self.sbom = {}
        self.layers = {}
        self.commands = []
        descriptors = []
        for arch in ("amd64", "arm64"):
            descriptors.extend((
                {"digest": self.child[arch],
                 "platform": {"os": "linux", "architecture": arch}},
                {"digest": self.sibling[arch],
                 "platform": {"os": "unknown", "architecture": "unknown"},
                 "annotations": {"vnd.docker.reference.type": "attestation-manifest",
                                 "vnd.docker.reference.digest": self.child[arch]}},
            ))
            self.slsa[arch] = {"buildDefinition": {"externalParameters": {"arch": arch}}}
            self.raw[arch] = {
                "SPDXID": "SPDXRef-DOCUMENT",
                "packages": [{"name": "package-" + arch}],
                "files": [{"SPDXID": "SPDXRef-File-1"}],
                "relationships": [
                    {"spdxElementId": "SPDXRef-DOCUMENT",
                     "relatedSpdxElement": "SPDXRef-File-1"},
                    {"spdxElementId": "SPDXRef-DOCUMENT",
                     "relatedSpdxElement": "SPDXRef-Package"},
                ],
            }
            self.sbom[arch] = trim_spdx(self.raw[arch])
            self.layers[arch] = {
                "layers": [
                    {"digest": digest("e" if arch == "amd64" else "1"),
                     "annotations": {"in-toto.io/predicate-type": SLSA}},
                    {"digest": digest("f" if arch == "amd64" else "2"),
                     "annotations": {"in-toto.io/predicate-type": SPDX}},
                ]
            }
        self.index = {"schemaVersion": 2, "manifests": descriptors}

    def runner(self, args):
        self.commands.append(args)
        if args[:2] == ["crane", "manifest"]:
            if args[2] == REF:
                return json.dumps(self.index)
            for arch in self.child:
                if args[2] == IMAGE + "@" + self.child[arch]:
                    return json.dumps({"schemaVersion": 2, "layers": [{"digest": digest("8")}]})
                if args[2] == IMAGE + "@" + self.sibling[arch]:
                    return json.dumps(self.layers[arch])
        if args[:2] == ["crane", "config"]:
            for arch in self.child:
                if args[2] == IMAGE + "@" + self.child[arch]:
                    return json.dumps({"config": {"Labels": {
                        "org.opencontainers.image.revision": SHA}}})
        if args[:2] == ["crane", "blob"]:
            for arch in self.child:
                for kind, value, predicate in (
                    (SLSA, "e" if arch == "amd64" else "1", self.slsa[arch]),
                    (SPDX, "f" if arch == "amd64" else "2", self.raw[arch]),
                ):
                    if args[2] == IMAGE + "@" + digest(value):
                        return json.dumps({"predicateType": kind, "predicate": predicate})
        if args[:2] == ["cosign", "verify-attestation"]:
            self.assertIn("https://github.com/baobab-platform/baobab-dev/"
                          ".github/workflows/publish.yml@refs/tags/" + self.current_tag, args)
            self.assertEqual(args[-1], REF)
            kind = args[args.index("--type") + 1]
            if kind == "slsaprovenance1":
                return signed(SLSA, [self.slsa[a] for a in ("amd64", "arm64")])
            if kind == "spdxjson":
                return signed(SPDX, [self.sbom[a] for a in ("amd64", "arm64")])
        raise AssertionError("unexpected verifier command: " + str(args))

    def test_exact_signed_native_registry_pass_and_no_write_commands(self):
        proof = verify(REF, TAG, SHA, self.runner)
        self.assertEqual(set(proof["native"]), {"amd64", "arm64"})
        for arch in self.child:
            self.assertEqual(proof["native"][arch]["revision"], SHA)
        self.assertEqual(len([x for x in self.commands if x[:2] ==
                              ["cosign", "verify-attestation"]]), 2)
        self.assertFalse(any("tag" in cmd or "push" in cmd or "sign" == cmd[1]
                             for cmd in self.commands))

    def test_each_approved_rc_requires_full_native_signed_content(self):
        for rc in ("v1.5.0-rc.1", "v1.5.0-rc.2", "v1.5.0-rc.10"):
            with self.subTest(rc=rc):
                self.current_tag = rc
                self.commands.clear()
                proof = verify(REF, rc, SHA, self.runner)
                self.assertEqual(proof["status"], "STRICT_SIGNED_NATIVE_CONTENT_VERIFIED")
                self.assertEqual(proof["release_tag"], rc)
                self.assertFalse(any("tag" in cmd or "push" in cmd
                                     for cmd in self.commands))

    def test_complete_index_required(self):
        self.assertEqual(len(native_index(self.index)), 2)
        for mutation in (
            lambda idx: idx["manifests"].pop(),
            lambda idx: idx["manifests"].append({"digest": digest("7")}),
            lambda idx: idx["manifests"][1]["annotations"].update(
                {"vnd.docker.reference.digest": digest("7")}),
            lambda idx: idx["manifests"][2].update(
                {"digest": self.child["amd64"]}),
        ):
            index = copy.deepcopy(self.index)
            mutation(index)
            with self.subTest(index=index), self.assertRaises(RegistryProofError):
                native_index(index)

    def test_trim_preserves_complete_packages_but_removes_file_entries(self):
        trimmed = trim_spdx(self.raw["amd64"])
        self.assertEqual(trimmed["packages"], self.raw["amd64"]["packages"])
        self.assertEqual(trimmed["relationships"],
                         [self.raw["amd64"]["relationships"][1]])
        self.assertNotIn("files", trimmed)
        self.assertEqual(trimmed["comment"], TRIM_NOTE)

    def test_mutated_signed_sbom_or_missing_provenance_blocks(self):
        original = self.runner

        def forged(args):
            if args[:2] == ["cosign", "verify-attestation"] and args[3] == "spdxjson":
                fake = copy.deepcopy(self.sbom)
                fake["arm64"]["packages"] = [{"name": "wrong"}]
                return signed(SPDX, [fake[a] for a in ("amd64", "arm64")])
            return original(args)
        with self.assertRaises(ValueError):
            verify(REF, TAG, SHA, forged)

        def absent(args):
            if args[:2] == ["crane", "manifest"] and args[2] == IMAGE + "@" + self.sibling["arm64"]:
                out = copy.deepcopy(self.layers["arm64"])
                out["layers"] = out["layers"][:1]
                return json.dumps(out)
            return original(args)
        with self.assertRaises(RegistryProofError):
            verify(REF, TAG, SHA, absent)

    def test_signed_attestation_for_another_index_is_rejected(self):
        original = self.runner

        def substituted(args):
            if args[:2] == ["cosign", "verify-attestation"] and args[3] == "slsaprovenance1":
                payload = json.loads(original(args))
                for record in payload:
                    statement = json.loads(base64.b64decode(record["payload"]))
                    statement["subject"][0]["digest"]["sha256"] = "f" * 64
                    record["payload"] = base64.b64encode(
                        json.dumps(statement).encode()).decode()
                return json.dumps(payload)
            return original(args)

        with self.assertRaises(RegistryProofError):
            verify(REF, TAG, SHA, substituted)

    def test_invalid_image_identity_and_tag_refuse_before_network(self):
        for ref, tag, sha in (
            (IMAGE + ":1.5.0", TAG, SHA),
            (REF, "v1.5.0-rc.0", SHA),
            (REF, "v1.5.0-rc.01", SHA),
            (REF, "v1.5.1-rc.1", SHA),
            (REF, TAG, "invalid"),
            ("ghcr.io/evil/image@" + INDEX, TAG, SHA),
        ):
            with self.subTest(ref=ref, tag=tag), self.assertRaises(RegistryProofError):
                verify(ref, tag, sha, self.runner)


if __name__ == "__main__":
    unittest.main()
