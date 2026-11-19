"""Read-only dual-architecture GHCR attestation proof and negative controls."""
from __future__ import annotations

import base64
import copy
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from verify_registry_arch_attestations import (  # noqa: E402
    RegistryProofError, IMAGE, SLSA, SPDX, TRIM_NOTE,
    native_index, trim_spdx, verify, run_cli, parse_verified_signature, main,
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
        self.signer_tag = TAG
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
        if args[:2] == ["cosign", "verify"]:
            self.assertIn("https://github.com/baobab-platform/baobab-dev/"
                          ".github/workflows/publish.yml@refs/tags/" + self.signer_tag, args)
            self.assertEqual(args[-1], REF)
            return json.dumps([{"critical": {"image": {
                "docker-manifest-digest": INDEX
            }}}])
        if args[:2] == ["cosign", "verify-attestation"]:
            self.assertIn("https://github.com/baobab-platform/baobab-dev/"
                          ".github/workflows/publish.yml@refs/tags/" + self.signer_tag, args)
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
        self.assertEqual(proof["image_signature_evidence"]["status"], "VERIFIED")
        self.assertEqual(proof["image_signature_evidence"]["subject_digest"], INDEX)
        self.assertEqual(len([x for x in self.commands if x[:2] ==
                              ["cosign", "verify-attestation"]]), 2)
        self.assertEqual(len([x for x in self.commands if x[:2] ==
                              ["cosign", "verify"]]), 1)
        self.assertFalse(any("tag" in cmd or "push" in cmd or "sign" == cmd[1]
                             for cmd in self.commands))

    def test_each_approved_rc_requires_full_native_signed_content(self):
        for rc in ("v1.5.0-rc.1", "v1.5.0-rc.2", "v1.5.0-rc.10", "v1.5.2-rc.1", "v1.5.2-rc.10"):
            with self.subTest(rc=rc):
                self.current_tag = rc
                self.signer_tag = rc
                self.commands.clear()
                proof = verify(REF, rc, SHA, self.runner)
                self.assertEqual(proof["status"], "STRICT_SIGNED_NATIVE_CONTENT_VERIFIED")
                self.assertEqual(proof["release_tag"], rc)
                self.assertFalse(any("tag" in cmd or "push" in cmd
                                     for cmd in self.commands))

    def test_ga_reuse_verifies_exact_same_version_rc_signer(self):
        self.current_tag = "v1.5.1"
        self.signer_tag = "v1.5.1-rc.2"
        proof = verify(REF, self.current_tag, SHA, self.runner,
                       signer_tag=self.signer_tag)
        self.assertEqual(proof["release_tag"], "v1.5.1")
        self.assertEqual(proof["signer_tag"], "v1.5.1-rc.2")

    def test_ga_rejects_cross_version_or_wrong_rc_signer(self):
        for release_tag, signer_tag in (
            ("v1.5.1", "v1.5.0-rc.2"),
            ("v1.5.1", "v1.5.2-rc.1"),
            ("v1.5.1-rc.1", "v1.5.1-rc.2"),
        ):
            with self.subTest(release_tag=release_tag, signer_tag=signer_tag):
                with self.assertRaises(RegistryProofError):
                    verify(REF, release_tag, SHA, self.runner,
                           signer_tag=signer_tag)

    def test_cli_failure_diagnostics_are_classified_and_secret_safe(self):
        cases = [
            ("no matching signatures for digest; Bearer super-secret",
             "signature_or_referrer_not_found"),
            ("no matching certificates found for issuer https://private.example",
             "oidc_identity_or_issuer_mismatch"),
            ("certificate identity mismatch for https://private.example",
             "oidc_identity_or_issuer_mismatch"),
            ("unknown flag --type; token=secret-value",
             "cosign_cli_or_predicate_incompatible"),
            ("no matching attestations for predicate type https://private.example",
             "cosign_predicate_type_mismatch"),
            ("429 too many requests from ghcr.io/private/path",
             "registry_rate_limited"),
            ("connection reset by peer while fetching private registry referrer",
             "transient_registry_or_network_failure"),
        ]
        for stderr, expected in cases:
            with self.subTest(expected=expected):
                failed = SimpleNamespace(returncode=1, stdout="", stderr=stderr)
                with patch("verify_registry_arch_attestations.subprocess.run", return_value=failed):
                    with self.assertRaises(RegistryProofError) as raised:
                        run_cli(["cosign", "verify-attestation", "--type", "slsaprovenance1"])
                diagnostic = raised.exception.diagnostic
                self.assertEqual(diagnostic["error_code"], expected)
                self.assertEqual(diagnostic["command_category"], "cosign_verify_attestation")
                self.assertEqual(diagnostic["exit_status"], 1)
                rendered = json.dumps(diagnostic) + str(raised.exception)
                self.assertNotIn("super-secret", rendered)
                self.assertNotIn("secret-value", rendered)
                self.assertNotIn("private.example", rendered)
                self.assertNotIn("private/path", rendered)
                self.assertNotIn("Bearer", rendered)

    def test_cli_timeout_and_tool_errors_are_structured(self):
        with patch("verify_registry_arch_attestations.subprocess.run",
                   side_effect=__import__("subprocess").TimeoutExpired(["cosign", "verify"], 120)):
            with self.assertRaises(RegistryProofError) as raised:
                run_cli(["cosign", "verify"])
        self.assertEqual(raised.exception.diagnostic["error_code"],
                         "transient_registry_or_network_failure")
        with patch("verify_registry_arch_attestations.subprocess.run",
                   side_effect=FileNotFoundError("secret path /private/tool")):
            with self.assertRaises(RegistryProofError) as raised:
                run_cli(["cosign", "verify"])
        self.assertEqual(raised.exception.diagnostic["error_code"], "verifier_tool_unavailable")
        self.assertNotIn("/private/tool", str(raised.exception))

    def test_signature_subject_digest_is_checked(self):
        good = json.dumps([{"critical": {"image": {"docker-manifest-digest": INDEX}}}])
        self.assertEqual(parse_verified_signature(good, INDEX)["status"], "VERIFIED")
        bad = json.dumps([{"critical": {"image": {"docker-manifest-digest": digest("f")}}}])
        with self.assertRaisesRegex(RegistryProofError, "subject differs"):
            parse_verified_signature(bad, INDEX)
        with self.assertRaisesRegex(RegistryProofError, "no verified signatures"):
            parse_verified_signature("[]", INDEX)

    def test_historical_ga_failure_is_named_and_does_not_become_strict(self):
        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp) / "evidence.json"
            argv = [
                "verify_registry_arch_attestations.py",
                "--image", REF, "--tag", "v1.5.1",
                "--signer-tag", "v1.5.1-rc.2", "--expected-sha", SHA,
                "--evidence", str(evidence),
            ]
            with patch("sys.argv", argv), patch(
                "verify_registry_arch_attestations.verify",
                side_effect=RegistryProofError(
                    "read-only remote verification failed: cosign_verify_attestation/signature_or_referrer_not_found (exit 1)",
                    {"command_category": "cosign_verify_attestation",
                     "command_operation": "verify-attestation", "exit_status": 1,
                     "error_code": "signature_or_referrer_not_found",
                     "safe_stderr": "Expected signature, attestation or registry referrer not found"},
                )
            ), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(), 1)
            report = json.loads(evidence.read_text())
            self.assertEqual(report["status"], "HISTORICAL_BASELINE_UNQUALIFIED")
            self.assertEqual(report["failure"]["error_code"], "signature_or_referrer_not_found")
            self.assertNotIn("STRICT_SIGNED_NATIVE_CONTENT_VERIFIED", report["status"])

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
            (REF, "v1.5.1-rc.01", SHA),
            (REF, TAG, "invalid"),
            ("ghcr.io/evil/image@" + INDEX, TAG, SHA),
        ):
            with self.subTest(ref=ref, tag=tag), self.assertRaises(RegistryProofError):
                verify(ref, tag, sha, self.runner)


if __name__ == "__main__":
    unittest.main()
