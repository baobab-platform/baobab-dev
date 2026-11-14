"""Exact release signer selection for RC and digest-reused GA releases."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from resolve_release_signer import (SignerResolutionError, resolve_signer,\n                                    validate_qualified_run)


SHA = "a" * 40
OTHER = "b" * 40


class ReleaseSignerTests(unittest.TestCase):
    def test_rc_signs_its_own_exact_tag(self):
        self.assertEqual(resolve_signer("v1.5.2-rc.3", SHA, [],
                                        lambda tag: SHA), "v1.5.2-rc.3")

    def test_ga_resolves_unique_rc_at_same_source_sha(self):
        self.assertEqual(resolve_signer(
            "v1.5.1", SHA,
            ["v1.5.1-rc.1", "v1.5.1-rc.2", "v1.5.0-rc.9"],
            lambda tag: SHA if tag == "v1.5.1-rc.2" else OTHER),
            "v1.5.1-rc.2")

    def test_declared_signer_tag_is_verified_against_exact_source(self):
        self.assertEqual(resolve_signer("v1.5.1", SHA, [],
                                        lambda tag: SHA,
                                        preferred_tag="v1.5.1-rc.2"),
                         "v1.5.1-rc.2")
        with self.assertRaises(SignerResolutionError):
            resolve_signer("v1.5.1", SHA, [],
                           lambda tag: SHA, preferred_tag="v1.5.0-rc.2")
        with self.assertRaises(SignerResolutionError):
            resolve_signer("v1.5.1-rc.1", SHA, [],
                           lambda tag: SHA, preferred_tag="v1.5.1-rc.2")

    def test_actual_actions_run_shape_is_required(self):
        run = {"id": 123, "status": "completed", "conclusion": "success",
               "event": "push", "head_branch": "v1.5.1-rc.2",
               "head_sha": SHA,
               "path": ".github/workflows/publish.yml@refs/tags/v1.5.1-rc.2"}
        self.assertEqual(validate_qualified_run(run, "v1.5.1-rc.2", SHA, 123), 123)
        for change in ({"conclusion": "failure"}, {"status": "in_progress"},
                       {"event": "workflow_dispatch"}, {"head_branch": "v1.5.1-rc.1"},
                       {"head_sha": OTHER}, {"path": ".github/workflows/other.yml"},
                       {"id": True}):
            with self.subTest(change=change), self.assertRaises(SignerResolutionError):
                validate_qualified_run({**run, **change}, "v1.5.1-rc.2", SHA, 123)
        with self.assertRaises(SignerResolutionError):
            validate_qualified_run(run, "v1.5.1-rc.2", SHA, 124)

    def test_ga_without_matching_rc_is_denied(self):
        with self.assertRaises(SignerResolutionError):
            resolve_signer("v1.5.1", SHA, ["v1.5.1-rc.1"],
                           lambda tag: OTHER)

    def test_ambiguous_rc_tags_are_denied(self):
        with self.assertRaises(SignerResolutionError):
            resolve_signer("v1.5.1", SHA,
                           ["v1.5.1-rc.1", "v1.5.1-rc.2"],
                           lambda tag: SHA)

    def test_foreign_version_and_malformed_rc_are_ignored(self):
        with self.assertRaises(SignerResolutionError):
            resolve_signer("v1.5.1", SHA,
                           ["v1.5.0-rc.2", "v1.5.1-rc.01", "v1.5.2-rc.1"],
                           lambda tag: SHA)

    def test_wrong_rc_source_is_denied(self):
        with self.assertRaises(SignerResolutionError):
            resolve_signer("v1.5.2-rc.3", SHA, [],
                           lambda tag: OTHER)

    def test_invalid_source_sha_is_denied(self):
        with self.assertRaises(SignerResolutionError):
            resolve_signer("v1.5.1", "not-a-sha", ["v1.5.1-rc.2"],
                           lambda tag: SHA)


if __name__ == "__main__":
    unittest.main()
