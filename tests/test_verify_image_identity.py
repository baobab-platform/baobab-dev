"""DEV-10 R5: Cosign must validate the exact release-workflow identity.

Uses a mock CLI to inspect arguments; it does not substitute for a genuine
Sigstore/GHCR verification on a live signed release.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify-image.sh"
EXPECTED = (
    "https://github.com/baobab-platform/baobab-dev/"
    ".github/workflows/publish.yml@refs/tags/v1.5.0"
)
DIGEST_REF = "ghcr.io/baobab-platform/baobab-dev@sha256:" + "a" * 64


class SigningIdentityContractTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        cosign = self.root / "cosign"
        cosign.write_text(
            "#!/bin/sh\n"
            'printf "%s\\n" "$*" >> "$MOCK_COSIGN_LOG"\n'
            "exit 0\n"
        )
        cosign.chmod(0o700)
        self.log = self.root / "cosign.txt"
        self.env = {
            **os.environ,
            "PATH": f"{self.root}:{os.environ['PATH']}",
            "MOCK_COSIGN_LOG": str(self.log),
        }

    def verify(self, *args):
        return subprocess.run(
            ["bash", str(SCRIPT), *args],
            env=self.env, text=True, capture_output=True, check=False
        )

    def test_three_distinct_verifiers_use_exact_signer_identity(self):
        result = self.verify(DIGEST_REF, "v1.5.0")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.log.read_text().splitlines()
        self.assertEqual(len(calls), 3)
        for command in calls:
            self.assertIn(f"--certificate-identity {EXPECTED}", command)
            self.assertNotIn("--certificate-identity-regexp", command)
            self.assertIn(
                "--certificate-oidc-issuer https://token.actions.githubusercontent.com",
                command
            )
            self.assertIn(DIGEST_REF, command)
        self.assertEqual(sum("verify-attestation" in x for x in calls), 2)

    def test_digest_without_explicit_release_tag_denied(self):
        result = self.verify(DIGEST_REF)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Specify the verified stable release tag", result.stderr)
        self.assertFalse(self.log.exists())

    def test_prerelease_tag_denied(self):
        result = self.verify(DIGEST_REF, "v1.5.0-rc.1")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.log.exists())

    def test_mutable_tag_infers_stable_release_identity(self):
        result = self.verify("ghcr.io/baobab-platform/baobab-dev:1.5.0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(EXPECTED, self.log.read_text())


if __name__ == "__main__":
    unittest.main()
