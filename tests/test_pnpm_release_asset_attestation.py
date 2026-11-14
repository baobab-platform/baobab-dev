from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_pnpm_release_assets.sh"
VERSION = "12.21.0"
ASSETS = {
    "pnpm-linux-x64.tar.gz": b"publisher-pnpm-x64-fixture",
    "pnpm-linux-arm64.tar.gz": b"publisher-pnpm-arm64-fixture",
}
DIGESTS = {name: hashlib.sha256(data).hexdigest() for name, data in ASSETS.items()}


class PnpmReleaseAssetAttestationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.log = self.root / "gh-attestations.log"
        self.write_executable(
            self.bin / "gh",
            """#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == "version" ]]; then
  echo "gh version ${FAKE_GH_VERSION:-2.102.1} (test)"
  exit 0
fi
printf '%s\\n' "$*" >> "$GH_ATTESTATION_LOG"
[[ "${FAKE_GH_ATTESTATION_FAIL:-0}" != "1" ]]
""",
        )
        self.write_executable(
            self.bin / "curl",
            """#!/usr/bin/env bash
set -euo pipefail
out=""
url=""
while (($#)); do
  case "$1" in
    --output) out="$2"; shift 2 ;;
    https://*) url="$1"; shift ;;
    *) shift ;;
  esac
done
[[ -n "$out" && -n "$url" ]]
case "$url" in
  *pnpm-linux-x64.tar.gz) printf '%s' 'publisher-pnpm-x64-fixture' > "$out" ;;
  *pnpm-linux-arm64.tar.gz) printf '%s' 'publisher-pnpm-arm64-fixture' > "$out" ;;
  *) exit 22 ;;
esac
""",
        )
        self.env = {
            **os.environ,
            "PATH": str(self.bin) + os.pathsep + os.environ.get("PATH", ""),
            "GH_ATTESTATION_LOG": str(self.log),
        }

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def write_executable(path: Path, content: str):
        path.write_text(content)
        path.chmod(0o755)

    def run_verifier(self, amd64=None, arm64=None, **extra_env):
        env = {**self.env, **extra_env}
        return subprocess.run(
            ["bash", str(SCRIPT), VERSION,
             amd64 or DIGESTS["pnpm-linux-x64.tar.gz"],
             arm64 or DIGESTS["pnpm-linux-arm64.tar.gz"]],
            text=True, capture_output=True, env=env, check=False,
        )

    def test_both_assets_require_exact_publisher_attestation_and_sha256(self):
        result = self.run_verifier()
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.log.read_text().splitlines()
        self.assertEqual(len(calls), 2)
        for call, asset in zip(calls, ASSETS):
            self.assertIn(asset, call)
            self.assertIn("--repo pnpm/pnpm", call)
            self.assertIn("--signer-workflow pnpm/pnpm/.github/workflows/release.yml", call)
            self.assertIn("--source-ref refs/tags/v12.21.0", call)
            self.assertIn("--predicate-type https://slsa.dev/provenance/v1", call)
        self.assertIn("signed publisher provenance", result.stderr)

    def test_old_gh_cli_is_denied_before_any_download(self):
        result = self.run_verifier(FAKE_GH_VERSION="2.101.9")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("GitHub CLI >=2.102.0", result.stderr)
        self.assertFalse(self.log.exists())

    def test_failed_attestation_is_not_replaced_by_checksum_success(self):
        result = self.run_verifier(FAKE_GH_ATTESTATION_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.log.exists())
        self.assertEqual(len(self.log.read_text().splitlines()), 1)

    def test_manifest_checksum_must_match_attested_asset_bytes(self):
        result = self.run_verifier(amd64="0" * 64)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SHA-256 mismatch", result.stderr)
        self.assertEqual(len(self.log.read_text().splitlines()), 1)

    def test_noncanonical_version_and_malformed_digest_are_rejected(self):
        result = subprocess.run(
            ["bash", str(SCRIPT), "12.021.0", DIGESTS["pnpm-linux-x64.tar.gz"],
             DIGESTS["pnpm-linux-arm64.tar.gz"]],
            text=True, capture_output=True, env=self.env, check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("canonical stable SemVer", result.stderr)
        self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
