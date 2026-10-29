"""Temporary .trivyignore exceptions must not hide already-patchable CLIs.

The repository uses the legacy global-ID format. A short-lived exception
therefore requires stricter owner-pin checks than a path-scoped YAML rule.
"""
from datetime import date
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    "CVE-2026-109869",
    "CVE-2026-111943",
    "CVE-2026-78667",
    "CVE-2026-78669",
    "CVE-2026-97031",
}
EXPIRES = date(2026, 10, 29)
REQUIRED_PINS = {
    "GH_VERSION": "2.102.1",
    "GH_ASSET_AMD64": "gh_2.102.1_linux_amd64.tar.gz",
    "GH_SHA256_AMD64": "77b9e297e94c50336823d0f84de7ef1be60cba704601fa0d98f129f47a94987b",
    "GH_ASSET_ARM64": "gh_2.102.1_linux_arm64.tar.gz",
    "GH_SHA256_ARM64": "5019b3cc6e8a03bb4d88600f8dbda2add8e6407705c159b0c63151036e77a1af",
    "TERRAFORM_VERSION": "1.16.7",
    "TERRAFORM_ASSET_AMD64": "terraform_1.16.7_linux_amd64.zip",
    "TERRAFORM_SHA256_AMD64": "5454efcf7fc87f0c2113111b9a5c7182f0ca1c6f0f23a1e110a50770a8fe473b",
    "TERRAFORM_ASSET_ARM64": "terraform_1.16.7_linux_arm64.zip",
    "TERRAFORM_SHA256_ARM64": "2d6a3f1098de94f1672aaa4e6873ef91ade9eac38851d3a403e2009193208de4",
}


def read_ignore():
    ids = {}
    for line in (ROOT / ".trivyignore").read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Z]+-[0-9a-zA-Z-]+) exp:(\d{4}-\d{2}-\d{2})", line)
        if match is None:
            raise ValueError("UNBOUNDED_OR_MALFORMED_TRIVY_EXCEPTION")
        key, until = match.groups()
        if key in ids:
            raise ValueError("DUPLICATE_TRIVY_EXCEPTION")
        ids[key] = date.fromisoformat(until)
    return ids


class TemporaryTrivyExceptions(unittest.TestCase):
    def test_temporary_exceptions_expire_without_extension(self):
        rules = read_ignore()
        self.assertLessEqual(EXPECTED, set(rules))
        self.assertTrue(date.today() <= EXPIRES, "TEMPORARY_TRIVY_EXCEPTIONS_EXPIRED")
        for key in EXPECTED:
            self.assertEqual(rules[key], EXPIRES, f"DO_NOT_SILENTLY_EXTEND_{key}")

    def test_legacy_exceptions_have_expiry_and_are_unique(self):
        rules = read_ignore()
        self.assertTrue(rules)
        self.assertTrue(all(expires >= date.today() for expires in rules.values()))

    def test_patched_binaries_remain_pinned_during_global_exception(self):
        lock = dict(
            line[len("export "):].split("=", 1)
            for line in (ROOT / "config/versions.lock").read_text().splitlines()
            if line.startswith("export ") and "=" in line
        )
        for key, expected in REQUIRED_PINS.items():
            self.assertEqual(lock.get(key), expected, f"SECURITY_PIN_DRIFT_{key}")
        manifest = (ROOT / "config/versions.yaml").read_text()
        self.assertRegex(manifest, r"github_cli:\s*(?:#[^\n]*\n\s*)*version: \"2\.102\.1\"")
        self.assertRegex(manifest, r"terraform:\s*(?:#[^\n]*\n\s*)*version: \"1\.16\.7\"")


if __name__ == "__main__":
    unittest.main()
