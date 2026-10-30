"""Security rebuilds may not reactivate historical vulnerability suppressions."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
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


class TemporaryTrivyExceptions(unittest.TestCase):
    def test_no_active_suppression_rules(self):
        active = [line for line in (ROOT / ".trivyignore").read_text().splitlines()
                  if line.strip() and not line.lstrip().startswith("#")]
        self.assertEqual(active, [], "VULNERABILITY_SUPPRESSIONS_ARE_NOT_PERMITTED")

    def test_previously_patched_binaries_remain_pinned(self):
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
