"""DEV-10 release tag policy: future versions, invalid tags and channels."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/release_tag_policy.py"
spec = importlib.util.spec_from_file_location("release_tag_policy", SCRIPT)
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class ReleaseTagPolicyTests(unittest.TestCase):
    def test_ga_versions(self):
        for tag in ("v0.0.0", "v1.5.0", "v2.0.0", "v10.3.12"):
            with self.subTest(tag=tag):
                self.assertEqual(policy.classify(tag), "ga")

    def test_future_release_candidates(self):
        for tag in ("v1.5.0-rc.5", "v2.0.0-rc.1", "v10.3.12-rc.999"):
            with self.subTest(tag=tag):
                self.assertEqual(policy.classify(tag), "rc")

    def test_invalid_tags_fail_closed(self):
        for tag in ("", "v01.5.0", "v1.05.0", "v1.5.00", "v1.5.0-rc.0",
                    "v1.5.0-rc.01", "v2.0.0-beta.1", "v2.0.0-rc.1-extra",
                    "v2.0.0+build.1", "v1.2", "v1.2.3.4", "v1.2.x",
                    "v1.2.3\n", "refs/tags/v2.0.0", "v1.2.3;echo bad"):
            with self.subTest(tag=tag):
                self.assertIsNone(policy.classify(tag))

    def test_cli_channel_enforcement(self):
        for tag, kind, expected in (
            ("v2.0.0", "ga", 0), ("v2.0.0-rc.1", "rc", 0),
            ("v2.0.0", "rc", 2), ("v2.0.0-rc.1", "ga", 2),
            ("v02.0.0", "any", 2),
        ):
            with self.subTest(tag=tag, kind=kind):
                result = subprocess.run([sys.executable, str(SCRIPT),
                                         "--tag", tag, "--kind", kind],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, expected, result.stderr)


if __name__ == "__main__":
    unittest.main()
