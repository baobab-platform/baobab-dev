"""Offline release-tag source checks never turn path presence into CVE clearance."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("ubuntu_git", root / "scripts/audit_ubuntu_kernel_git_paths.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class UbuntuSourceVerificationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        def git(*args):
            return subprocess.run(["git", "-C", str(self.repo), *args],
                                  check=True, capture_output=True)
        git("init", "-q")
        git("config", "user.name", "DEV10 Test")
        git("config", "user.email", "dev10-test@example.invalid")
        (self.repo / "drivers").mkdir()
        (self.repo / "drivers" / "example.c").write_text("/* fixture */\n")
        (self.repo / "include" / "linux").mkdir(parents=True)
        (self.repo / "include" / "linux" / "example.h").write_text("/* private fixture */\n")
        git("add", ".")
        git("commit", "-qm", "fixture kernel source")
        git("tag", m.RELEASE_TAG)
        git("remote", "add", "origin", m.SOURCE_REPO)
        self.upstream = {
            "package": "linux-libc-dev=" + m.RELEASE_VERSION,
            "records": [{
                "cve": f"CVE-2026-{30000+i}",
                "upstream_paths": (["include/linux/example.h"] if i < 47 else
                                   ["drivers/example.c"]),
                "affected_headers": (["include/linux/example.h"] if i < 47 else []),
                "candidate_upstream_fix_references": [],
                "error": ""
            } for i in range(295)]
        }

    def test_295_paths_present_but_no_automatic_fix_or_vex(self):
        report = m.inspect(self.upstream, self.repo, set())
        self.assertEqual(report["counts"], {"under_investigation": 295})
        self.assertEqual(len(report["records"]), 295)
        self.assertEqual(sum(bool(r["kernel_private_header_paths"]) for r in report["records"]), 47)
        self.assertTrue(all(r["ubuntu_source_paths_present"] for r in report["records"]))
        self.assertTrue(all(r["ubuntu_fix_commit_verified"] is False for r in report["records"]))
        self.assertTrue(all(r["uapi_abi_macro_indirect_exposure"] == "under_investigation"
                            for r in report["records"]))

    def test_wrong_source_origin_rejected(self):
        subprocess.run(["git", "-C", str(self.repo), "remote", "set-url",
                        "origin", "https://example.invalid/linux"], check=True)
        with self.assertRaisesRegex(ValueError, "official"):
            m.inspect(self.upstream, self.repo, set())

    def test_missing_path_not_misclassified_safe(self):
        self.upstream["records"][0]["upstream_paths"] = ["drivers/missing.c"]
        report = m.inspect(self.upstream, self.repo, set())
        self.assertEqual(report["records"][0]["upstream_paths_missing_from_ubuntu_snapshot"],
                         ["drivers/missing.c"])
        self.assertEqual(report["records"][0]["binary_disposition"], "under_investigation")

    def test_partial_source_inventory_rejected(self):
        self.upstream["records"].pop()
        with self.assertRaisesRegex(ValueError, "missing/duplicate"):
            m.inspect(self.upstream, self.repo, set())


if __name__ == "__main__":
    unittest.main()
