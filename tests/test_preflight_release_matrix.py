"""Negative regression tests for mandatory DEV-10 pre-tag release matrix."""
import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("preflight_release_matrix", ROOT / "scripts/preflight_release_matrix.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class ReleaseMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = (ROOT / ".github/workflows/publish.yml").read_text()

    def test_current_release_matrix(self):
        self.assertEqual(mod.check(ROOT, self.workflow), [])

    def test_missing_artifact(self):
        changed = self.workflow.replace("name: ga-reused-candidates", "name: wrong-ga-candidates")
        self.assertTrue(mod.check(ROOT, changed))

    def test_missing_rc_artifact(self):
        changed = self.workflow.replace("name: published-info-${{ matrix.target }}", "name: wrong-target")
        self.assertTrue(mod.check(ROOT, changed))

    def test_missing_executable_provisioning(self):
        changed = self.workflow.replace("cosign-installer@", "unapproved-installer@")
        self.assertTrue(mod.check(ROOT, changed))

    def test_missing_job_dependency(self):
        changed = self.workflow.replace("needs: [publish, ga-reuse, sanity-check]",
                                        "needs: [publish, sanity-check]")
        self.assertTrue(mod.check(ROOT, changed))

    def test_missing_rc_ga_branch(self):
        changed = self.workflow.replace("publication_channel == 'ga-direct'", "publication_channel == 'invalid'")
        self.assertTrue(mod.check(ROOT, changed))

    def test_missing_contract_gate(self):
        changed = self.workflow.replace("scripts/verify_release_artifact_contract.py",
                                        "scripts/disabled_artifact_contract.py")
        self.assertTrue(mod.check(ROOT, changed))

if __name__ == "__main__":
    unittest.main()
