"""Immutable RC recovery planner negative and positive cases."""
import importlib.util
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("rc_recovery", ROOT / "scripts/plan_rc_recovery.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class ImmutableRecoveryTests(unittest.TestCase):
    def test_new_rc_after_highest_existing(self):
        self.assertEqual(mod.next_rc("v1.5.2-rc.1", {"v1.5.2-rc.1", "v1.5.2-rc.3"}),
                         "v1.5.2-rc.4")
    def test_reject_missing_original(self):
        with self.assertRaises(ValueError):
            mod.next_rc("v1.5.2-rc.1", {"v1.5.2-rc.2"})
    def test_reject_ga_recovery(self):
        with self.assertRaises(ValueError):
            mod.next_rc("v1.5.2", {"v1.5.2"})
    def test_reject_malformed(self):
        with self.assertRaises(ValueError):
            mod.next_rc("v1.5.2-rc.01", {"v1.5.2-rc.01"})
    def test_ignore_other_families(self):
        self.assertEqual(mod.next_rc("v1.5.2-rc.1", {"v1.5.2-rc.1", "v1.5.3-rc.99"}),
                         "v1.5.2-rc.2")
if __name__ == "__main__":
    unittest.main()
