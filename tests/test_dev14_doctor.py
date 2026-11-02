"""DEV-14 non-mutating developer diagnostic safety regression tests."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

script = Path(__file__).resolve().parents[1] / "scripts/dev14-doctor.py"
spec = importlib.util.spec_from_file_location("dev14_doctor", script)
doctor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(doctor)


class DoctorTests(unittest.TestCase):
    def test_minimum_versions(self):
        self.assertTrue(doctor.meets_version("Python 3.14.3", (3, 14)))
        self.assertFalse(doctor.meets_version("Python 3.13.16", (3, 14)))
        self.assertTrue(doctor.meets_version("rustc 1.88.0 (123)", (1, 88)))
        self.assertFalse(doctor.meets_version("rustc 1.87.9", (1, 88)))
        self.assertTrue(doctor.python_line_supported("Python 3.14.6"))
        self.assertFalse(doctor.python_line_supported("Python 3.13.16"))
        self.assertFalse(doctor.python_line_supported("Python 3.15.0"))
        self.assertEqual(
            doctor.SHARED_PIN,
            "32b71f3335e566daeb58246f17fcbbf162cf7f53",
        )

    def test_missing_rust_and_docker_block_payments(self):
        with patch.object(doctor.shutil, "which", return_value=None):
            result = doctor.inspect("payments-sandbox")
        self.assertIn("rustc", result["blocked_prerequisites"])
        self.assertIn("docker", result["blocked_prerequisites"])
        self.assertEqual(result["engine_runtime"], "NOT_OBSERVED")
        self.assertFalse(result["production_authorized"])

    def test_valid_local_toolchain_never_proves_engine_execution(self):
        with patch.object(doctor.shutil, "which", return_value="/usr/bin/tool"):
            with patch.object(doctor, "probe", return_value=(True, "Python 3.14.0")):
                result = doctor.inspect("pulse-intelligence")
        self.assertEqual(result["result"], "BLOCKED")  # Shared checkout not inspected
        self.assertIn("shared_contract_pin", result["blocked_prerequisites"])
        self.assertEqual(result["eng_onb_runtime_cases"], "NOT_EXECUTED")

    def test_checkout_matches_only_exact_shared_sha_and_clean_worktree(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with patch.object(doctor.shutil, "which", return_value="/usr/bin/tool"):
                with patch.object(doctor, "probe",
                                  side_effect=lambda cmd, **kw: (
                                      (True, doctor.SHARED_PIN) if "rev-parse" in cmd
                                      else (True, "OBSERVED") if "status" in cmd
                                      else (True, "Python 3.14.0")
                                  )):
                    result = doctor.inspect("pulse-intelligence", root)
            self.assertEqual(result["checks"]["shared_contract_pin"], "MATCHED")
            self.assertEqual(result["result"], "LOCAL_TOOLCHAIN_OBSERVED")
            self.assertEqual(result["scope"], "TOOLCHAIN_DIAGNOSTIC_ONLY")
            self.assertFalse(result["protected_acceptance"])

    def test_python_315_is_blocked_even_with_other_prerequisites(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with patch.object(doctor.shutil, "which", return_value="/usr/bin/tool"):
                with patch.object(doctor, "probe", side_effect=lambda cmd, **kw: (
                    (True, doctor.SHARED_PIN) if "rev-parse" in cmd else
                    (True, "OBSERVED") if "status" in cmd else
                    (True, "Python 3.15.0") if "--version" in cmd and cmd[0] == doctor.sys.executable else
                    (True, "Docker version 29.0.0")
                )):
                    result = doctor.inspect("pulse-intelligence", root)
        self.assertEqual(result["checks"]["python"], "VERSION_UNSUPPORTED")
        self.assertIn("python", result["blocked_prerequisites"])
        self.assertEqual(result["result"], "BLOCKED")

    def test_unknown_profile_rejected(self):
        with self.assertRaisesRegex(ValueError, "UNKNOWN_DEV14_PROFILE"):
            doctor.inspect("production-admin")

    def test_shared_symlink_not_followed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            link = root / "link"
            link.symlink_to(root, target_is_directory=True)
            with patch.object(doctor.shutil, "which", return_value="/usr/bin/tool"):
                with patch.object(doctor, "probe", return_value=(True, "Python 3.14.0")):
                    result = doctor.inspect("pulse-intelligence", link)
            self.assertEqual(result["checks"]["shared_contract_pin"], "REFUSED")


if __name__ == "__main__":
    unittest.main()
