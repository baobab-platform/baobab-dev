"""Review-only risk inventory extraction never creates an approval."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from prepare_dev10_risk_inventory import extract

def report():
    return {"SchemaVersion": 2, "ArtifactType": "container_image",
            "Trivy": {"Version": "0.73.0"},
            "Results": [{"Target": "ubuntu:26.04", "Type": "ubuntu",
                         "Vulnerabilities": [
                             {"VulnerabilityID": "CVE-2026-68103",
                              "PkgName": "linux-libc-dev", "InstalledVersion": "7.0.0-43.43",
                              "Severity": "HIGH"}]}]}

class RiskInventoryTests(unittest.TestCase):
    def test_exact_inventory(self):
        self.assertEqual(extract(report(), scanner_version="0.73.0")[0]["version"], "7.0.0-43.43")
    def test_wrong_scanner_version_denied(self):
        value = report()
        value.pop("Trivy")
        with self.assertRaises(ValueError):
            extract(value, scanner_version="0.72.0")
    def test_available_fix_denied(self):
        value = report()
        value["Results"][0]["Vulnerabilities"][0]["FixedVersion"] = "7.0.0-44.44"
        with self.assertRaises(ValueError):
            extract(value, scanner_version="0.73.0")
    def test_secret_denied(self):
        value = report()
        value["Results"][0]["Secrets"] = [{"RuleID": "test"}]
        with self.assertRaises(ValueError):
            extract(value, scanner_version="0.73.0")
    def test_empty_inventory_denied(self):
        value = report()
        value["Results"][0]["Vulnerabilities"] = []
        with self.assertRaises(ValueError):
            extract(value, scanner_version="0.73.0")

if __name__ == "__main__":
    unittest.main()
