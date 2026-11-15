"""Protected local Foundation risk policy: positive and negative regression controls."""
import copy
import datetime as dt
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / "scripts"))
from verify_protected_policy_hash import verify

NOW = dt.datetime(2026, 11, 15, tzinfo=dt.timezone.utc)
FINDING = {"cve": "CVE-2026-68103", "package": "linux-libc-dev",
           "version": "7.0.0-43.43", "severity": "HIGH", "type": "ubuntu"}

class LocalPolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = {
            "schema_version": 2, "status": "approved", "revoked_at": None,
            "repository": "baobab-platform/baobab-dev", "environment": "development",
            "profiles": ["final"], "architectures": ["linux/amd64"],
            "prepared_by": "maker", "approved_by": "checker",
            "approval_id": "DEV10-TEST",
            "approval_evidence": "https://github.com/baobab-platform/baobab-dev/pull/123",
            "approved_at": "2026-11-14T00:00:00Z",
            "expires_at": "2026-11-26T00:00:00Z",
            "findings": [dict(FINDING)],
        }
        self.report = {"SchemaVersion": 2, "ArtifactType": "container_image",
                       "Trivy": {"Version": "0.73.0"}, "Results": [{"Target": "ubuntu:26.04", "Type": "ubuntu",
            "Vulnerabilities": [{"VulnerabilityID": FINDING["cve"],
                "PkgName": FINDING["package"], "InstalledVersion": FINDING["version"],
                "Severity": "HIGH"}]}]}

    def evaluate(self, *, policy=None, report=None, trusted_hash=None, now=NOW):
        raw = json.dumps(self.policy if policy is None else policy, sort_keys=True).encode()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_bytes(raw)
            return verify(path, trusted_hash or hashlib.sha256(raw).hexdigest(),
                          self.report if report is None else report,
                          profile="final", architecture="linux/amd64", now=now)

    def test_exact_protected_inventory(self):
        self.assertEqual(self.evaluate()["findings"], 1)

    def test_untrusted_policy_hash(self):
        with self.assertRaises(ValueError):
            self.evaluate(trusted_hash="a" * 64)

    def test_expired_policy(self):
        with self.assertRaises(ValueError):
            self.evaluate(now=dt.datetime(2026, 11, 27, tzinfo=dt.timezone.utc))

    def test_new_cve_package_version_severity_and_fixed_version(self):
        for field, value in (
            ("VulnerabilityID", "CVE-2026-99999"),
            ("PkgName", "openssl"), ("InstalledVersion", "7.0.0-44.44"),
            ("Severity", "CRITICAL"), ("FixedVersion", "7.0.0-44.44"),
        ):
            report = copy.deepcopy(self.report)
            report["Results"][0]["Vulnerabilities"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.evaluate(report=report)

    def test_missing_approval_identity_or_scan_provenance(self):
        policy = copy.deepcopy(self.policy)
        policy["approval_evidence"] = None
        with self.assertRaises(ValueError):
            self.evaluate(policy=policy)
        report = copy.deepcopy(self.report)
        report.pop("Trivy")
        with self.assertRaises(ValueError):
            self.evaluate(report=report)

    def test_wrong_scope_or_maker_checker(self):
        for field, value in (("environment", "production"),
                             ("profiles", ["infra"]),
                             ("approved_by", "maker"),
                             ("status", "revoked")):
            policy = copy.deepcopy(self.policy)
            policy[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.evaluate(policy=policy)

if __name__ == "__main__":
    unittest.main()
