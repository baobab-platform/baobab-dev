"""Regression and denial tests for protected digest-bound risk decisions."""
import copy
import datetime as dt
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

path = Path(__file__).resolve().parents[1] / "scripts/evaluate_protected_risk_decision.py"
spec = importlib.util.spec_from_file_location("protected_risk", path)
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)
DIGEST = "sha256:" + "a" * 64
NOW = dt.datetime(2026, 11, 15, tzinfo=dt.timezone.utc)


class ProtectedDecisionTests(unittest.TestCase):
    def setUp(self):
        self.decision = {
            "schema_version": 1, "status": "approved",
            "repository": "baobab-platform/baobab-dev", "environment": "development",
            "image_digests": [DIGEST], "profiles": ["final"],
            "architectures": ["linux/amd64"], "approval_id": "example-only",
            "approved_by": "independent-reviewer", "approval_evidence": "https://example.org/approval",
            "approved_at": "2026-11-14T00:00:00Z", "expires_at": "2026-11-26T00:00:00Z",
            "findings": [{"cve": "CVE-2026-12345", "package": "linux-libc-dev",
                          "version": "7.0.0-43.43", "severity": "HIGH"}],
        }
        self.report = {"Results": [{"Target": "ubuntu:26.04",
            "Vulnerabilities": [{"VulnerabilityID": "CVE-2026-12345",
                "PkgName": "linux-libc-dev", "InstalledVersion": "7.0.0-43.43",
                "Severity": "HIGH"}]}]}

    def evaluate(self, decision=None, report=None, **changes):
        args = dict(image_digest=DIGEST, profile="final", architecture="linux/amd64",
                    environment="development", now=NOW)
        args.update(changes)
        return policy.evaluate(self.decision if decision is None else decision,
                               self.report if report is None else report, **args)

    def test_digest_bound_decision_without_pr_number(self):
        self.assertEqual(self.evaluate()["status"], "accepted_residual_risk")

    def test_decision_file_requires_independent_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / "decision.json"
            raw = json.dumps(self.decision).encode()
            p.write_bytes(raw)
            sha = hashlib.sha256(raw).hexdigest()
            self.assertEqual(policy.load_verified_decision(p, sha), self.decision)
            p.write_bytes(raw + b" ")
            with self.assertRaises(policy.DecisionDenied):
                policy.load_verified_decision(p, sha)

    def test_unapproved_contexts_and_digest_denied(self):
        for change in ({"image_digest": "sha256:" + "b" * 64},
                       {"profile": "infra"}, {"architecture": "linux/arm64"},
                       {"environment": "production"},
                       {"now": dt.datetime(2026, 11, 26, tzinfo=dt.timezone.utc)}):
            with self.subTest(change=change), self.assertRaises(policy.DecisionDenied):
                self.evaluate(**change)

    def test_revocation_and_unattributed_approval_denied(self):
        for field, value in (("status", "revoked"), ("approved_by", ""),
                             ("approval_evidence", ""), ("approval_id", "")):
            d = copy.deepcopy(self.decision)
            d[field] = value
            with self.subTest(field=field), self.assertRaises(policy.DecisionDenied):
                self.evaluate(decision=d)

    def test_changed_or_fixed_vulnerability_denied(self):
        for field, value in (("VulnerabilityID", "CVE-2026-99999"),
                             ("Severity", "CRITICAL"), ("PkgName", "openssl"),
                             ("FixedVersion", "7.0.0-44.44")):
            report = copy.deepcopy(self.report)
            report["Results"][0]["Vulnerabilities"][0][field] = value
            with self.subTest(field=field), self.assertRaises(policy.DecisionDenied):
                self.evaluate(report=report)

    def test_secret_and_incomplete_inventory_denied(self):
        report = copy.deepcopy(self.report)
        report["Results"][0]["Secrets"] = [{"RuleID": "credential"}]
        with self.assertRaises(policy.DecisionDenied):
            self.evaluate(report=report)
        report = copy.deepcopy(self.report)
        report["Results"][0]["Vulnerabilities"] = []
        with self.assertRaises(policy.DecisionDenied):
            self.evaluate(report=report)


if __name__ == "__main__":
    unittest.main()
