"""Regression and denial tests for reusable artifact-bound DEV-10 risk policies."""
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
OTHER_DIGEST = "sha256:" + "b" * 64
NOW = dt.datetime(2026, 11, 15, tzinfo=dt.timezone.utc)
IMAGE = policy.IMAGE_REPOSITORY


class ProtectedDecisionTests(unittest.TestCase):
    def setUp(self):
        self.decision = {
            "schema_version": 2, "status": "approved",
            "repository": policy.REPOSITORY, "image_repository": IMAGE,
            "environment": "development",
            "profiles": ["final", "frontend", "frontend-e2e", "infra"],
            "architectures": ["linux/amd64", "linux/arm64"],
            "approval_id": "DEV10-RISK-EXAMPLE",
            "prepared_by": "engineering-maker",
            "approved_by": "independent-security-checker",
            "approval_evidence": "https://github.com/baobab-platform/baobab-dev/issues/54",
            "approved_at": "2026-11-14T00:00:00Z",
            "expires_at": "2026-11-26T00:00:00Z",
            "findings": [
                {"cve": "CVE-2026-12345", "package": "linux-libc-dev",
                 "version": "7.0.0-43.43", "severity": "HIGH"},
                {"cve": "CVE-2026-12346", "package": "linux-libc-dev",
                 "version": "7.0.0-43.43", "severity": "HIGH"},
            ],
        }
        self.report = self.report_for(DIGEST, "amd64")
        self.report["Results"][0]["Vulnerabilities"] = [
            {"VulnerabilityID": "CVE-2026-12345", "PkgName": "linux-libc-dev",
             "InstalledVersion": "7.0.0-43.43", "Severity": "HIGH"},
        ]

    @staticmethod
    def report_for(digest, architecture):
        return {
            "SchemaVersion": 2,
            "ArtifactName": f"{IMAGE}@{digest}",
            "ArtifactType": "container_image",
            "Trivy": {"Version": policy.TRIVY_VERSION},
            "Metadata": {
                "RepoDigests": [f"{IMAGE}@{digest}"],
                "ImageConfig": {"os": "linux", "architecture": architecture},
            },
            "Results": [{
                "Target": "ubuntu:26.04", "Type": "ubuntu",
                "Vulnerabilities": [], "Secrets": [],
            }],
        }

    def evaluate(self, decision=None, report=None, **changes):
        args = dict(image_repository=IMAGE, image_digest=DIGEST, profile="final",
                    architecture="linux/amd64", environment="development",
                    policy_sha256="c" * 64, now=NOW)
        args.update(changes)
        return policy.evaluate(self.decision if decision is None else decision,
                               self.report if report is None else report, **args)

    def test_new_candidate_digest_qualifies_against_same_policy(self):
        report = copy.deepcopy(self.report)
        report["ArtifactName"] = f"{IMAGE}@{OTHER_DIGEST}"
        report["Metadata"]["RepoDigests"] = [f"{IMAGE}@{OTHER_DIGEST}"]
        result = self.evaluate(report=report, image_digest=OTHER_DIGEST)
        self.assertEqual(result["status"], "accepted_residual_risk_not_remediated")
        self.assertEqual(result["image_digest"], OTHER_DIGEST)
        self.assertEqual(result["observed_findings"], 1)

    def test_clean_scan_needs_no_policy_or_approval(self):
        result = self.evaluate(decision=None, report=self.report_for(DIGEST, "amd64"))
        self.assertEqual(result["status"], "clean_no_exception_required")

    def test_direct_evaluation_without_verified_policy_hash_is_denied(self):
        with self.assertRaises(policy.DecisionDenied):
            policy.evaluate(
                self.decision, self.report,
                image_repository=IMAGE, image_digest=DIGEST,
                profile="final", architecture="linux/amd64",
                environment="development", now=NOW,
            )

    def test_policy_file_requires_independent_trusted_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "decision.json"
            raw = json.dumps(self.decision, sort_keys=True).encode()
            path.write_bytes(raw)
            digest = hashlib.sha256(raw).hexdigest()
            loaded, actual = policy.load_verified_decision(path, digest)
            self.assertEqual(loaded, self.decision)
            self.assertEqual(actual, digest)
            path.write_bytes(raw + b" ")
            with self.assertRaises(policy.DecisionDenied):
                policy.load_verified_decision(path, digest)

    def test_exact_digest_repository_and_architecture_are_verified(self):
        for changes in (
            {"image_digest": OTHER_DIGEST},
            {"image_repository": "ghcr.io/attacker/baobab-dev"},
            {"architecture": "linux/arm64"},
        ):
            with self.subTest(changes=changes), self.assertRaises(policy.DecisionDenied):
                self.evaluate(**changes)

    def test_report_architecture_and_repo_digest_must_match(self):
        report = copy.deepcopy(self.report)
        report["Metadata"]["ImageConfig"]["architecture"] = "arm64"
        with self.assertRaises(policy.DecisionDenied):
            self.evaluate(report=report)
        report = copy.deepcopy(self.report)
        report["Metadata"]["RepoDigests"] = [f"{IMAGE}@{OTHER_DIGEST}"]
        with self.assertRaises(policy.DecisionDenied):
            self.evaluate(report=report)

    def test_scan_tool_and_report_type_are_pinned(self):
        report = copy.deepcopy(self.report)
        report["Trivy"]["Version"] = "0.74.0"
        with self.assertRaises(policy.DecisionDenied):
            self.evaluate(report=report)
        report = copy.deepcopy(self.report)
        report["ArtifactType"] = "filesystem"
        with self.assertRaises(policy.DecisionDenied):
            self.evaluate(report=report)

    def test_new_or_changed_findings_are_denied(self):
        for field, value in (
            ("VulnerabilityID", "CVE-2026-99999"),
            ("Severity", "CRITICAL"), ("PkgName", "openssl"),
            ("InstalledVersion", "9.9"), ("FixedVersion", "7.0.0-44.44"),
        ):
            report = copy.deepcopy(self.report)
            report["Results"][0]["Vulnerabilities"][0][field] = value
            with self.subTest(field=field), self.assertRaises(policy.DecisionDenied):
                self.evaluate(report=report)

    def test_subset_of_approved_findings_is_allowed_after_partial_remediation(self):
        result = self.evaluate()
        self.assertEqual(result["observed_findings"], 1)
        self.assertEqual(result["approved_findings"], 2)

    def test_secrets_and_malformed_scan_evidence_are_denied(self):
        report = copy.deepcopy(self.report)
        report["Results"][0]["Secrets"] = [{"RuleID": "credential"}]
        with self.assertRaises(policy.DecisionDenied):
            self.evaluate(report=report)
        report = copy.deepcopy(self.report)
        report["Results"] = []
        with self.assertRaises(policy.DecisionDenied):
            self.evaluate(report=report)

    def test_revocation_expiry_context_and_maker_checker_are_enforced(self):
        mutations = (
            ("status", "revoked"), ("revoked_at", "2026-11-14T12:00:00Z"),
            ("approved_by", "engineering-maker"), ("approved_by", ""),
            ("environment", "production"), ("expires_at", "2026-11-14T00:00:00Z"),
        )
        for field, value in mutations:
            decision = copy.deepcopy(self.decision)
            decision[field] = value
            with self.subTest(field=field), self.assertRaises(policy.DecisionDenied):
                self.evaluate(decision=decision)

    def test_profile_and_architecture_scope_are_enforced(self):
        with self.assertRaises(policy.DecisionDenied):
            self.evaluate(decision={**self.decision, "profiles": ["frontend"]},
                          profile="final")
        report = copy.deepcopy(self.report)
        report["Metadata"]["ImageConfig"]["architecture"] = "arm64"
        with self.assertRaises(policy.DecisionDenied):
            self.evaluate(decision={**self.decision, "architectures": ["linux/amd64"]},
                          report=report, architecture="linux/arm64")
        decision = copy.deepcopy(self.decision)
        decision["profiles"] = "final"
        with self.assertRaises(policy.DecisionDenied):
            self.evaluate(decision=decision)

    def test_invalid_cve_types_and_duplicate_policy_findings_are_denied(self):
        decision = copy.deepcopy(self.decision)
        decision["findings"][0]["cve"] = 12345
        with self.assertRaises(policy.DecisionDenied):
            self.evaluate(decision=decision)
        decision = copy.deepcopy(self.decision)
        decision["findings"].append(copy.deepcopy(decision["findings"][0]))
        with self.assertRaises(policy.DecisionDenied):
            self.evaluate(decision=decision)


if __name__ == "__main__":
    unittest.main()
