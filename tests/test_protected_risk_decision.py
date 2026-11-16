"""Regression and denial tests for reusable artifact-bound DEV-10 risk policies."""
import copy
import contextlib
import datetime as dt
import io
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

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
            "execution_scope": {"pull_request_base": "main",
                                "pull_request_head_repository": policy.REPOSITORY,
                                "push_ref": "refs/heads/main"},
            "profiles": ["final", "frontend", "frontend-e2e", "infra"],
            "architectures": ["linux/amd64", "linux/arm64"],
            "prepared_by": "engineering-maker", "prepared_by_id": 1,
            "approval_evidence": "https://github.com/baobab-platform/baobab-dev/pull/999",
            "expires_at": "2026-11-26T00:00:00Z",
            "findings": [
                {"cve": "CVE-2026-12345", "package": "linux-libc-dev",
                 "version": "7.0.0-43.43", "severity": "HIGH", "type": "ubuntu"},
                {"cve": "CVE-2026-12346", "package": "linux-libc-dev",
                 "version": "7.0.0-43.43", "severity": "HIGH", "type": "ubuntu"},
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

    def evaluate(self, decision="__default__", report=None, **changes):
        if decision == "__default__":
            decision = self.decision
        decision_bytes = None
        trusted_hash = None
        if isinstance(decision, dict):
            decision_bytes = json.dumps(decision, sort_keys=True).encode()
            trusted_hash = hashlib.sha256(decision_bytes).hexdigest()
        args = dict(image_repository=IMAGE, image_digest=DIGEST, profile="final",
                    architecture="linux/amd64", environment="development",
                    trusted_decision_sha256=trusted_hash,
                    event="pull_request", ref="refs/pull/123/merge",
                    base_ref="main", head_repository=policy.REPOSITORY,
                    approval_id="github-review-123",
                    approval_timestamp="2026-11-14T00:00:00Z",
                    approved_by_id=2, now=NOW)
        args.update(changes)
        return policy.evaluate(decision_bytes,
                               self.report if report is None else report, **args)

    def test_actual_issue_54_eight_cve_inventory_is_exactly_qualifiable(self):
        cves = [
            "CVE-2022-50240", "CVE-2025-40190", "CVE-2026-68103",
            "CVE-2026-72198", "CVE-2026-74578", "CVE-2026-89805",
            "CVE-2026-98376", "CVE-2026-98420",
        ]
        decision = copy.deepcopy(self.decision)
        decision["findings"] = [
            {"cve": cve, "package": "linux-libc-dev",
             "version": "7.0.0-43.43", "severity": "HIGH", "type": "ubuntu"}
            for cve in cves
        ]
        report = copy.deepcopy(self.report)
        report["Results"][0]["Vulnerabilities"] = [
            {"VulnerabilityID": cve, "PkgName": "linux-libc-dev",
             "InstalledVersion": "7.0.0-43.43", "Severity": "HIGH"}
            for cve in cves
        ]
        result = self.evaluate(decision=decision, report=report)
        self.assertEqual(result["observed_findings"], 8)
        self.assertEqual(result["approved_findings"], 8)

    def test_all_four_profiles_and_both_architectures_are_supported(self):
        for profile in policy.PROFILES:
            for architecture in policy.ARCHES:
                report = copy.deepcopy(self.report)
                report["Metadata"]["ImageConfig"]["architecture"] = architecture.split("/")[1]
                with self.subTest(profile=profile, architecture=architecture):
                    result = self.evaluate(report=report, profile=profile,
                                            architecture=architecture)
                    self.assertEqual(result["status"],
                                     "accepted_residual_risk_not_remediated")

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

    def test_non_execution_scope_decision_still_requires_numeric_review_metadata(self):
        decision = self.decision()
        decision.pop("execution_scope")
        with self.assertRaises(policy.DecisionError):
            self.evaluate(decision, approved_by_id=None)
        result = self.evaluate(decision, approved_by_id=2)
        self.assertEqual(result["approved_by_id"], 2)

    def test_direct_evaluation_without_verified_policy_hash_is_denied(self):
        with self.assertRaises(policy.DecisionDenied):
            policy.evaluate(
                self.decision, self.report,
                image_repository=IMAGE, image_digest=DIGEST,
                profile="final", architecture="linux/amd64",
                environment="development", event="pull_request",
                ref="refs/pull/123/merge", base_ref="main",
                head_repository=policy.REPOSITORY, now=NOW,
            )

    def test_cli_denial_writes_evidence_and_reports_to_stderr(self):
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "trivy.json"
            result_path = Path(directory) / "decision-result.json"
            report_path.write_text(json.dumps(self.report))
            argv = [
                "evaluate_protected_risk_decision.py",
                "--report", str(report_path),
                "--image-repository", IMAGE,
                "--digest", DIGEST,
                "--profile", "final",
                "--architecture", "linux/amd64",
                "--environment", "development",
                "--event", "pull_request",
                "--ref", "refs/pull/123/merge",
                "--base-ref", "main",
                "--head-repository", policy.REPOSITORY,
                "--result-output", str(result_path),
            ]
            stderr = io.StringIO()
            stdout = io.StringIO()
            with patch.object(policy.sys, "argv", argv):
                with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(stdout):
                    exit_code = policy.main()
            self.assertEqual(exit_code, 2)
            self.assertIn("SECURITY DENIED:", stderr.getvalue())
            self.assertEqual(json.loads(result_path.read_text())["status"], "denied")

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

    def test_execution_context_rejects_tags_dispatch_schedules_and_wrong_pr_base(self):
        for event, ref, base_ref in (
            ("push", "refs/tags/v1.5.2-rc.1", ""),
            ("workflow_dispatch", "refs/heads/main", ""),
            ("schedule", "refs/heads/main", ""),
            ("deployment", "refs/heads/main", ""),
            ("pull_request", "refs/pull/123/merge", "release"),
            ("pull_request", "refs/pull/123/head", "main"),
            ("push", "refs/heads/release", ""),
        ):
            with self.subTest(event=event, ref=ref, base_ref=base_ref):
                with self.assertRaises(policy.DecisionDenied):
                    self.evaluate(event=event, ref=ref, base_ref=base_ref)

    def test_fork_pull_request_is_not_eligible_for_reusable_policy(self):
        with self.assertRaises(policy.DecisionDenied):
            self.evaluate(head_repository="attacker/baobab-dev")

    def test_push_to_main_is_allowed_by_reusable_development_policy(self):
        result = self.evaluate(event="push", ref="refs/heads/main", base_ref="",
                               head_repository=policy.REPOSITORY)
        self.assertEqual(result["status"], "accepted_residual_risk_not_remediated")
    def test_duplicate_identical_scan_occurrences_are_deduplicated(self):
        report = copy.deepcopy(self.report)
        report["Results"].append(copy.deepcopy(report["Results"][0]))
        result = self.evaluate(report=report)
        self.assertEqual(result["observed_findings"], 1)

    def test_package_ecosystem_type_is_part_of_policy_identity(self):
        report = copy.deepcopy(self.report)
        report["Results"][0]["Type"] = "alpine"
        with self.assertRaises(policy.DecisionDenied):
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

    def test_issue_reference_cannot_substitute_for_decision_approval(self):
        decision = copy.deepcopy(self.decision)
        decision["approval_evidence"] = (
            "https://github.com/baobab-platform/baobab-dev/issues/54"
        )
        with self.assertRaises(policy.DecisionDenied):
            self.evaluate(decision=decision)

    def test_revocation_expiry_context_and_maker_checker_are_enforced(self):
        mutations = (
            ("status", "revoked"), ("revoked_at", "2026-11-14T12:00:00Z"),
            ("prepared_by_id", 2), ("prepared_by_id", 0),
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
