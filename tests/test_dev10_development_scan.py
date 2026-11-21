"""CI scan receipts must preserve the protected policy boundary."""
import datetime as dt
from functools import partial
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import dev10_development_scan as scan

IMAGE_ID = "sha256:" + "a" * 64
NOW = dt.datetime(2026, 11, 21, tzinfo=dt.timezone.utc)


class DevelopmentScanTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        self.report_path = self.root / "raw.json"
        self.output = self.root / "evidence"
        self.decision_path = self.root / "foundation.json"
        self.summary = self.root / "summary.md"
        baseline = ROOT / scan.DECISION_PATH
        self.policy = json.loads(baseline.read_bytes())
        self.env = {
            "GITHUB_SHA": "1" * 40, "POLICY_HEAD_SHA": "2" * 40, "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": "2", "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_BASE_REF": "main", "GITHUB_REF": "refs/pull/74/merge",
            "GITHUB_REPOSITORY": scan.REPOSITORY, "POLICY_HEAD_REPOSITORY": scan.REPOSITORY,
            "TRUSTED_APPROVERS": "independent-reviewer", "GITHUB_TOKEN": "read-only-fixture",
            "GITHUB_STEP_SUMMARY": str(self.summary),
        }
        self.custody = {"approval_id": "github-review-4", "approved_at": "2026-11-17T00:00:00Z",
                        "approved_by_id": 356900102}
        self.set_policy()
        self.report = {
            "SchemaVersion": 2, "ArtifactType": "container_image", "Trivy": {"Version": scan.TRIVY_VERSION},
            "Metadata": {"ImageID": IMAGE_ID, "ImageConfig": {
                "os": "linux", "architecture": "amd64", "config": {"Env": ["SECRET=test-image-env"]},
            }},
            "Results": [{"Target": "Ubuntu", "Class": "os-pkgs", "Type": "ubuntu", "Vulnerabilities": []}],
        }

    def set_policy(self):
        raw = json.dumps(self.policy).encode()
        self.decision_path.write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        self.env["TRUSTED_POLICY_SHA"] = digest
        self.custody["merged_decision_sha256"] = digest

    def add_finding(self, cve="CVE-2026-68103", *, version="7.0.0-43.43", severity="HIGH", fixed=""):
        self.report["Results"][0]["Vulnerabilities"].append({
            "VulnerabilityID": cve, "PkgName": "linux-libc-dev", "InstalledVersion": version,
            "Severity": severity, "FixedVersion": fixed,
        })

    def run_scan(self, scanner_exit, *, custody_error=None, now=NOW,
                 image_options=("--image-config-digest", IMAGE_ID)):
        self.report_path.write_text(json.dumps(self.report), encoding="utf-8")
        argv = ["--report", str(self.report_path), "--evidence-dir", str(self.output),
                "--profile", "final", "--architecture", "linux/amd64",
                "--scan-exit-code", str(scanner_exit), *image_options]
        with patch.object(scan, "DECISION_PATH", self.decision_path), \
             patch.object(scan, "verify_read_custody", return_value=self.custody, side_effect=custody_error) as custody, \
             patch.object(scan, "verify_policy", partial(scan.verify_policy, now=now)):
            code = scan.main(argv, env=self.env)
        return code, self.read("gate-result.json"), custody

    def read(self, name):
        return json.loads((self.output / name).read_text())

    def test_clean_scan_does_not_require_an_anchor_or_live_custody(self):
        self.env.pop("TRUSTED_POLICY_SHA")
        code, result, custody = self.run_scan(0)
        self.assertEqual((code, result["status"], result["observed"]["count"]), (0, "clean", 0))
        custody.assert_not_called()

    def test_exact_covered_subset_requires_verified_bytes_and_live_custody(self):
        self.add_finding()
        code, result, custody = self.run_scan(scan.FINDINGS_EXIT_CODE)
        self.assertEqual((code, result["status"]), (0, "covered"))
        custody.assert_called_once()
        self.assertEqual(self.read("dev10-protected-risk-acceptance.json")["policy_sha256"],
                         self.env["TRUSTED_POLICY_SHA"])
        self.assertFalse((self.output / "risk-review-request.json").exists())

    def test_inventory_change_creates_scoped_request_and_never_writes_acceptance(self):
        self.add_finding()
        self.add_finding("CVE-2026-99312", version="7.0.0-44.44", severity="CRITICAL")
        archive = "9" * 64
        code, result, _ = self.run_scan(scan.FINDINGS_EXIT_CODE, image_options=("--archive-sha256", archive))
        self.assertEqual((code, result["status"]), (1, "inventory_changed"))
        self.assertEqual(result["approved"]["count"], len(self.policy["findings"]))
        self.assertEqual(result["observed"]["severity"], {"CRITICAL": 1, "HIGH": 1})
        self.assertEqual(result["out_of_scope"]["count"], 1)
        request = self.read("risk-review-request.json")
        self.assertEqual(request["status"], "review_required")
        self.assertEqual(request["covered_findings"], 1)
        self.assertEqual(request["accountable_owner_id"], 49340314)
        self.assertEqual(request["source_sha"], self.env["GITHUB_SHA"])
        self.assertEqual(request["pull_request_head_sha"], self.env["POLICY_HEAD_SHA"])
        self.assertEqual(request["image_config_digest"], IMAGE_ID)
        self.assertEqual(request["image_archive_sha256"], archive)
        self.assertEqual(request["raw_trivy_sha256"], hashlib.sha256(self.report_path.read_bytes()).hexdigest())
        self.assertEqual(result["review_request_sha256"],
                         hashlib.sha256((self.output / "risk-review-request.json").read_bytes()).hexdigest())
        self.assertEqual([finding["disposition"] for finding in request["findings_requiring_disposition"]], ["pending"])
        self.assertIn("Open the owner review request", self.summary.read_text())
        self.assertFalse((self.output / "dev10-protected-risk-acceptance.json").exists())

    def test_scanner_error_and_status_report_disagreement_are_technical_failures(self):
        code, result, custody = self.run_scan(scan.FINDINGS_EXIT_CODE)
        self.assertEqual((code, result["status"]), (1, "technical_scan_failure"))
        custody.assert_not_called()
        self.add_finding()
        for status in (0, 1, 125):
            with self.subTest(scanner_status=status):
                code, result, custody = self.run_scan(status)
                self.assertEqual((code, result["status"]), (1, "technical_scan_failure"))
                custody.assert_not_called()
        self.assertFalse((self.output / "risk-review-request.json").exists())

    def test_fixed_versions_and_secret_payloads_require_remediation(self):
        self.add_finding(fixed="7.0.0-44.44")
        self.assertEqual(self.run_scan(scan.FINDINGS_EXIT_CODE)[1]["status"], "remediation_required")
        self.report["Results"][0]["Secrets"] = [{"Match": "secret-test-payload"}]
        code, result, custody = self.run_scan(scan.FINDINGS_EXIT_CODE)
        self.assertEqual((code, result["status"]), (1, "remediation_required"))
        for path in self.output.iterdir():
            text = path.read_text()
            self.assertNotIn("secret-test-payload", text)
            self.assertNotIn("test-image-env", text)
        custody.assert_not_called()

    def test_wrong_image_or_malformed_inventory_cannot_pass_a_clean_scan(self):
        code, result, _ = self.run_scan(0, image_options=("--image-config-digest", "sha256:" + "b" * 64))
        self.assertEqual((code, result["status"]), (1, "technical_scan_failure"))
        self.report["Results"][0]["Vulnerabilities"] = {}
        code, result, _ = self.run_scan(0)
        self.assertEqual((code, result["status"]), (1, "technical_scan_failure"))

    def test_out_of_scope_context_never_contacts_custody_or_requests_review(self):
        self.add_finding(version="7.0.0-44.44")
        for change in ({"POLICY_HEAD_REPOSITORY": "fork/baobab-dev"}, {"GITHUB_BASE_REF": "release"},
                       {"GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/tags/v1.5.2"}):
            with self.subTest(context=change), patch.dict(self.env, change):
                code, result, custody = self.run_scan(scan.FINDINGS_EXIT_CODE)
                self.assertEqual((code, result["status"]), (1, "outside_development_scope"))
                custody.assert_not_called()
                self.assertFalse((self.output / "risk-review-request.json").exists())

    def test_missing_or_mismatched_anchor_denies_even_approved_form(self):
        self.add_finding()
        for anchor in ("", "f" * 64):
            with self.subTest(anchor=anchor), patch.dict(self.env, TRUSTED_POLICY_SHA=anchor):
                code, result, custody = self.run_scan(scan.FINDINGS_EXIT_CODE)
                self.assertEqual((code, result["status"]), (1, "awaiting_activation"))
                custody.assert_not_called()

    def test_custody_sha_mismatch_stale_review_and_missing_concurrence_deny(self):
        self.add_finding()
        with patch.dict(self.custody, merged_decision_sha256="b" * 64):
            code, result, _ = self.run_scan(scan.FINDINGS_EXIT_CODE)
            self.assertEqual((code, result["status"]), (1, "policy_verification_failed"))
        for error, state in ((scan.IndependentApprovalMissing("stale review"), "awaiting_independent_approval"),
                             (scan.OwnerConcurrenceMissing("missing concurrence"), "awaiting_owner_concurrence")):
            with self.subTest(state=state):
                code, result, _ = self.run_scan(scan.FINDINGS_EXIT_CODE, custody_error=error)
                self.assertEqual((code, result["status"]), (1, state))

    def test_expired_and_revoked_decision_remain_blocking(self):
        self.add_finding()
        code, result, _ = self.run_scan(scan.FINDINGS_EXIT_CODE, now=NOW + dt.timedelta(days=7))
        self.assertEqual((code, result["status"]), (1, "decision_inactive"))
        self.policy.update(status="revoked", revoked_at="2026-11-20T00:00:00Z")
        self.set_policy()
        code, result, _ = self.run_scan(scan.FINDINGS_EXIT_CODE)
        self.assertEqual((code, result["status"]), (1, "decision_inactive"))


if __name__ == "__main__":
    unittest.main()
