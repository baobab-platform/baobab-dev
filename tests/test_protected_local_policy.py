"""Protected local Foundation risk policy: exact scope and denial regressions."""
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
CVES = ["CVE-2022-50240","CVE-2025-40190","CVE-2026-68103","CVE-2026-72198","CVE-2026-74578","CVE-2026-89805","CVE-2026-98376","CVE-2026-98420"]
FINDINGS = [{"cve":"CVE-2022-50240","package":"linux-libc-dev","version":"7.0.0-43.43","severity":"HIGH","type":"ubuntu"},{"cve":"CVE-2025-40190","package":"linux-libc-dev","version":"7.0.0-43.43","severity":"HIGH","type":"ubuntu"},{"cve":"CVE-2026-68103","package":"linux-libc-dev","version":"7.0.0-43.43","severity":"HIGH","type":"ubuntu"},{"cve":"CVE-2026-72198","package":"linux-libc-dev","version":"7.0.0-43.43","severity":"HIGH","type":"ubuntu"},{"cve":"CVE-2026-74578","package":"linux-libc-dev","version":"7.0.0-43.43","severity":"HIGH","type":"ubuntu"},{"cve":"CVE-2026-89805","package":"linux-libc-dev","version":"7.0.0-43.43","severity":"HIGH","type":"ubuntu"},{"cve":"CVE-2026-98376","package":"linux-libc-dev","version":"7.0.0-43.43","severity":"HIGH","type":"ubuntu"},{"cve":"CVE-2026-98420","package":"linux-libc-dev","version":"7.0.0-43.43","severity":"HIGH","type":"ubuntu"}]

class LocalPolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = {
            "schema_version": 2, "status": "approved", "revoked_at": None,
            "repository": "baobab-platform/baobab-dev",
            "image_repository": "ghcr.io/baobab-platform/baobab-dev",
            "environment": "development",
            "execution_scope": {"pull_request_base": "main",
                                "pull_request_head_repository": "baobab-platform/baobab-dev",
                                "push_ref": "refs/heads/main"},
            "profiles": ["final", "frontend", "frontend-e2e", "infra"],
            "architectures": ["linux/amd64", "linux/arm64"],
            "prepared_by": "maker", "prepared_by_id": 1,
            "approved_by": "checker", "approved_by_id": 2,
            "approval_id": "DEV10-TEST",
            "approval_evidence": "https://github.com/baobab-platform/baobab-dev/pull/123",
            "approved_at": "2026-11-14T00:00:00Z",
            "expires_at": "2026-11-26T00:00:00Z",
            "findings": copy.deepcopy(FINDINGS), "finding_count": 8,
        }
        self.report = {
            "SchemaVersion": 2, "ArtifactType": "container_image",
            "Trivy": {"Version": "0.73.0"},
            "Results": [{"Target": "ubuntu:26.04", "Type": "ubuntu",
                         "Vulnerabilities": [
                             {"VulnerabilityID": f["cve"], "PkgName": f["package"],
                              "InstalledVersion": f["version"], "Severity": f["severity"]}
                             for f in FINDINGS
                         ]}],
        }

    def evaluate(self, *, policy=None, report=None, trusted_hash=None, now=NOW,
                 event="pull_request", ref="refs/pull/123/merge", base_ref="main",
                          head_repository="baobab-platform/baobab-dev"):
        raw = json.dumps(self.policy if policy is None else policy, sort_keys=True).encode()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_bytes(raw)
            return verify(path, trusted_hash or hashlib.sha256(raw).hexdigest(),
                          self.report if report is None else report,
                          profile="final", architecture="linux/amd64",
                          event=event, ref=ref, base_ref=base_ref,
                          head_repository=head_repository, now=now)

    def test_exact_eight_finding_inventory_and_all_supported_profiles_architectures(self):
        for profile in self.policy["profiles"]:
            for architecture in self.policy["architectures"]:
                raw = json.dumps(self.policy, sort_keys=True).encode()
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "policy.json"
                    path.write_bytes(raw)
                    result = verify(path, hashlib.sha256(raw).hexdigest(), self.report,
                                    profile=profile, architecture=architecture,
                                    event="pull_request", ref="refs/pull/123/merge",
                                    base_ref="main", head_repository="baobab-platform/baobab-dev", now=NOW)
                self.assertEqual(result["findings"], 8)

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

    def test_partial_remediation_may_remove_findings_but_never_add_findings(self):
        report = copy.deepcopy(self.report)
        report["Results"][0]["Vulnerabilities"].pop()
        self.assertEqual(self.evaluate(report=report)["findings"], 7)

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
                             ("approved_by_id", 1),
                             ("status", "revoked")):
            policy = copy.deepcopy(self.policy)
            policy[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.evaluate(policy=policy)

    def test_tags_dispatch_schedules_wrong_base_and_wrong_ref_are_denied(self):
        for event, ref, base_ref in (
            ("push", "refs/tags/v1.5.2-rc.1", ""),
            ("workflow_dispatch", "refs/heads/main", ""),
            ("schedule", "refs/heads/main", ""),
            ("deployment", "refs/heads/main", ""),
            ("pull_request", "refs/pull/123/merge", "release"),
            ("pull_request", "refs/pull/123/head", "main"),
            ("push", "refs/heads/release", ""),
        ):
            with self.subTest(event=event, ref=ref, base_ref=base_ref), self.assertRaises(ValueError):
                self.evaluate(event=event, ref=ref, base_ref=base_ref)

    def test_fork_pull_request_is_denied(self):
        with self.assertRaises(ValueError):
            self.evaluate(head_repository="attacker/baobab-dev")

    def test_main_push_is_allowed(self):
        self.assertEqual(self.evaluate(event="push", ref="refs/heads/main", base_ref="",
                                    head_repository="baobab-platform/baobab-dev")["findings"], 8)

    def test_proposal_and_schema_remain_pending_and_exactly_bounded(self):
        schema = json.loads((ROOT / "security/decisions/development/foundation.schema.json").read_text())
        proposal = json.loads((ROOT / "security/decisions/development/foundation.proposal.json").read_text())
        self.assertEqual(schema["properties"]["expires_at"]["const"], "2026-11-26T00:00:00Z")
        self.assertEqual(proposal["status"], "pending_independent_review")
        self.assertIsNone(proposal["approved_by"])
        self.assertEqual(proposal["execution_scope"], {"pull_request_base": "main", "pull_request_head_repository": "baobab-platform/baobab-dev", "push_ref": "refs/heads/main"})
        self.assertEqual({item["cve"] for item in proposal["findings"]}, set(CVES))
        self.assertEqual(proposal["expires_at"], "2026-11-26T00:00:00Z")

if __name__ == "__main__":
    unittest.main()
