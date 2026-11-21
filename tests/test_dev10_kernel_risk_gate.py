"""Runtime contract tests for the protected DEV-10 Foundation evaluator."""
from __future__ import annotations

import copy
import datetime as dt
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "dev10_kernel_risk_gate", ROOT / "scripts/dev10_kernel_risk_gate.py")
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)

DECISION = ROOT / "security/decisions/development/foundation.json"
LOCK = ROOT / "security/decisions/development/foundation-eight-image-evidence-lock.json"
NOW = dt.datetime(2026, 11, 21, 12, tzinfo=dt.timezone.utc)


class FoundationRuntimeDecisionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = DECISION.read_bytes()
        cls.anchor = hashlib.sha256(cls.raw).hexdigest()
        cls.authenticated = mod.load_decision(DECISION, LOCK, cls.anchor, now=NOW)
        cls.document = cls.authenticated["document"]

    def report(self, findings=None):
        selected = self.document["findings"] if findings is None else findings
        return {"Results": [{
            "Target": "ubuntu 26.04",
            "Type": "ubuntu",
            "Vulnerabilities": [{
                "VulnerabilityID": item["cve"],
                "PkgName": item["package"],
                "InstalledVersion": item["version"],
                "Severity": item["severity"],
            } for item in selected],
        }]}

    def qualify(self, report=None, **extra):
        args = dict(
            target="final", platform="linux/amd64", event="pull_request",
            ref="refs/pull/74/merge", repository=mod.REPOSITORY,
            pr_number=74, pr_base="main", head_repository=mod.REPOSITORY,
            now=NOW,
        )
        args.update(extra)
        return mod.validate(
            self.report() if report is None else report,
            self.authenticated, **args,
        )

    def test_exact_decision_and_evidence_lock_are_authenticated(self):
        self.assertEqual(len(self.authenticated["allowed"]), 30)
        self.assertEqual(self.document["finding_count"], 30)
        self.assertEqual(
            hashlib.sha256(LOCK.read_bytes()).hexdigest(),
            self.document["evidence_lock_sha256"],
        )

    def test_missing_or_mismatched_protected_anchor_fails_closed(self):
        for anchor in ("", "0" * 64, "not-a-sha256"):
            with self.subTest(anchor=anchor), self.assertRaises(mod.RiskGateError):
                mod.load_decision(DECISION, LOCK, anchor, now=NOW)

    def test_decision_or_evidence_lock_byte_change_invalidates_authentication(self):
        with tempfile.TemporaryDirectory() as directory:
            changed_decision = Path(directory) / "foundation.json"
            changed_decision.write_bytes(self.raw + b" ")
            with self.assertRaisesRegex(mod.RiskGateError, "trust anchor"):
                mod.load_decision(changed_decision, LOCK, self.anchor, now=NOW)
            changed_lock = Path(directory) / "lock.json"
            changed_lock.write_bytes(LOCK.read_bytes() + b" ")
            with self.assertRaisesRegex(mod.RiskGateError, "evidence-lock bytes"):
                mod.load_decision(DECISION, changed_lock, self.anchor, now=NOW)

    def test_exact_thirty_finding_inventory_is_accepted_in_supported_matrix(self):
        for profile in mod.PROFILES:
            for platform in mod.PLATFORMS:
                with self.subTest(profile=profile, platform=platform):
                    result = self.qualify(target=profile, platform=platform)
                    self.assertEqual(result["known_cves_observed"], 30)
                    self.assertEqual(result["critical"], 3)
                    self.assertEqual(result["decision"], "development_risk_accepted_not_remediated")
                    self.assertEqual(result["technical_applicability"], "under_investigation")

    def test_partial_remediation_subset_of_exact_inventory_is_accepted(self):
        subset = self.document["findings"][:7]
        result = self.qualify(self.report(subset))
        self.assertEqual(result["known_cves_observed"], 7)
        self.assertEqual(result["critical"], 3)

    def test_unknown_or_redefined_findings_are_denied(self):
        mutations = (
            ("unknown CVE", {"VulnerabilityID": "CVE-2026-999999"}),
            ("wrong package", {"PkgName": "openssl"}),
            ("wrong version", {"InstalledVersion": "7.0.0-43.43"}),
            ("wrong severity", {"Severity": "LOW"}),
            ("fixed version", {"FixedVersion": "7.0.0-44.44"}),
        )
        for label, mutation in mutations:
            with self.subTest(label=label):
                report = self.report()
                report["Results"][0]["Vulnerabilities"][0].update(mutation)
                with self.assertRaises(mod.RiskGateError):
                    self.qualify(report)

    def test_duplicate_missing_or_empty_inventory_is_denied(self):
        report = self.report()
        report["Results"][0]["Vulnerabilities"].append(
            copy.deepcopy(report["Results"][0]["Vulnerabilities"][0]))
        with self.assertRaisesRegex(mod.RiskGateError, "duplicate"):
            self.qualify(report)
        for invalid in ({}, {"Results": []},
                        {"Results": [{"Target": "ubuntu", "Type": "ubuntu",
                                      "Vulnerabilities": []}]}):
            with self.subTest(invalid=invalid), self.assertRaises(mod.RiskGateError):
                self.qualify(invalid)

    def test_secret_findings_and_malformed_results_are_denied(self):
        report = self.report()
        report["Results"][0]["Secrets"] = [{"RuleID": "credential"}]
        with self.assertRaisesRegex(mod.RiskGateError, "secret"):
            self.qualify(report)
        with self.assertRaises(mod.RiskGateError):
            self.qualify({"Results": [{"Target": None, "Type": "ubuntu"}]})

    def test_only_same_repository_main_pull_requests_and_main_pushes_are_allowed(self):
        allowed = self.qualify()
        self.assertEqual(allowed["version"], "7.0.0-44.44")
        self.qualify(event="push", ref="refs/heads/main", pr_number=0,
                     pr_base="", head_repository="")
        denied = (
            {"event": "pull_request", "ref": "refs/pull/74/head"},
            {"event": "pull_request", "pr_base": "release"},
            {"event": "pull_request", "head_repository": "fork/baobab-dev"},
            {"event": "push", "ref": "refs/heads/release", "pr_number": 0},
            {"event": "push", "ref": "refs/tags/v1.5.2", "pr_number": 0},
            {"event": "workflow_dispatch", "ref": "refs/heads/main"},
            {"event": "schedule", "ref": "refs/heads/main"},
            {"repository": "baobab-platform/other"},
        )
        for kwargs in denied:
            with self.subTest(kwargs=kwargs), self.assertRaises(mod.RiskGateError):
                self.qualify(**kwargs)

    def test_expiry_and_matrix_scope_are_enforced(self):
        with self.assertRaisesRegex(mod.RiskGateError, "expired"):
            self.qualify(now=dt.datetime(2026, 11, 26, tzinfo=dt.timezone.utc))
        for kwargs in ({"target": "backend"}, {"platform": "linux/s390x"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(mod.RiskGateError):
                self.qualify(**kwargs)


if __name__ == "__main__":
    unittest.main()
