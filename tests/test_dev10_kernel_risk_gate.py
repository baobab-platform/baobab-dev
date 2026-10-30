"""Negative controls for short-lived, package-scoped DEV-10 risk acceptance."""
from __future__ import annotations

import datetime as dt
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "dev10_kernel_risk_gate", ROOT / "scripts/dev10_kernel_risk_gate.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

INVENTORY = ROOT / "docs/assessments/dev10-kernel-cves.tsv"
NOW = dt.datetime(2026, 10, 30, 10, tzinfo=dt.timezone.utc)


class DevelopmentRiskGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.allowed = mod.inventory(INVENTORY)

    def report(self):
        return {"Results": [{
            "Target": "ubuntu 26.04", "Type": "ubuntu",
            "Vulnerabilities": [{
                "VulnerabilityID": cve, "PkgName": "linux-libc-dev",
                "InstalledVersion": "7.0.0-42.42", "Severity": severity,
            } for cve, severity in self.allowed.items()],
        }]}

    def qualify(self, report=None, **extra):
        args = dict(target="final", platform="linux/amd64",
                    event="pull_request", ref="refs/pull/48/merge",
                    repository="baobab-platform/baobab-dev", pr_number=48, now=NOW)
        args.update(extra)
        return mod.validate(report if report is not None else self.report(),
                            self.allowed, **args)

    def test_real_inventory_approved_scope_for_pr48(self):
        result = self.qualify()
        self.assertEqual(result["known_cves_observed"], 295)
        self.assertEqual(result["critical"], 12)
        self.assertEqual(result["decision"], "development_risk_accepted_not_remediated")

    def test_dependent_dev14_pr50_allowed_under_same_expiry(self):
        result = self.qualify(pr_number=50, ref="refs/pull/50/merge")
        self.assertEqual(result["known_cves_observed"], 295)
        self.assertEqual(result["decision"], "development_risk_accepted_not_remediated")

    def test_development_main_allowed_but_never_a_tag(self):
        self.qualify(event="push", ref="refs/heads/main", pr_number=0)
        with self.assertRaises(mod.RiskGateError):
            self.qualify(event="push", ref="refs/tags/v1.5.0", pr_number=0)
        with self.assertRaises(mod.RiskGateError):
            self.qualify(pr_number=50, ref="refs/pull/48/merge")

    def test_wrong_pr_arch_and_repo_denied(self):
        for kwargs in (
            {"pr_number": 49}, {"platform": "linux/s390x"}, {"target": "backend"},
            {"repository": "baobab-platform/baobab-trade"},
            {"event": "workflow_dispatch", "ref": "refs/heads/main"},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(mod.RiskGateError):
                self.qualify(**kwargs)

    def test_expired(self):
        with self.assertRaises(mod.RiskGateError):
            self.qualify(now=dt.datetime(2026, 11, 13, tzinfo=dt.timezone.utc))

    def test_other_cve_or_package_or_version_or_severity_denied(self):
        for key, value in (
            ("VulnerabilityID", "CVE-2026-999999"),
            ("PkgName", "openssl"), ("InstalledVersion", "7.0.0-43.43"),
            ("Severity", "LOW"), ("FixedVersion", "7.0.0-43.43"),
        ):
            with self.subTest(field=key), self.assertRaises(mod.RiskGateError):
                report = self.report()
                report["Results"][0]["Vulnerabilities"][0][key] = value
                self.qualify(report)

    def test_secret_denied(self):
        report = self.report()
        report["Results"][0]["Secrets"] = [{"RuleID": "credential"}]
        with self.assertRaises(mod.RiskGateError):
            self.qualify(report)

    def test_missing_inventory_invalid_report_and_duplicate_denied(self):
        for report in (
            {}, {"Results": []},
            {"Results": [{"Target": "ubuntu", "Type": "ubuntu", "Vulnerabilities": []}]},
        ):
            with self.subTest(report=report), self.assertRaises(mod.RiskGateError):
                self.qualify(report)
        report = self.report()
        report["Results"][0]["Vulnerabilities"].append(
            report["Results"][0]["Vulnerabilities"][0].copy())
        with self.assertRaises(mod.RiskGateError):
            self.qualify(report)

    def test_pinned_inventory_digest_blocks_unreviewed_edit(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as d:
            p = Path(d) / "inventory.tsv"
            p.write_bytes(INVENTORY.read_bytes() + b"\nCVE-2099-12345\tHIGH\tnot approved\n")
            with self.assertRaises(mod.RiskGateError):
                mod.inventory(p)


if __name__ == "__main__":
    unittest.main()
