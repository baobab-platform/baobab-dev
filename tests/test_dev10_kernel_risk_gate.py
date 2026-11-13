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
                    event="pull_request", ref="refs/pull/68/merge",
                    repository="baobab-platform/baobab-dev", pr_number=68, now=NOW)
        args.update(extra)
        return mod.validate(report if report is not None else self.report(),
                            self.allowed, **args)

    def test_real_inventory_approved_scope_for_pr68(self):
        result = self.qualify()
        self.assertEqual(result["known_cves_observed"], 295)
        self.assertEqual(result["critical"], 12)
        self.assertEqual(result["decision"], "development_risk_accepted_not_remediated")

    def test_exact_new_ubuntu_version_eight_high_findings_accepted(self):
        report = {"Results": [{"Target": "ubuntu 26.04", "Type": "ubuntu",
            "Vulnerabilities": [
                {"VulnerabilityID": cve, "PkgName": "linux-libc-dev",
                 "InstalledVersion": "7.0.0-43.43", "Severity": "HIGH"}
                for cve in sorted(mod.ADDITIONAL_CVES)]}]}
        self.assertEqual(len(mod.ADDITIONAL_CVES), 8)
        for platform in ("linux/amd64", "linux/arm64"):
            for target in ("final", "infra", "frontend", "frontend-e2e"):
                with self.subTest(platform=platform, target=target):
                    decision = self.qualify(report, platform=platform, target=target)
                    self.assertEqual(decision["version"], "7.0.0-43.43")
                    self.assertEqual(decision["known_cves_observed"], 8)
                    self.assertEqual(decision["critical"], 0)
        for mutation in ("extra", "missing", "severity", "fixed", "package", "version"):
            import copy
            altered = copy.deepcopy(report)
            vulns = altered["Results"][0]["Vulnerabilities"]
            if mutation == "extra":
                vulns.append({**vulns[0], "VulnerabilityID": "CVE-2026-999999"})
            elif mutation == "missing":
                vulns.pop()
            elif mutation == "severity":
                vulns[0]["Severity"] = "CRITICAL"
            elif mutation == "fixed":
                vulns[0]["FixedVersion"] = "7.0.0-44.44"
            elif mutation == "package":
                vulns[0]["PkgName"] = "openssl"
            else:
                vulns[0]["InstalledVersion"] = "7.0.0-44.44"
            with self.subTest(mutation=mutation), self.assertRaises(mod.RiskGateError):
                self.qualify(altered)

    def test_only_open_pr68_is_authorised(self):
        self.assertEqual(mod.APPROVED_DEVELOPMENT_PRS, frozenset({68}))
        for number in (48, 50, 57, 58, 62, 63, 64, 65, 66, 67):
            with self.subTest(merged_pr=number), self.assertRaises(mod.RiskGateError):
                self.qualify(pr_number=number, ref=f"refs/pull/{number}/merge")
        for number in (68,):
            with self.subTest(active_pr=number):
                decision = self.qualify(pr_number=number, ref=f"refs/pull/{number}/merge")
                self.assertEqual(decision["known_cves_observed"], 295)
        result = self.qualify()
        self.assertEqual(result["known_cves_observed"], 295)
        self.assertEqual(result["expiry_utc"], "2026-11-26T00:00:00+00:00")

    def test_owner_authorised_pr68_only_through_new_expiry(self):
        self.assertEqual(mod.EXPIRY, dt.datetime(2026, 11, 26, tzinfo=dt.timezone.utc))
        for platform in ("linux/amd64", "linux/arm64"):
            for target in ("final", "infra", "frontend", "frontend-e2e"):
                with self.subTest(platform=platform, target=target):
                    result = self.qualify(pr_number=68, ref="refs/pull/68/merge",
                                          now=dt.datetime(2026, 11, 12, tzinfo=dt.timezone.utc),
                                          platform=platform, target=target)
                    self.assertEqual(result["known_cves_observed"], 295)
                    self.assertEqual(result["expiry_utc"], "2026-11-26T00:00:00+00:00")
        for event, ref, number in (
            ("pull_request", "refs/pull/68/head", 68),
            ("pull_request", "refs/pull/66/merge", 66),
            ("pull_request", "refs/pull/65/merge", 65),
            ("pull_request", "refs/pull/64/merge", 64),
            ("pull_request", "refs/pull/62/merge", 62),
            ("pull_request", "refs/pull/63/merge", 63),
            ("pull_request", "refs/pull/58/merge", 62),
            ("workflow_dispatch", "refs/pull/68/merge", 62),
            ("push", "refs/tags/v1.5.1", 0),
        ):
            with self.subTest(event=event, ref=ref, number=number):
                with self.assertRaises(mod.RiskGateError):
                    self.qualify(event=event, ref=ref, pr_number=number)
        for field, value in (
            ("VulnerabilityID", "CVE-2026-999999"),
            ("PkgName", "openssl"),
            ("InstalledVersion", "7.0.0-44.44"),
            ("FixedVersion", "7.0.0-43.43"),
        ):
            report = self.report()
            report["Results"][0]["Vulnerabilities"][0][field] = value
            with self.subTest(field=field), self.assertRaises(mod.RiskGateError):
                self.qualify(report, pr_number=68, ref="refs/pull/68/merge")
        with self.assertRaises(mod.RiskGateError):
            self.qualify(pr_number=68, ref="refs/pull/68/merge",
                         now=dt.datetime(2026, 11, 26, tzinfo=dt.timezone.utc))

    def test_pr58_staging_wrong_event_or_ref_never_inherits_dev_risk(self):
        # The owner explicitly authorised this exact tag as a *development*
        # image distribution. Its successful push/pr_number=0 case is in
        # test_v150_exact_tag_is_distributed_dev_image_not_production.
        for event, ref, number in (
            ("push", "refs/tags/v1.5.0", 58),
            ("push", "refs/tags/v1.5.1", 0),
            ("workflow_dispatch", "refs/heads/main", 58),
            ("deployment", "refs/heads/staging", 58),
            ("pull_request", "refs/pull/58/head", 58),
            ("pull_request", "refs/pull/57/merge", 58),
            ("pull_request", "refs/pull/59/merge", 59),
            ("pull_request", "refs/pull/48/merge", 58),
        ):
            with self.subTest(event=event, ref=ref, number=number):
                with self.assertRaises(mod.RiskGateError):
                    self.qualify(event=event, ref=ref, pr_number=number)

    def test_tag_v150_unknown_findings_fixes_secrets_or_expiry_still_denied(self):
        # Run every rejection against both the first RC and the final GA.
        for release_tag in ("v1.5.0-rc.1", "v1.5.0"):
            self._assert_rejected_tag_findings(release_tag)

    def _assert_rejected_tag_findings(self, release_tag):
        for field, value in (
            ("VulnerabilityID", "CVE-2026-999999"), ("PkgName", "openssl"),
            ("InstalledVersion", "7.0.0-43.43"), ("Severity", "LOW"),
            ("FixedVersion", "7.0.0-43.43"),
        ):
            report = self.report()
            report["Results"][0]["Vulnerabilities"][0][field] = value
            with self.subTest(field=field), self.assertRaises(mod.RiskGateError):
                self.qualify(report, event="push", ref=f"refs/tags/{release_tag}", pr_number=0)
        report = self.report()
        report["Results"][0]["Secrets"] = [{"RuleID": "credential"}]
        with self.assertRaises(mod.RiskGateError):
            self.qualify(report, event="push", ref=f"refs/tags/{release_tag}", pr_number=0)
        with self.assertRaises(mod.RiskGateError):
            self.qualify(event="push", ref=f"refs/tags/{release_tag}", pr_number=0,
                         now=dt.datetime(2026, 11, 26, tzinfo=dt.timezone.utc))

    def test_pr58_unknown_cve_or_fix_available_still_denied(self):
        for field, value in (
            ("VulnerabilityID", "CVE-2026-999999"),
            ("PkgName", "linux-tools"),
            ("InstalledVersion", "7.0.0-43.43"),
            ("FixedVersion", "7.0.0-43.43"),
            ("Severity", "LOW"),
        ):
            with self.subTest(field=field), self.assertRaises(mod.RiskGateError):
                report = self.report()
                report["Results"][0]["Vulnerabilities"][0][field] = value
                self.qualify(report, pr_number=68, ref="refs/pull/68/merge")
        report = self.report()
        report["Results"][0]["Secrets"] = [{"RuleID": "aws-secret"}]
        with self.assertRaises(mod.RiskGateError):
            self.qualify(report, pr_number=68, ref="refs/pull/68/merge")
        with self.assertRaises(mod.RiskGateError):
            self.qualify(pr_number=68, ref="refs/pull/68/merge",
                         now=dt.datetime(2026, 11, 26, tzinfo=dt.timezone.utc))

    def test_owner_authorised_rc_tags_are_dev_distribution_only(self):
        for candidate in ("v1.5.0-rc.1", "v1.5.0-rc.2", "v1.5.0-rc.10"):
            for platform in ("linux/amd64", "linux/arm64"):
                for target in ("final", "infra", "frontend", "frontend-e2e"):
                    with self.subTest(candidate=candidate, platform=platform, target=target):
                        result = self.qualify(
                            event="push", ref=f"refs/tags/{candidate}",
                            pr_number=0, target=target, platform=platform)
                        self.assertEqual(result["distribution"], "v1.5.0_release_candidate")
                        self.assertEqual(result["known_cves_observed"], 295)
                        self.assertIn("no staging/production", result["scope"])

    def test_v150_exact_tag_is_distributed_dev_image_not_production(self):
        for target in ("final", "infra", "frontend", "frontend-e2e"):
            for platform in ("linux/amd64", "linux/arm64"):
                with self.subTest(target=target, platform=platform):
                    result = self.qualify(event="push", ref="refs/tags/v1.5.0",
                                          pr_number=0, target=target, platform=platform)
                    self.assertEqual(result["distribution"],
                                     "v1.5.0_tagged_development_container")
                    self.assertEqual(result["known_cves_observed"], 295)
                    self.assertEqual(result["critical"], 12)
                    self.assertIn("no staging/production", result["scope"])

    def test_all_other_tag_or_deployment_contexts_denied(self):
        self.qualify(event="push", ref="refs/heads/main", pr_number=0)
        for event, ref, number in (
            ("push", "refs/tags/v1.4.4", 0),
            ("push", "refs/tags/v1.5.1", 0),
            ("push", "refs/tags/v1.6.0", 0),
            ("push", "refs/tags/v1.5.0-rc.0", 0),
            ("push", "refs/tags/v1.5.0-rc.01", 0),
            ("push", "refs/tags/v1.5.0-rc.foo", 0),
            ("push", "refs/tags/v1.5.0-rc.1-extra", 0),
            ("push", "refs/tags/v1.5.1-rc.1", 0),
            ("pull_request", "refs/tags/v1.5.0", 58),
            ("workflow_dispatch", "refs/tags/v1.5.0", 0),
            ("deployment", "refs/tags/v1.5.0", 0),
            ("push", "refs/heads/staging", 0),
            ("push", "refs/heads/production", 0),
            ("push", "refs/tags/v1.5.0", 58),
        ):
            with self.subTest(event=event, ref=ref, number=number):
                with self.assertRaises(mod.RiskGateError):
                    self.qualify(event=event, ref=ref, pr_number=number)
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
            self.qualify(now=dt.datetime(2026, 11, 26, tzinfo=dt.timezone.utc))

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
