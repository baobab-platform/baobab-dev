"""DEV-10 approval verification: real Ed25519 signatures and fail-closed negatives.

Test keys are ephemeral and MUST NOT be used as production trust authority.
"""
import base64
import copy
import datetime as dt
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
def load(path, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

policy = load("scripts/verify_dev10_vex.py", "vexpolicy")
builder = load("scripts/build_dev10_applicability_register.py", "cveregister")


class ApplicabilityTests(unittest.TestCase):
    def test_all_295_are_under_investigation_not_approved(self):
        result = builder.build(
            builder.tsv(ROOT / "docs/assessments/dev10-kernel-cves.tsv"),
            builder.tsv(ROOT / "docs/assessments/dev10-canonical-cve-status-20261030.tsv"))
        self.assertEqual(len(result["records"]), 295)
        self.assertEqual(result["counts"], {"under_investigation": 295})
        self.assertTrue(all(x["approved_disposition"] is None for x in result["records"]))
        self.assertTrue(all(x["binary_exposure"]["abi_uapi_compiler_transitive"]
                            == "under_investigation" for x in result["records"]))

    def test_missing_ubuntu_patch_never_becomes_not_affected(self):
        scanner = builder.tsv(ROOT / "docs/assessments/dev10-kernel-cves.tsv")
        vendor = builder.tsv(ROOT / "docs/assessments/dev10-canonical-cve-status-20261030.tsv")
        upstream = {"upstream_commit": builder.SOURCE_SHA, "records": [
            {"cve": row["cve"], "upstream_paths": ["net/driver.c"],
             "affected_headers": [], "matching_shipped_uapi_headers": [],
             "upstream_url": "https://example.invalid/a", "classification": "KERNEL_IMPLEMENTATION_PATHS_REVIEW_REQUIRED",
             "error": ""} for row in scanner]}
        report = builder.build(scanner, vendor, upstream)
        self.assertEqual(report["counts"], {"under_investigation": 295})
        self.assertEqual(report["records"][0]["ubuntu_source"]["source_diff_verified"], False)
        upstream["records"].pop()
        with self.assertRaisesRegex(ValueError, "295"):
            builder.build(scanner, vendor, upstream)


class SignedVEXTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        folder = Path(self.temp.name)
        self.key = folder / "test.key"
        self.public = folder / "test.pub"
        subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(self.key)],
                       check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", str(self.key), "-pubout",
                        "-out", str(self.public)], check=True, capture_output=True)
        self.now = dt.datetime(2026, 10, 30, 12, 0, tzinfo=dt.timezone.utc)
        self.digest = "a" * 64
        self.purl = "pkg:oci/baobab-dev@sha256:" + self.digest + "?repository_url=ghcr.io/baobab-platform/baobab-dev"
        self.cve = "CVE-2026-89530"
        self.report = {"ArtifactName": "dev10-scan-image", "Results": [
            {"Target": "ubuntu:26.04", "Vulnerabilities": [
                {"VulnerabilityID": self.cve, "PkgName": "linux-libc-dev",
                 "InstalledVersion": "7.0.0-42.42", "Severity": "CRITICAL"}]}]}
        self.register = builder.build(
            builder.tsv(ROOT / "docs/assessments/dev10-kernel-cves.tsv"),
            builder.tsv(ROOT / "docs/assessments/dev10-canonical-cve-status-20261030.tsv"))
        self.vendor = next(row["canonical"]["status"] for row in self.register["records"]
                           if row["cve"] == self.cve)
        self.trust = {"authorised_approvers": {"principal-checker": {
            "key_id": "test-key-1", "permission": "security:vex:approve",
            "scope": "baobab-platform/baobab-dev", "public_key_pem": self.public.read_text(),
            "valid_from": "2026-10-01T00:00:00Z", "valid_until": "2026-12-01T00:00:00Z"}},
            "revoked_keys": [], "revoked_decisions": []}
        self.decision = {
            "schema": "baobab.dev10.vex-approval.v1",
            "decision_id": "SEC-TEST-ONLY-1", "decision": "approved",
            "approver_principal": "principal-checker", "approval_key_id": "test-key-1",
            "preparer_principal": "principal-preparer",
            "engineering_author_principal": "principal-author",
            "source_revision": "b" * 40,
            "raw_trivy_sha256": hashlib.sha256(policy.canonical(self.report)).hexdigest(),
            "evidence_sha256": "c" * 64, "platform": "linux/amd64",
            "image_digest": "sha256:" + self.digest, "image_purl": self.purl,
            "issued_at": "2026-10-30T09:00:00Z", "expires_at": "2026-11-07T09:00:00Z",
            "cve_decisions": [{
                "cve": self.cve, "status": "not_affected",
                "justification": "vulnerable_code_not_present",
                "canonical_vendor_status": self.vendor,
                "review_reasoning": ("Synthetic unit-test reasoning only; exact downstream "
                                      "headers and compiler ABI paths are simulated, "
                                      "not real security evidence or release clearance."),
                "ubuntu_patch_review_reference": "fixture-ubuntu-diff",
                "indirect_uapi_abi_review_reference": "fixture-uapi-evidence",
                "review_reference": "fixture-independent-review",
                "per_cve_evidence_sha256": "d" * 64
            }]
        }

    def sign(self):
        folder = Path(self.temp.name)
        (folder / "decision.json").write_bytes(policy.canonical(self.decision))
        subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin",
                        "-inkey", str(self.key), "-in", str(folder / "decision.json"),
                        "-out", str(folder / "decision.sig")], check=True, capture_output=True)
        return {"decision": copy.deepcopy(self.decision),
                "signature": base64.b64encode((folder / "decision.sig").read_bytes()).decode()}

    def check(self, signed=None, **kwargs):
        return policy.qualify(self.report, signed or self.sign(), self.trust,
                              register=self.register, image_digest=kwargs.get("digest", self.digest),
                              platform=kwargs.get("platform", "linux/amd64"),
                              image_purl=kwargs.get("purl", self.purl), now=self.now)

    def test_valid_ephemeral_signed_approval_scopes_one_cve(self):
        vex, remaining = self.check()
        self.assertEqual(remaining, [])
        self.assertEqual(len(vex["statements"]), 1)
        self.assertEqual(vex["statements"][0]["products"][0]["@id"], self.purl)

    def test_missing_or_unsigned_approval_fails(self):
        with self.assertRaises(policy.PolicyError):
            self.check({"decision": self.decision})

    def test_forged_decision_after_signature_fails(self):
        signed = self.sign()
        signed["decision"]["cve_decisions"][0]["review_reasoning"] += " MODIFIED"
        with self.assertRaisesRegex(policy.PolicyError, "signature"):
            self.check(signed)

    def test_self_approval_fails_even_with_valid_signature(self):
        self.decision["engineering_author_principal"] = "principal-checker"
        with self.assertRaisesRegex(policy.PolicyError, "maker-checker"):
            self.check()

    def test_wrong_digest_and_architecture_fail(self):
        with self.assertRaisesRegex(policy.PolicyError, "mismatch"):
            self.check(digest="e" * 64, purl=self.purl.replace(self.digest, "e" * 64))
        with self.assertRaisesRegex(policy.PolicyError, "mismatch"):
            self.check(platform="linux/arm64")

    def test_expired_or_revoked_fails(self):
        self.decision["expires_at"] = "2026-10-29T00:00:00Z"
        with self.assertRaisesRegex(policy.PolicyError, "expired"):
            self.check()
        self.decision["expires_at"] = "2026-11-07T09:00:00Z"
        self.trust["revoked_decisions"] = ["SEC-TEST-ONLY-1"]
        with self.assertRaisesRegex(policy.PolicyError, "revoked"):
            self.check()

    def test_rejection_and_need_more_evidence_block(self):
        for value in ("rejected", "needs_evidence"):
            self.decision["decision"] = value
            with self.assertRaisesRegex(policy.PolicyError, "rejected or requested"):
                self.check()

    def test_new_unreviewed_cve_still_blocks(self):
        self.report["Results"][0]["Vulnerabilities"].append({
            "VulnerabilityID": "CVE-2026-98863", "PkgName": "linux-libc-dev",
            "InstalledVersion": "7.0.0-42.42", "Severity": "HIGH"})
        self.decision["raw_trivy_sha256"] = hashlib.sha256(policy.canonical(self.report)).hexdigest()
        vex, remaining = self.check()
        self.assertEqual(len(vex["statements"]), 1)
        self.assertEqual(remaining, [("CVE-2026-98863", "linux-libc-dev", "7.0.0-42.42")])

    def test_missing_evidence_fails(self):
        self.decision["cve_decisions"][0]["indirect_uapi_abi_review_reference"] = ""
        with self.assertRaisesRegex(policy.PolicyError, "individual Ubuntu"):
            self.check()

    def test_scanner_inventory_tampering_fails(self):
        self.report["Results"][0]["Vulnerabilities"][0]["Severity"] = "HIGH"
        with self.assertRaisesRegex(policy.PolicyError, "scanner evidence"):
            self.check()

    def test_untrusted_reviewer_fails(self):
        self.trust["authorised_approvers"] = {}
        with self.assertRaisesRegex(policy.PolicyError, "authority"):
            self.check()


if __name__ == "__main__":
    unittest.main()
