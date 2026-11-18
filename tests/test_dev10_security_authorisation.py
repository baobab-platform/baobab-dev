"""DEV-10 approval verification: real Ed25519 signatures and fail-closed negatives.

Test keys are ephemeral and MUST NOT be used as production trust authority.
"""
import base64
import copy
import datetime as dt
import hashlib
import importlib.util
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


def canonical_osv_fixture(scanner, retrieved_at=None):
    return {
        "source_commit": builder.LOCK.canonical_osv_commit,
        "retrieved_at": retrieved_at or dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "target_binary_version": builder.LOCK.package_version,
        "record_count": len(scanner),
        "counts": {"TARGET_BINARY_VERSION_LISTED_AS_AFFECTED": len(scanner)},
        "records": [{
            "cve": row["cve"], "raw_sha256": "f" * 64,
            "modified": "2026-11-17T14:57:09Z",
            "release_evidence": "TARGET_BINARY_VERSION_LISTED_AS_AFFECTED",
            "ubuntu_26_04_linux_source_entries": [{
                "source_package": "linux", "source_package_version": "7.0.0-43.43",
                "linux_libc_dev_binary_versions": ["7.0.0-43.43"],
                "target_binary_version_listed": True,
                "target_version_in_affected_versions": True,
                "canonical_fixed_versions": [],
            }],
            "disposition": "UNDER_INVESTIGATION_NO_VEX_NO_EXCEPTION",
        } for row in scanner],
    }


class ApplicabilityTests(unittest.TestCase):
    def test_historical_ghcr_profile_digests_and_signer_are_locked(self):
        images = builder.LOCK.stable_profile_images
        self.assertEqual(set(images), {"final", "frontend", "frontend-e2e", "infra"})
        for profile, image in images.items():
            with self.subTest(profile=profile):
                self.assertRegex(image["index_digest"], r"^sha256:[a-f0-9]{64}$")
                self.assertEqual(image["release_tag"], "v1.5.1")
                self.assertEqual(image["signer_tag"], "v1.5.1-rc.2")
                self.assertEqual(image["source_sha"], "13493b24d6af1a9e7bddf7df9be555d1c06a635d")
                self.assertGreater(image["ga_reuse_run_id"], 0)
                self.assertGreater(image["signer_run_id"], 0)

    def test_all_298_are_under_investigation_not_approved(self):
        result = builder.build(
            builder.tsv(ROOT / "docs/assessments/dev10-kernel-cves-298.tsv"),
            builder.tsv(ROOT / "docs/assessments/dev10-canonical-cve-status-20261118.tsv"))
        self.assertEqual(len(result["records"]), 298)
        self.assertEqual(result["counts"], {"under_investigation": 298})
        self.assertTrue(all(x["approved_disposition"] is None for x in result["records"]))
        self.assertTrue(all(x["binary_exposure"]["abi_uapi_compiler_transitive"]
                            == "under_investigation" for x in result["records"]))

    def test_register_does_not_claim_historical_inventory_was_scanned_at_43_43(self):
        scanner = builder.tsv(ROOT / "docs/assessments/dev10-kernel-cves-298.tsv")
        canonical = builder.tsv(ROOT / "docs/assessments/dev10-canonical-cve-status-20261118.tsv")
        report = builder.build(scanner, canonical)
        records = {row["cve"]: row for row in report["records"]}
        self.assertEqual(
            records["CVE-2026-98869"]["inventory_provenance"]["origin"],
            "new_298_cve_extension",
        )
        self.assertEqual(
            records["CVE-2026-89530"]["inventory_provenance"]["origin"],
            "historical_295_cve_inventory",
        )
        self.assertEqual(
            records["CVE-2026-89530"]["inventory_provenance"]["historical_inventory_package_version"],
            "7.0.0-42.42",
        )
        self.assertNotIn("scanned_package", records["CVE-2026-89530"])
        self.assertNotIn("manifest_sha256", records["CVE-2026-89530"]["binary_exposure"])
        self.assertNotIn("binary_manifest_sha256", report["source_provenance"])

    def test_each_cve_scan_provenance_names_only_evidenced_package_versions(self):
        scanner = builder.tsv(ROOT / "docs/assessments/dev10-kernel-cves-298.tsv")
        canonical = builder.tsv(ROOT / "docs/assessments/dev10-canonical-cve-status-20261118.tsv")
        report = builder.build(scanner, canonical)
        records = {row["cve"]: row for row in report["records"]}
        def versions(cve):
            return {item["package_version"] for item in records[cve]["scan_provenance"]}
        self.assertEqual(versions("CVE-2026-89530"), {"7.0.0-42.42"})
        self.assertEqual(
            versions("CVE-2022-50240"),
            {"7.0.0-42.42", "7.0.0-43.43"},
        )
        self.assertEqual(versions("CVE-2026-98869"), {"7.0.0-43.43"})
        for cve, record in records.items():
            claimed_43 = any(
                item["package_version"] == "7.0.0-43.43"
                for item in record["scan_provenance"]
            )
            self.assertEqual(claimed_43, cve in builder.LOCK.observed_kernel_cves)
            for item in record["scan_provenance"]:
                if item["package_version"] == "7.0.0-43.43":
                    self.assertEqual(item["run_id"], builder.LOCK.profile_scan_run_id)
                    self.assertEqual(item["profile_architecture_artifact_count"], 8)
                    self.assertTrue(item["observed_on_43_43"])

    def test_three_new_kernel_advisories_are_in_the_canonical_join(self):
        scanner = builder.tsv(ROOT / "docs/assessments/dev10-kernel-cves-298.tsv")
        canonical = builder.tsv(ROOT / "docs/assessments/dev10-canonical-cve-status-20261118.tsv")
        expected = {"CVE-2026-98869", "CVE-2026-98890", "CVE-2026-99083"}
        self.assertTrue(expected.issubset({row["cve"] for row in scanner}))
        joined = {row["cve"]: row for row in canonical}
        self.assertEqual(joined["CVE-2026-98869"]["ubuntu_linux_resolute_status"], "Vulnerable")
        self.assertEqual(joined["CVE-2026-98890"]["ubuntu_linux_resolute_status"], "Vulnerable")
        self.assertIn("Vulnerable", joined["CVE-2026-99083"]["ubuntu_linux_resolute_status"])
        self.assertIn("7.0.0-44.44", joined["CVE-2026-99083"]["canonical_pending_version_or_detail"])

    def test_live_upstream_revision_is_propagated_without_security_clearance(self):
        scanner = builder.tsv(ROOT / "docs/assessments/dev10-kernel-cves-298.tsv")
        vendor = builder.tsv(ROOT / "docs/assessments/dev10-canonical-cve-status-20261118.tsv")
        current_sha = builder.SOURCE_SHA
        upstream = {"upstream_commit": current_sha, "records": [
            {"cve": row["cve"], "upstream_paths": ["net/driver.c"],
             "affected_headers": [], "matching_shipped_uapi_headers": [],
             "classification": "KERNEL_IMPLEMENTATION_PATHS_REVIEW_REQUIRED",
             "error": ""} for row in scanner]}
        report = builder.build(scanner, vendor, upstream)
        self.assertEqual(report["source_provenance"]["upstream_linux_cna_revision"], current_sha)
        self.assertTrue(all(row["upstream"]["source_revision"] == current_sha
                            and row["approved_disposition"] is None for row in report["records"]))
        self.assertEqual(report["decision"], "SECURITY_HELD_NO_EXCEPTION_APPROVED")
        upstream["upstream_commit"] = "master"
        with self.assertRaisesRegex(ValueError, "evidence lock"):
            builder.build(scanner, vendor, upstream)

    def test_ubuntu_tag_paths_are_joined_per_cve_without_claiming_a_fix(self):
        scanner = builder.tsv(ROOT / "docs/assessments/dev10-kernel-cves-298.tsv")
        canonical = builder.tsv(ROOT / "docs/assessments/dev10-canonical-cve-status-20261118.tsv")
        tag_sha = builder.LOCK.ubuntu_tag_commit
        ubuntu = {
            "ubuntu_release_tag": builder.LOCK.ubuntu_tag,
            "ubuntu_source_commit": tag_sha,
            "path_counts": {"PATHS_PRESENT_NONDISCRIMINATING": 298},
            "binary_manifest": {
                "package": "linux-libc-dev=7.0.0-43.43",
                "sha256": builder.LOCK.binary_manifest_sha256, "path_count": builder.LOCK.binary_manifest_path_count, "header_count": builder.LOCK.header_count,
            },
            "records": [{
                "cve": row["cve"],
                "ubuntu_release_tag": "Ubuntu-7.0.0-43.43",
                "ubuntu_release_tag_commit": tag_sha,
                "ubuntu_source_paths_present": ["kernel/example.c"],
                "upstream_paths_missing_from_ubuntu_snapshot": [],
                "ubuntu_source_path_status": "PATHS_PRESENT_NONDISCRIMINATING",
                "upstream_path_correspondence": [{
                    "upstream_path": "kernel/example.c",
                    "ubuntu_tag_status": "present",
                    "same_basename_candidates": [],
                }],
                "direct_binary_manifest_uapi_path_matches": [],
                "kernel_private_header_paths": [],
                "upstream_candidate_fix_references": [],
                "ubuntu_fix_commit_verified": False,
            } for row in scanner],
        }
        upstream = {
            "upstream_commit": builder.SOURCE_SHA,
            "records": [{
                "cve": row["cve"], "upstream_paths": ["kernel/example.c"],
                "affected_headers": [], "matching_shipped_uapi_headers": [],
                "classification": "KERNEL_IMPLEMENTATION_PATHS_REVIEW_REQUIRED",
                "error": "",
            } for row in scanner],
        }
        result = builder.build(scanner, canonical, upstream, ubuntu, canonical_osv_fixture(scanner))
        self.assertEqual(result["source_provenance"]["ubuntu_source_tag"], "Ubuntu-7.0.0-43.43")
        self.assertEqual(result["source_provenance"]["ubuntu_source_commit"], tag_sha)
        first = result["records"][0]["ubuntu_source"]
        self.assertEqual(first["source_paths_present"], ["kernel/example.c"])
        self.assertEqual(first["ubuntu_source_path_status"], "PATHS_PRESENT_NONDISCRIMINATING")
        self.assertEqual(first["upstream_path_correspondence"][0]["ubuntu_tag_status"], "present")
        self.assertFalse(first["ubuntu_fix_commit_verified"])
        self.assertEqual(first["binary_header_diff_verified"], False)

    def test_register_carries_computed_manifest_digest_only_from_captured_evidence(self):
        scanner = builder.tsv(ROOT / "docs/assessments/dev10-kernel-cves-298.tsv")
        canonical = builder.tsv(ROOT / "docs/assessments/dev10-canonical-cve-status-20261118.tsv")
        ubuntu = {
            "ubuntu_release_tag": "Ubuntu-7.0.0-43.43",
            "ubuntu_source_commit": builder.LOCK.ubuntu_tag_commit,
            "path_counts": {"PATHS_PRESENT_NONDISCRIMINATING": 298},
            "binary_manifest": {
                "package": "linux-libc-dev=7.0.0-43.43",
                "sha256": builder.LOCK.binary_manifest_sha256, "path_count": builder.LOCK.binary_manifest_path_count, "header_count": builder.LOCK.header_count,
            },
            "records": [{
                "cve": row["cve"], "ubuntu_release_tag": "Ubuntu-7.0.0-43.43",
                "ubuntu_release_tag_commit": builder.LOCK.ubuntu_tag_commit,
                "ubuntu_source_paths_present": ["kernel/example.c"],
                "upstream_paths_missing_from_ubuntu_snapshot": [],
                "ubuntu_source_path_status": "PATHS_PRESENT_NONDISCRIMINATING",
                "upstream_path_correspondence": [],
                "direct_binary_manifest_uapi_path_matches": [],
                "kernel_private_header_paths": [],
                "upstream_candidate_fix_references": [],
            } for row in scanner],
        }
        report = builder.build(scanner, canonical, None, ubuntu, canonical_osv_fixture(scanner))
        self.assertEqual(
            report["source_provenance"]["binary_manifest"]["sha256"], builder.LOCK.binary_manifest_sha256
        )
        self.assertNotIn("manifest_sha256", report["records"][0]["binary_exposure"])

        wrong = copy.deepcopy(ubuntu)
        wrong["binary_manifest"]["sha256"] = "b" * 64
        with self.assertRaisesRegex(ValueError, "manifest digest differs"):
            builder.build(scanner, canonical, None, wrong, canonical_osv_fixture(scanner))

    def test_fresh_canonical_osv_join_is_digested_and_not_a_disposition(self):
        scanner = builder.tsv(ROOT / "docs/assessments/dev10-kernel-cves-298.tsv")
        vendor = builder.tsv(ROOT / "docs/assessments/dev10-canonical-cve-status-20261118.tsv")
        upstream = {"upstream_commit": builder.SOURCE_SHA, "records": [
            {"cve": row["cve"], "upstream_paths": ["kernel/example.c"],
             "affected_headers": [], "matching_shipped_uapi_headers": [],
             "classification": "KERNEL_IMPLEMENTATION_PATHS_REVIEW_REQUIRED", "error": ""}
            for row in scanner
        ]}
        osv = canonical_osv_fixture(scanner)
        tag_sha = builder.LOCK.ubuntu_tag_commit
        ubuntu = {
            "ubuntu_release_tag": builder.LOCK.ubuntu_tag,
            "ubuntu_source_commit": tag_sha,
            "path_counts": {"PATHS_PRESENT_NONDISCRIMINATING": 298},
            "binary_manifest": {
                "package": "linux-libc-dev=7.0.0-43.43",
                "sha256": "a" * 64, "path_count": 1300, "header_count": 1039,
            },
            "records": [{
                "cve": row["cve"], "ubuntu_release_tag": builder.LOCK.ubuntu_tag,
                "ubuntu_release_tag_commit": tag_sha,
                "ubuntu_source_paths_present": ["kernel/example.c"],
                "upstream_paths_missing_from_ubuntu_snapshot": [],
                "ubuntu_source_path_status": "PATHS_PRESENT_NONDISCRIMINATING",
                "upstream_path_correspondence": [],
                "direct_binary_manifest_uapi_path_matches": [],
                "kernel_private_header_paths": [],
                "upstream_candidate_fix_references": [],
            } for row in scanner],
        }
        report = builder.build(scanner, vendor, upstream, ubuntu, osv)
        row = report["records"][0]
        self.assertEqual(row["canonical_osv"]["raw_sha256"], "f" * 64)
        self.assertEqual(row["canonical_osv"]["source_commit"], builder.LOCK.canonical_osv_commit)
        self.assertEqual(row["canonical_osv"]["disposition"] if "disposition" in row["canonical_osv"] else None, None)
        self.assertEqual(row["approved_disposition"], None)
        stale = dict(osv)
        stale["retrieved_at"] = "2026-10-01T00:00:00Z"
        with self.assertRaisesRegex(ValueError, "freshness window"):
            builder.build(scanner, vendor, upstream, ubuntu, stale)
        wrong = dict(osv)
        wrong["source_commit"] = "0" * 40
        with self.assertRaisesRegex(ValueError, "evidence lock"):
            builder.build(scanner, vendor, upstream, ubuntu, wrong)

    def test_missing_ubuntu_patch_never_becomes_not_affected(self):
        scanner = builder.tsv(ROOT / "docs/assessments/dev10-kernel-cves-298.tsv")
        vendor = builder.tsv(ROOT / "docs/assessments/dev10-canonical-cve-status-20261118.tsv")
        upstream = {"upstream_commit": builder.SOURCE_SHA, "records": [
            {"cve": row["cve"], "upstream_paths": ["net/driver.c"],
             "affected_headers": [], "matching_shipped_uapi_headers": [],
             "upstream_url": "https://example.invalid/a", "classification": "KERNEL_IMPLEMENTATION_PATHS_REVIEW_REQUIRED",
             "error": ""} for row in scanner]}
        report = builder.build(scanner, vendor, upstream)
        self.assertEqual(report["counts"], {"under_investigation": 298})
        self.assertEqual(report["records"][0]["ubuntu_source"]["source_diff_verified"], False)
        upstream["records"].pop()
        with self.assertRaisesRegex(ValueError, "298"):
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
        self.package_purl = "pkg:deb/ubuntu/linux-libc-dev@7.0.0-43.43?arch=amd64"
        self.report = {"ArtifactName": "dev10-scan-image", "Results": [
            {"Target": "ubuntu:26.04", "Vulnerabilities": [
                {"VulnerabilityID": self.cve, "PkgName": "linux-libc-dev",
                 "InstalledVersion": "7.0.0-43.43", "Severity": "CRITICAL",
                 "PkgIdentifier": {"PURL": self.package_purl}}]}]}
        scanner = builder.tsv(ROOT / "docs/assessments/dev10-kernel-cves-298.tsv")
        self.register = builder.build(
            scanner,
            builder.tsv(ROOT / "docs/assessments/dev10-canonical-cve-status-20261118.tsv"),
            canonical_osv=canonical_osv_fixture(scanner, "2026-10-30T11:00:00Z"),
            now=self.now)
        # Ephemeral test-only proof flags; no production evidence or approval.
        reviewed = next(row for row in self.register["records"] if row["cve"] == self.cve)
        reviewed["ubuntu_source"].update({
            "source_diff_verified": True, "binary_header_diff_verified": True,
            "patch_commit_references": ["fixture-upstream-commit"],
            "downstream_changed_paths": ["net/fixture.c"],
        })
        reviewed["binary_exposure"].update({
            "shipped_header_inline_macro": "not_affected",
            "abi_uapi_compiler_transitive": "not_affected",
            "downstream_userspace_compilation": "not_affected",
        })
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
            "evidence_sha256": hashlib.sha256(policy.canonical(self.register)).hexdigest(),
            "platform": "linux/amd64",
            "risk_owner_principal": "principal-risk-owner",
            "risk_acceptance_reason": "Test-only scoped synthetic risk ownership to validate enforcement.",
            "re_review_triggers": ["new image digest", "new CVE", "expiry"],
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
                "package_purl": self.package_purl,
                "per_cve_evidence_sha256": hashlib.sha256(policy.canonical(reviewed)).hexdigest()
            }]
        }

    def refresh_register_digests(self):
        reviewed = next(row for row in self.register["records"] if row["cve"] == self.cve)
        self.decision["evidence_sha256"] = hashlib.sha256(policy.canonical(self.register)).hexdigest()
        self.decision["cve_decisions"][0]["per_cve_evidence_sha256"] = (
            hashlib.sha256(policy.canonical(reviewed)).hexdigest())

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
                              source_revision=kwargs.get("revision", "b" * 40),
                              platform=kwargs.get("platform", "linux/amd64"),
                              image_purl=kwargs.get("purl", self.purl), now=self.now)

    def test_vex_gate_rejects_missing_or_stale_canonical_osv_snapshot(self):
        original = self.register["source_provenance"]["canonical_osv_snapshot"]
        self.register["source_provenance"]["canonical_osv_snapshot"] = None
        self.refresh_register_digests()
        with self.assertRaisesRegex(ValueError, "Canonical OSV source commit"):
            self.check()
        self.register["source_provenance"]["canonical_osv_snapshot"] = dict(original)
        self.register["source_provenance"]["canonical_osv_snapshot"]["retrieved_at"] = "2026-10-01T00:00:00Z"
        self.refresh_register_digests()
        with self.assertRaisesRegex(ValueError, "stale"):
            self.check()

    def test_valid_ephemeral_signed_approval_scopes_one_cve(self):
        vex, remaining = self.check()
        self.assertEqual(remaining, [])
        self.assertEqual(len(vex["statements"]), 1)
        self.assertEqual(vex["statements"][0]["products"][0]["@id"], self.purl)
        self.assertEqual(vex["statements"][0]["products"][0]["subcomponents"][0]["@id"], self.package_purl)

    def test_signed_register_must_bind_exact_inventory_extension_and_lock(self):
        self.register["source_provenance"]["inventory_extension_cves"] = ["CVE-2026-98869"]
        self.refresh_register_digests()
        with self.assertRaisesRegex(ValueError, "inventory extension"):
            self.check()

    def test_signed_register_must_preserve_historical_record_origin(self):
        reviewed = next(row for row in self.register["records"]
                        if row["cve"] == "CVE-2026-89530")
        reviewed["inventory_provenance"]["origin"] = "new_298_cve_extension"
        self.refresh_register_digests()
        with self.assertRaisesRegex(ValueError, "historical inventory record origin"):
            self.check()

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

    def test_wrong_reviewed_source_revision_fails(self):
        with self.assertRaisesRegex(policy.PolicyError, "source revision"):
            self.check(revision="e" * 40)

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
            "InstalledVersion": "7.0.0-43.43", "Severity": "HIGH"})
        self.decision["raw_trivy_sha256"] = hashlib.sha256(policy.canonical(self.report)).hexdigest()
        vex, remaining = self.check()
        self.assertEqual(len(vex["statements"]), 1)
        self.assertEqual(remaining, [("CVE-2026-98863", "linux-libc-dev", "7.0.0-43.43")])

    def test_same_cve_unapproved_package_purl_not_suppressed(self):
        self.report["Results"][0]["Vulnerabilities"][0]["PkgIdentifier"]["PURL"] = "pkg:deb/ubuntu/other@1.0"
        self.decision["raw_trivy_sha256"] = hashlib.sha256(policy.canonical(self.report)).hexdigest()
        vex, blocking = self.check()
        self.assertEqual(len(vex["statements"]), 0)
        self.assertEqual(len(blocking), 1)

    def test_incomplete_ubuntu_patch_review_blocks_even_signed_approval(self):
        reviewed = next(row for row in self.register["records"] if row["cve"] == self.cve)
        reviewed["ubuntu_source"]["binary_header_diff_verified"] = False
        self.refresh_register_digests()
        with self.assertRaisesRegex(policy.PolicyError, "completed Ubuntu patch"):
            self.check()

    def test_unresolved_transitive_header_impact_blocks_even_signed_approval(self):
        reviewed = next(row for row in self.register["records"] if row["cve"] == self.cve)
        reviewed["binary_exposure"]["abi_uapi_compiler_transitive"] = "under_investigation"
        self.refresh_register_digests()
        with self.assertRaisesRegex(policy.PolicyError, "ABI and downstream"):
            self.check()

    def test_tampered_reviewed_register_invalidates_signed_evidence(self):
        reviewed = next(row for row in self.register["records"] if row["cve"] == self.cve)
        reviewed["technical_reasoning"] += " author-modified after approval"
        with self.assertRaisesRegex(policy.PolicyError, "applicability evidence digest mismatch"):
            self.check()

    def test_tampered_individual_cve_evidence_is_rejected(self):
        reviewed = next(row for row in self.register["records"] if row["cve"] == self.cve)
        reviewed["technical_reasoning"] += " author-modified after approval"
        self.decision["evidence_sha256"] = hashlib.sha256(policy.canonical(self.register)).hexdigest()
        with self.assertRaisesRegex(policy.PolicyError, "individual CVE evidence"):
            self.check()

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
