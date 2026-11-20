from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "security/evidence/dev10-image-observed-cves-41.lock.json"
TSV_PATH = ROOT / "docs/assessments/dev10-image-observed-cves-41.tsv"


class ObservedImageCveReconciliationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
        with TSV_PATH.open(encoding="utf-8", newline="") as stream:
            cls.rows = list(csv.DictReader(stream, delimiter="\t"))

    def test_supplemental_inventory_is_exact_and_fail_closed(self) -> None:
        lock = self.lock
        inventory = lock["inventory_reconciliation"]
        extra = inventory["additional_41_inventory"]
        self.assertEqual(lock["schema"], "baobab.dev10.observed-image-cve-reconciliation.v1")
        self.assertEqual(lock["status"], "OBSERVED_SCAN_EVIDENCE_ONLY_NO_VEX_NO_EXCEPTION")
        self.assertEqual(len(self.rows), 41)
        ids = [row["cve"] for row in self.rows]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(set(ids), set(lock["additional_41_cves"]))
        blob = TSV_PATH.read_bytes()
        git_blob = hashlib.sha1(b"blob " + str(len(blob)).encode("ascii") + b"\0" + blob).hexdigest()
        self.assertEqual(git_blob, extra["git_blob_sha1"])
        self.assertEqual(extra["count"], 41)
        self.assertEqual(extra["all_binary_applicability"], "under_investigation")
        self.assertEqual(extra["all_vex_disposition"], "under_investigation")
        self.assertTrue(all(row["binary_applicability"] == "under_investigation" for row in self.rows))
        self.assertTrue(all(row["vex_disposition"] == "under_investigation" for row in self.rows))
        self.assertTrue(all(row["fixed_version"] == "" for row in self.rows))

    def test_historical_and_extended_inventories_remain_immutable(self) -> None:
        inventory = self.lock["inventory_reconciliation"]
        for key in ("historical_295", "extended_298"):
            entry = inventory[key]
            path = ROOT / entry["path"]
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), entry["sha256"])
            self.assertEqual(entry["mutation"], "none")
        with (ROOT / inventory["historical_295"]["path"]).open(encoding="utf-8", newline="") as stream:
            historical = {row["cve"] for row in csv.DictReader(stream, delimiter="\t")}
        with (ROOT / inventory["extended_298"]["path"]).open(encoding="utf-8", newline="") as stream:
            extended = {row["cve"] for row in csv.DictReader(stream, delimiter="\t")}
        extra = set(self.lock["additional_41_cves"])
        self.assertEqual(len(historical), 295)
        self.assertEqual(len(extended), 298)
        self.assertTrue(historical.issubset(extended))
        self.assertTrue(extra.isdisjoint(extended))

    def test_eight_profile_architecture_artifacts_reconcile_to_52(self) -> None:
        lock = self.lock
        scan = lock["scan_run"]
        artifacts = lock["profile_architecture_artifacts"]
        self.assertEqual(scan["findings_per_profile_architecture"], 52)
        self.assertEqual(scan["severity_counts"], {"HIGH": 49, "CRITICAL": 3})
        self.assertEqual(len(artifacts), 8)
        self.assertEqual(len({(x["profile"], x["architecture"]) for x in artifacts}), 8)
        self.assertEqual(len({x["artifact_id"] for x in artifacts}), 8)
        for artifact in artifacts:
            self.assertRegex(artifact["artifact_sha256"], r"^[a-f0-9]{64}$")
        observed = lock["inventory_reconciliation"]["observed_scan_set"]
        self.assertEqual(observed["unique_findings"], 52)
        self.assertEqual(observed["overlap_with_extended_298"], 11)
        self.assertEqual(observed["additional_findings"], 41)
        self.assertEqual(observed["additional_severity_counts"], {"HIGH": 38, "CRITICAL": 3})
        self.assertTrue(set(lock["overlap_cves"]).isdisjoint(lock["additional_41_cves"]))
        self.assertEqual(len(lock["overlap_cves"]), 11)

    def test_binary_applicability_gap_is_not_misrepresented_as_clearance(self) -> None:
        gap = self.lock["binary_applicability_gap"]
        self.assertFalse(gap["trivy_package_path_available"])
        self.assertEqual(gap["status"], "NOT_ASSESSED_FOR_ADDITIONAL_41_OR_ARM64")
        self.assertEqual(gap["binary_manifest_architecture"], "amd64")
        self.assertEqual(gap["source_audit_inventory_count"], 298)
        self.assertEqual(gap["existing_298_upstream_header_path_count"], 48)
        self.assertEqual(gap["existing_298_exact_shipped_uapi_path_matches"], 0)
        policy = self.lock["policy_boundary"]
        self.assertFalse(policy["new_41_findings_added_to_298_inventory"])
        self.assertFalse(policy["added_to_295_historical_inventory"])
        self.assertFalse(policy["risk_acceptance"])
        self.assertFalse(policy["vex"])
        self.assertFalse(policy["suppression"])
        self.assertFalse(policy["release_authorization"])
        self.assertFalse(policy["publication_or_promotion_authorization"])


if __name__ == "__main__":
    unittest.main()
