"""Offline integrity tests for the supplemental 41-CVE source evidence pins."""
from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "docs/assessments/dev10-image-observed-cves-41.tsv"
CANONICAL_TSV = ROOT / "docs/assessments/dev10-image-observed-cves-41-canonical.tsv"
CANONICAL_LOCK = ROOT / "security/evidence/dev10-image-observed-cves-41-canonical.lock.json"
UPSTREAM_LOCK = ROOT / "security/evidence/dev10-image-observed-cves-41-upstream.lock.json"
SOURCE_PURL = "pkg:deb/ubuntu/linux@7.0.0-43.43?arch=source&distro=resolute"


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream, delimiter="\t"))


def git_blob_sha1(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


class Supplemental41SourceEvidenceTests(unittest.TestCase):
    def test_supplemental_inventory_is_exactly_41_and_separate(self):
        rows = read_rows(INVENTORY)
        ids = {row["cve"] for row in rows}
        self.assertEqual(len(rows), 41)
        self.assertEqual(len(ids), 41)
        self.assertTrue(all(row["binary_applicability"] == "under_investigation" for row in rows))
        self.assertTrue(all(row["vex_disposition"] == "under_investigation" for row in rows))
        self.assertEqual(git_blob_sha1(INVENTORY.read_bytes()),
                         "62ad83bd1f9b251c4561c28df847ac1941d5ddb8")

    def test_canonical_snapshot_and_all_41_osv_blobs_are_pinned(self):
        rows = read_rows(CANONICAL_TSV)
        lock = json.loads(CANONICAL_LOCK.read_text(encoding="utf-8"))
        self.assertEqual(git_blob_sha1(CANONICAL_TSV.read_bytes()),
                         "8a355c92db7ac64b48d584ab3257a1d469aa885a")
        self.assertEqual(lock["source"]["commit"],
                         "a64faad6c6b5b52353b7300d278e501c0ca75d21")
        self.assertEqual(lock["source"]["record_count"], 41)
        self.assertEqual(lock["source"]["binary_package_mapping"]["binary_package"], "linux-libc-dev")
        self.assertEqual(lock["source"]["binary_package_mapping"]["binary_version"], "7.0.0-43.43")
        self.assertEqual(lock["source"]["binary_package_mapping"]["records_listed_as_affected"], 41)
        self.assertEqual(len(rows), 41)
        self.assertEqual(len(lock["records"]), 41)
        self.assertEqual({row["cve"] for row in rows},
                         {row["cve"] for row in lock["records"]})
        self.assertEqual({row["cve"] for row in rows},
                         {row["cve"] for row in read_rows(INVENTORY)})
        for row in rows:
            self.assertEqual(row["resolute_source_purl"], SOURCE_PURL)
            self.assertEqual(row["canonical_linux_source_version_7_0_0_43_43_affected"], "true")
            self.assertEqual(row["canonical_linux_libc_dev_binary_version"], "7.0.0-43.43")
            self.assertEqual(row["canonical_linux_libc_dev_binary_listed_as_affected"], "true")
            self.assertEqual(row["binary_disposition"], "under_investigation")
            self.assertEqual(len(row["canonical_osv_blob_sha"]), 40)
        self.assertEqual(sum(row["canonical_osv_ubuntu_severity"] == "high" for row in rows), 38)
        self.assertEqual(sum(row["canonical_osv_ubuntu_severity"] == "critical" for row in rows), 3)
        self.assertTrue(all(row["resolute_7_0_0_43_43_affected"] is True
                            for row in lock["records"]))
        self.assertTrue(all(row["canonical_linux_source_version_affected"] is True
                            and row["linux_libc_dev_binary_version"] == "7.0.0-43.43"
                            and row["linux_libc_dev_binary_listed_as_affected"] is True
                            for row in lock["records"]))

    def test_upstream_pin_is_immutable_and_scope_preserving(self):
        lock = json.loads(UPSTREAM_LOCK.read_text(encoding="utf-8"))
        self.assertEqual(lock["commit"], "f418c1116f2ec1940e27ae4a38dbf42a0be719a8")
        self.assertEqual(lock["record_count"], 41)
        self.assertEqual(lock["record_inventory_blob_sha1"],
                         "62ad83bd1f9b251c4561c28df847ac1941d5ddb8")
        self.assertEqual(set(lock["cves"]), {row["cve"] for row in read_rows(INVENTORY)})
        self.assertFalse(lock["policy_boundary"]["vex"])
        self.assertFalse(lock["policy_boundary"]["not_affected"])
        self.assertFalse(lock["policy_boundary"]["risk_acceptance"])
        self.assertFalse(lock["policy_boundary"]["release_authorization"])


if __name__ == "__main__":
    unittest.main()
