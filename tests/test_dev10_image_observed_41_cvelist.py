"""Regression checks for the pinned Linux CNA CVE List mirror."""
from __future__ import annotations

import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
TSV = ROOT / "docs/assessments/dev10-image-observed-cves-41-upstream.tsv"
LOCK = ROOT / "security/evidence/dev10-image-observed-cves-41-cvelist.lock.json"


def read_tsv(path: Path) -> list[dict[str, str]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    header = lines[0].split("\t")
    return [dict(zip(header, line.split("\t"), strict=True)) for line in lines[1:]]


class Supplemental41CveListMirrorTests(unittest.TestCase):
    def test_all_41_linux_cna_records_are_pinned(self):
        rows = read_tsv(TSV)
        lock = json.loads(LOCK.read_text(encoding="utf-8"))
        self.assertEqual(lock["source"]["repository"], "CVEProject/cvelistV5")
        self.assertEqual(lock["source"]["commit"], "4c07c147c7a7132e0228ab8bf6fb8b411b256e13")
        self.assertEqual(lock["source"]["record_count"], 41)
        self.assertEqual(len(rows), 41)
        self.assertEqual(len(lock["records"]), 41)
        self.assertEqual({row["cve"] for row in rows}, {row["cve"] for row in lock["records"]})
        self.assertTrue(all(row["provider_short_name"] == "Linux" for row in rows))
        self.assertTrue(all(row["assigner_short_name"] == "Linux" for row in rows))
        self.assertTrue(all(row["affected_source_paths"] for row in rows))
        self.assertTrue(all(row["candidate_fix_commit_ids"] for row in rows))
        self.assertEqual(sum(int(row["affected_source_path_count"]) for row in rows), 53)
        self.assertEqual(sum(int(row["candidate_fix_commit_count"]) for row in rows), 225)

    def test_tsv_rows_match_lock_paths_and_fix_commit_candidates(self):
        rows = {row["cve"]: row for row in read_tsv(TSV)}
        lock = json.loads(LOCK.read_text(encoding="utf-8"))
        for record in lock["records"]:
            row = rows[record["cve"]]
            self.assertEqual(row["record_path"], record["path"])
            self.assertEqual(row["record_blob_sha1"], record["blob_sha1"])
            self.assertEqual(row["record_updated"], record["record_updated"])
            self.assertEqual(row["affected_source_paths"].split(";"),
                             record["affected_source_paths"])
            self.assertEqual(row["candidate_fix_commit_ids"].split(";"),
                             record["candidate_fix_commit_ids"])
            self.assertEqual(row["candidate_fix_commit_references"].split(";"),
                             record["candidate_fix_commit_references"])


if __name__ == "__main__":
    unittest.main()
