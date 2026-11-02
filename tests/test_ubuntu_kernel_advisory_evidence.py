"""Fail closed on incomplete, unreviewed Ubuntu kernel-header advisory evidence."""
from collections import Counter
import csv
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "docs/assessments/dev10-canonical-cve-status-20261030.tsv"
TRIVY = ROOT / "docs/assessments/dev10-kernel-cves.tsv"

class VendorEvidenceTests(unittest.TestCase):
    def test_all_295_original_findings_have_vendor_records_without_waivers(self):
        with TRIVY.open(newline="") as src:
            trivy = list(csv.DictReader(src, delimiter="\t"))
        with REPORT.open(newline="") as src:
            vendor = list(csv.DictReader(src, delimiter="\t"))
        self.assertEqual(len(trivy), 295)
        self.assertEqual(len(vendor), 295)
        self.assertEqual({x["cve"] for x in trivy}, {x["cve"] for x in vendor})
        self.assertEqual(Counter(v["ubuntu_linux_resolute_status"] for v in vendor),
                         {"pending": 287, "needed": 8})
        self.assertTrue(all(v["binary_header_package_disposition"] ==
                            "PENDING_INDEPENDENT_CODE_PATH_REVIEW" for v in vendor))
        self.assertTrue(all(v["vendor_url"] ==
                            f'https://ubuntu.com/security/cves/{v["cve"]}.json' for v in vendor))

if __name__ == "__main__":
    unittest.main()
