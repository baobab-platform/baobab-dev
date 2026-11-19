"""Offline tests for the pinned supplemental 41-CVE upstream/Canonical auditor."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "image_41_source_auditor", ROOT / "scripts/audit_dev10_image_observed_41.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


class Supplemental41SourceAuditorTests(unittest.TestCase):
    def test_locked_inventory_and_canonical_rows_validate(self):
        inventory = MODULE.read_tsv(ROOT / "docs/assessments/dev10-image-observed-cves-41.tsv")
        canonical = MODULE.read_tsv(ROOT / "docs/assessments/dev10-image-observed-cves-41-canonical.tsv")
        lock = __import__("json").loads(
            (ROOT / "security/evidence/dev10-image-observed-cves-41-canonical.lock.json").read_text()
        )
        ids = MODULE.validate_inputs(inventory, canonical, lock)
        self.assertEqual(len(ids), 41)

    def test_stable_and_linus_commit_urls_are_only_candidates(self):
        stable = "https://git.kernel.org/stable/c/9efbd764ab80fa86d2258550877a74d78a25e855"
        linus = "https://git.kernel.org/linus/c/4aa2c106aef4bf3dfd97c30842db0767b26e8428"
        self.assertEqual(MODULE.COMMIT_URL_RE.search(stable).group(1),
                         "9efbd764ab80fa86d2258550877a74d78a25e855")
        self.assertEqual(MODULE.COMMIT_URL_RE.search(linus).group(1),
                         "4aa2c106aef4bf3dfd97c30842db0767b26e8428")

    def test_git_blob_sha1_uses_git_object_preimage(self):
        self.assertEqual(MODULE.git_blob_sha1(b"hello\n"),
                         "ce013625030ba8dba906f756967f9e9ca394464a")


if __name__ == "__main__":
    unittest.main()
