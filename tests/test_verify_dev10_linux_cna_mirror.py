"""Unit tests for Linux CNA mirror verification helpers."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_linux_cna_mirror", ROOT / "scripts/verify_dev10_linux_cna_mirror.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


class LinuxCnaMirrorVerifierTests(unittest.TestCase):
    def test_only_kernel_stable_and_linus_commit_refs_are_candidates(self):
        refs = [
            "https://git.kernel.org/stable/c/9efbd764ab80fa86d2258550877a74d78a25e855",
            "https://git.kernel.org/linus/c/4aa2c106aef4bf3dfd97c30842db0767b26e8428",
            "https://ubuntu.com/security/CVE-2026-99109",
        ]
        self.assertEqual(len(MODULE.candidate_refs(refs)), 2)
        self.assertEqual(MODULE.candidate_ids(refs), [
            "4aa2c106aef4bf3dfd97c30842db0767b26e8428",
            "9efbd764ab80fa86d2258550877a74d78a25e855",
        ])

    def test_cvelist_inventory_is_exactly_41_linux_cna_records(self):
        rows = MODULE.read_tsv(ROOT / "docs/assessments/dev10-image-observed-cves-41-upstream.tsv")
        self.assertEqual(len(rows), 41)
        self.assertTrue(all(row["provider_short_name"] == "Linux" for row in rows))
        self.assertTrue(all(row["affected_source_paths"] for row in rows))
        self.assertTrue(all(row["candidate_fix_commit_ids"] for row in rows))


if __name__ == "__main__":
    unittest.main()
