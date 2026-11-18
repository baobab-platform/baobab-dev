"""The evidence lock is the single validated source for DEV-10 inventory pins."""
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "dev10_evidence_lock", ROOT / "scripts/dev10_evidence_lock.py"
)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class EvidenceLockTests(unittest.TestCase):
    def test_checked_in_lock_validates_exact_inventory_inputs(self):
        lock = module.EvidenceLock.load(ROOT)
        self.assertEqual(lock.inventory_count, 298)
        self.assertEqual(lock.canonical_count, 298)
        self.assertEqual(lock.package_version, "7.0.0-43.43")
        self.assertEqual(lock.ubuntu_tag, "Ubuntu-7.0.0-43.43")
        self.assertEqual(lock.ubuntu_tag_commit, "f53b359683af7918c5436499948763cb726d5082")
        self.assertEqual(lock.canonical_osv_commit, "88c00a77a1247172dd107f5dd3f24a1e1d1f57b2")
        self.assertEqual(lock.canonical_osv_snapshot_path, "osv/cve")
        stable = json.loads((ROOT / module.LOCK_PATH).read_text())["stable_base_image"]
        self.assertEqual(stable["index_digest"], "sha256:faf9022ef06288767651a0ec1071d5199bc2b645f2cf7ada50477774dd297eed")
        self.assertEqual(stable["signer_tag"], "v1.5.1-rc.2")
        self.assertEqual(lock.binary_manifest_sha256, "688453ae46c07ec19b3bf6734eb2f23b0dfe5625c16d76d75149b8194da91fa3")
        self.assertEqual(lock.historical_inventory_count, 295)
        self.assertEqual(lock.historical_package_version, "7.0.0-42.42")
        self.assertEqual(len(lock.observed_kernel_cves), 11)
        self.assertEqual(len(lock.profile_scan_artifacts), 8)
        self.assertEqual(set(lock.stable_profile_images), {"final", "frontend", "frontend-e2e", "infra"})

    def test_inventory_digest_tampering_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "security/evidence").mkdir(parents=True)
            (root / "docs/assessments").mkdir(parents=True)
            shutil.copy2(ROOT / "security/evidence/dev10-kernel-evidence.lock.json",
                         root / module.LOCK_PATH)
            shutil.copy2(ROOT / "docs/assessments/dev10-kernel-cves-298.tsv",
                         root / "docs/assessments/dev10-kernel-cves-298.tsv")
            shutil.copy2(ROOT / "docs/assessments/dev10-kernel-cves.tsv",
                         root / "docs/assessments/dev10-kernel-cves.tsv")
            shutil.copy2(ROOT / "docs/assessments/dev10-canonical-cve-status-20261118.tsv",
                         root / "docs/assessments/dev10-canonical-cve-status-20261118.tsv")
            with (root / "docs/assessments/dev10-kernel-cves-298.tsv").open("a") as stream:
                stream.write("\n")
            with self.assertRaisesRegex(ValueError, "digest differs"):
                module.EvidenceLock.load(root)

    def test_manifest_digest_is_pinned_to_the_retained_capture(self):
        data = json.loads((ROOT / module.LOCK_PATH).read_text())
        self.assertEqual(
            data["binary_manifest"]["sha256"],
            "688453ae46c07ec19b3bf6734eb2f23b0dfe5625c16d76d75149b8194da91fa3",
        )
        self.assertIn("computed from installed-paths.txt",
                      data["binary_manifest"]["digest_policy"])


if __name__ == "__main__":
    unittest.main()
