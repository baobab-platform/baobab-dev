"""Canonical Ubuntu binary-to-source package provenance is explicit and reproducible."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from argparse import Namespace

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "ubuntu_binary_source", ROOT / "scripts/verify_ubuntu_binary_source.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class UbuntuBinarySourceTests(unittest.TestCase):
    def test_workflow_writes_plain_immutable_base_image_reference(self):
        workflow = (ROOT / ".github/workflows/dev10-ubuntu-source.yml").read_text()
        capture = (ROOT / "scripts/ci/capture-ubuntu-package-evidence.sh").read_text()
        self.assertIn("bash scripts/ci/capture-ubuntu-package-evidence.sh", workflow)
        self.assertIn("printf '%s\\n' \"$UBUNTU_IMAGE_REF\"", capture)
        self.assertNotIn("printf '%s\\\\n' \"$UBUNTU_IMAGE_REF\"", workflow)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.paths = {
            "installed_package": root / "installed-package.txt",
            "apt_package_metadata": root / "apt-package-metadata.txt",
            "apt_policy": root / "apt-policy.txt",
            "apt_madison": root / "apt-madison.txt",
            "deb_sha256": root / "apt-package-deb-sha256.txt",
            "index_sha256": root / "apt-package-index-sha256.txt",
            "base_image": root / "ubuntu-base-image.txt",
            "output": root / "binary-source.json",
        }
        version = MODULE.LOCK.package_version
        deb_hash = MODULE.LOCK.binary_artifact_sha256["amd64"]
        self.paths["installed_package"].write_text(
            "\t".join(("linux-libc-dev", version, "amd64", "install ok installed",
                       "linux", version)) + "\n",
            encoding="utf-8",
        )
        self.paths["apt_package_metadata"].write_text(
            f"Package: linux-libc-dev\nVersion: {version}\nArchitecture: amd64\n"
            f"Source: linux ({version})\nFilename: pool/main/l/linux/linux-libc-dev_{version}_amd64.deb\n"
            f"SHA256: {deb_hash}\n\n",
            encoding="utf-8",
        )
        self.paths["apt_policy"].write_text(
            f"linux-libc-dev:\n Installed: {version}\n Candidate: {version}\n"
            f" Version table:\n *** {version} 500\n"
            f"        500 http://archive.ubuntu.com/ubuntu resolute-updates/main amd64 Packages\n",
            encoding="utf-8",
        )
        self.paths["apt_madison"].write_text(
            f"linux-libc-dev | {version} | http://archive.ubuntu.com/ubuntu "
            "resolute-updates/main amd64 Packages\n",
            encoding="utf-8",
        )
        self.paths["deb_sha256"].write_text(
            deb_hash + f"  ./linux-libc-dev_{version}_amd64.deb\n",
            encoding="utf-8",
        )
        self.paths["index_sha256"].write_text(
            "b" * 64 + "  /var/lib/apt/lists/archive.ubuntu.com_Packages.lz4\n",
            encoding="utf-8",
        )
        self.paths["base_image"].write_text("ubuntu@sha256:" + "c" * 64 + "\n",
                                            encoding="utf-8")

    def args(self):
        return Namespace(**self.paths)

    def test_exact_installed_binary_maps_to_locked_linux_source(self):
        result = MODULE.verify(self.args())
        self.assertEqual(result["binary_package"], "linux-libc-dev")
        self.assertEqual(result["source_package"], "linux")
        self.assertEqual(result["binary_version"], MODULE.LOCK.package_version)
        self.assertEqual(result["source_version"], MODULE.LOCK.package_version)
        self.assertEqual(result["release_pocket"], "resolute-updates")
        self.assertEqual(result["ubuntu_base_image"], "ubuntu@sha256:" + "c" * 64)

    def test_installed_dpkg_source_mismatch_is_rejected(self):
        path = self.paths["installed_package"]
        values = path.read_text(encoding="utf-8").strip().split("\t")
        values[4] = "linux-raspi"
        path.write_text("\t".join(values) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "source_package differs"):
            MODULE.verify(self.args())

    def test_apt_source_metadata_mismatch_is_rejected(self):
        path = self.paths["apt_package_metadata"]
        path.write_text(path.read_text(encoding="utf-8").replace("Source: linux", "Source: linux-raspi"),
                        encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "does not corroborate"):
            MODULE.verify(self.args())

    def test_new_candidate_can_coexist_with_exact_locked_bytes_in_security_pocket(self):
        path = self.paths["apt_policy"]
        version = MODULE.LOCK.package_version
        path.write_text(path.read_text().replace(f"Candidate: {version}", "Candidate: 7.0.0-44.44"))
        path = self.paths["apt_madison"]
        path.write_text(path.read_text().replace("archive.ubuntu.com", "security.ubuntu.com").replace(
            "resolute-updates", "resolute-security"
        ))
        evidence = MODULE.verify(self.args())
        self.assertEqual(evidence["apt_candidate_version"], "7.0.0-44.44")
        self.assertEqual(evidence["apt_exact_version_pockets"], ["resolute-security"])
        self.assertEqual(evidence["release_pocket"], "resolute-updates")

    def test_exact_version_and_canonical_pocket_must_share_a_record(self):
        path = self.paths["apt_madison"]
        path.write_text(path.read_text().replace(MODULE.LOCK.package_version, "7.0.0-44.44")
                        + f"linux-libc-dev | {MODULE.LOCK.package_version} | https://untrusted.invalid/ubuntu "
                        "resolute-security/main amd64 Packages\n")
        with self.assertRaisesRegex(ValueError, "exact binary"):
            MODULE.verify(self.args())

    def test_downloaded_sha_and_metadata_must_both_match_the_evidence_lock(self):
        original = MODULE.LOCK.binary_artifact_sha256["amd64"]
        path = self.paths["apt_package_metadata"]
        path.write_text(path.read_text().replace(original, "a" * 64))
        with self.assertRaisesRegex(ValueError, "does not corroborate"):
            MODULE.verify(self.args())
        path = self.paths["deb_sha256"]
        path.write_text(path.read_text().replace(original, "a" * 64))
        with self.assertRaisesRegex(ValueError, "differs from evidence lock"):
            MODULE.verify(self.args())

    def test_missing_apt_index_digest_is_rejected(self):
        self.paths["index_sha256"].write_text("", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "no apt package index"):
            MODULE.verify(self.args())


if __name__ == "__main__":
    unittest.main()
