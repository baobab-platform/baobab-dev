"""Check architecture mapping and native artifact custody for the current audit."""

import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from audit_installed_kernel_headers import ARCHITECTURES, TARGETS, digest, header_matches, verify_native_payloads


class InstalledKernelHeadersTests(unittest.TestCase):
    def test_architecture_specific_uapi_paths_are_not_cross_matched(self):
        files = {"/usr/include/x86_64-linux-gnu/asm/example.h": "a" * 64}
        paths = ["arch/arm64/include/uapi/asm/example.h", "arch/x86/include/uapi/asm/example.h"]
        evidence = header_matches(paths, files, {}, "amd64")
        self.assertEqual(evidence["exported_path_candidates"], {paths[1]: files})

    def test_native_evidence_rejects_bytes_different_from_the_deb(self):
        source, lock, version = "1" * 40, "2" * 64, "7.0.0-44.44"
        header, sha = "/usr/include/linux/example.h", "3" * 64
        packages = {arch: ({}, {header: sha}, {}) for arch in ARCHITECTURES}
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for target in TARGETS:
                for arch in ARCHITECTURES:
                    directory = root / f"native-image-{target}-{arch}"
                    directory.mkdir()
                    package = directory / "linux-libc-dev.package.tsv"
                    package.write_text("status\tversion\tarchitecture\tsource_package\tsource_version\n"
                                       f"install ok installed\t{version}\t{arch}\tlinux\t{version}\n")
                    manifest = directory / "linux-libc-dev.manifest.tsv"
                    manifest.write_text(f"path\tkind\tsha256\tlink_target\n{header}\tfile\t{sha}\t\n")
                    metadata = directory / "native-image.json"
                    record = {
                        "schema": "baobab.dev10.native-image.v1", "source_sha": source, "lock_sha256": lock,
                        "platform": f"linux/{arch}", "profile": "full" if target == "final" else target,
                        "image_config_digest": "sha256:" + "4" * 64,
                        "linux_libc_dev": {"package_tsv_sha256": digest(package), "manifest_tsv_sha256": digest(manifest)},
                    }
                    metadata.write_text(json.dumps(record))
            self.assertEqual(len(verify_native_payloads(root, source, lock, version, packages)), 8)
            manifest.write_text(manifest.read_text().replace(sha, "5" * 64))
            record["linux_libc_dev"]["manifest_tsv_sha256"] = digest(manifest)
            metadata.write_text(json.dumps(record))
            with self.assertRaisesRegex(ValueError, "installed header path or bytes differ"):
                verify_native_payloads(root, source, lock, version, packages)
