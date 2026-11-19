"""Tests for immutable published-image package manifest assembly."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "assemble_image_binary_package_manifest",
    ROOT / "scripts/ci/assemble_image_binary_package_manifest.py",
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


class ImageBinaryManifestAssemblyTests(unittest.TestCase):
    def test_assembles_and_normalizes_installed_package_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package = root / "package.tsv"
            package.write_text(
                "status\tversion\tarchitecture\tsource_package\tsource_version\n"
                "install ok installed\t7.0.0-43.43\tamd64\tlinux\t7.0.0-43.43\n",
                encoding="utf-8",
            )
            manifest = root / "manifest.tsv"
            manifest.write_text(
                "path\tkind\tsha256\tlink_target\n"
                "/usr/include/linux/test.h\tfile\t" + "a" * 64 + "\t\n"
                "/usr/include/linux/current.h\tsymlink\t\tlinux/test.h\n"
                "/usr/include/linux\tdirectory\t\t\n"
                "/usr/include/linux/missing.h\tmissing\t\t\n",
                encoding="utf-8",
            )
            args = MODULE.argparse.Namespace(
                profile="final",
                architecture="amd64",
                image_ref="ghcr.io/baobab-platform/baobab-dev@sha256:" + "b" * 64,
                expected_version="7.0.0-43.43",
                package_metadata=package,
                manifest=manifest,
                output=root / "out.json",
            )
            result = MODULE.assemble(args)
            self.assertEqual(result["profile"], "final")
            self.assertEqual(result["architecture"], "amd64")
            self.assertEqual(result["package_path_count"], 4)
            by_path = {item["path"]: item for item in result["package_content_manifest"]}
            self.assertEqual(by_path["/usr/include/linux/test.h"]["value"], "a" * 64)
            self.assertEqual(by_path["/usr/include/linux/current.h"]["kind"], "symlink")
            self.assertEqual(by_path["/usr/include/linux"]["kind"], "dir")
            self.assertEqual(by_path["/usr/include/linux/missing.h"]["kind"], "missing")

    def test_rejects_wrong_source_version_or_non_immutable_image_ref(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package = root / "package.tsv"
            package.write_text(
                "status\tversion\tarchitecture\tsource_package\tsource_version\n"
                "install ok installed\t7.0.0-43.43\tarm64\tlinux\t7.0.0-42.42\n",
                encoding="utf-8",
            )
            manifest = root / "manifest.tsv"
            manifest.write_text("path\tkind\tsha256\tlink_target\n/usr/include/linux/a.h\tmissing\t\t\n", encoding="utf-8")
            args = MODULE.argparse.Namespace(
                profile="infra",
                architecture="arm64",
                image_ref="ghcr.io/baobab-platform/baobab-dev:latest",
                expected_version="7.0.0-43.43",
                package_metadata=package,
                manifest=manifest,
                output=root / "out.json",
            )
            with self.assertRaises(ValueError):
                MODULE.assemble(args)


if __name__ == "__main__":
    unittest.main()
