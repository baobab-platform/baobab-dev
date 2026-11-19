"""Offline tests for architecture-specific Ubuntu binary package verification."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "ubuntu_binary_arch", ROOT / "scripts/verify_ubuntu_binary_package_arch.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


class UbuntuBinaryPackageArchitectureTests(unittest.TestCase):
    def test_source_identity_requires_linux_source_and_version(self):
        self.assertEqual(MODULE.source_identity("linux (7.0.0-43.43)"),
                         ("linux", "7.0.0-43.43"))
        self.assertEqual(MODULE.source_identity("linux"), ("linux", "7.0.0-43.43"))
        with self.assertRaises(ValueError):
            MODULE.source_identity("linux (unknown)")
        with self.assertRaises(ValueError):
            MODULE.source_identity("other-linux (7.0.0-43.43)")

    def test_dpkg_deb_control_output_is_parsed_as_fields_not_positional_values(self):
        fields = MODULE.parse_control_fields(
            "Package: linux-libc-dev\\n"
            "Version: 7.0.0-43.43\\n"
            "Architecture: arm64\\n"
            "Source: linux\\n"
        )
        self.assertEqual(fields, {
            "Package": "linux-libc-dev",
            "Version": "7.0.0-43.43",
            "Architecture": "arm64",
            "Source": "linux",
        })

    def test_installed_manifest_is_sorted_and_typed(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "installed.tsv"
            path.write_text(
                "file\t/usr/include/linux/a.h\t" + "a" * 64 + "\n"
                "dir\t/usr/include/linux\t\n",
                encoding="utf-8",
            )
            rows = MODULE.installed_manifest(path)
            self.assertEqual([row["path"] for row in rows],
                             ["/usr/include/linux", "/usr/include/linux/a.h"])
            self.assertEqual(rows[0]["kind"], "dir")
            self.assertEqual(rows[1]["kind"], "file")

    def test_installed_manifest_rejects_duplicate_or_malformed_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "installed.tsv"
            path.write_text("file\t/usr/include/linux/a.h\t" + "a" * 64 + "\n"
                            "file\t/usr/include/linux/a.h\t" + "b" * 64 + "\n",
                            encoding="utf-8")
            with self.assertRaises(ValueError):
                MODULE.installed_manifest(path)
            path.write_text("unexpected\t/usr/include/linux/a.h\tbad\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                MODULE.installed_manifest(path)


if __name__ == "__main__":
    unittest.main()
