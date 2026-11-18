"""Offline tests for conservative 41-CVE source-to-binary path mapping."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "image_41_binary_paths", ROOT / "scripts/reconcile_dev10_image_observed_41_binary_paths.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


class Supplemental41BinaryPathMappingTests(unittest.TestCase):
    def test_common_uapi_path_maps_to_usr_include(self):
        self.assertEqual(
            MODULE.candidate_binary_paths("include/uapi/linux/cifs/cifs_mount.h", "amd64"),
            ("/usr/include/linux/cifs/cifs_mount.h",),
        )

    def test_arch_specific_uapi_paths_are_architecture_scoped(self):
        self.assertEqual(
            MODULE.candidate_binary_paths("arch/x86/include/uapi/asm/unistd.h", "amd64"),
            ("/usr/include/x86_64-linux-gnu/asm/unistd.h", "/usr/include/asm/unistd.h"),
        )
        self.assertEqual(
            MODULE.candidate_binary_paths("arch/arm64/include/uapi/asm/unistd.h", "arm64"),
            ("/usr/include/aarch64-linux-gnu/asm/unistd.h", "/usr/include/asm/unistd.h"),
        )
        self.assertEqual(
            MODULE.candidate_binary_paths("arch/x86/include/uapi/asm/unistd.h", "arm64"),
            (),
        )

    def test_private_headers_and_implementation_sources_are_not_mapped(self):
        self.assertEqual(MODULE.candidate_binary_paths("include/linux/sched.h", "amd64"), ())
        self.assertEqual(MODULE.candidate_binary_paths("fs/smb/client/cifssmb.c", "arm64"), ())

    def test_unsafe_source_paths_are_rejected(self):
        for value in ("../drivers/net/foo.c", "/etc/passwd", "include\\linux\\bad.h", "include//linux/x.h"):
            self.assertFalse(MODULE.safe_source_path(value))
        self.assertTrue(MODULE.safe_source_path("include/uapi/linux/cifs/cifs_mount.h"))


if __name__ == "__main__":
    unittest.main()
