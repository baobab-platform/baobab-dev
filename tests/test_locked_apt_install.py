"""An exact package is selected even when APT advertises a newer candidate."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class LockedAptInstallTests(unittest.TestCase):
    def test_refuses_unavailable_or_changed_artifact_and_checks_installed_version(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            commands = {
                "apt-cache": 'test "$*" = "show nodejs=26.13.1-1nodesource1" || exit 2\n'
                             'test "$AVAILABLE" = yes || exit 100\nprintf "SHA256: %s\\n" "$INDEX_SHA"\n',
                "apt-get": 'printf "%s\\n" "$*" > "$INSTALL_RECEIPT"\n',
                "dpkg-query": 'printf "%s" "$INSTALLED"\n',
            }
            for name, body in commands.items():
                path = directory / name
                path.write_text("#!/bin/sh\n" + body)
                path.chmod(0o755)
            receipt = directory / "install"
            correct = "a" * 64
            version = "26.13.1-1nodesource1"
            for available, index_sha, installed, success, invoked in (
                ("yes", correct, version, True, True),
                ("yes", "b" * 64, version, False, False),
                ("no", correct, version, False, False),
                ("yes", correct, "26.14.0-1nodesource1", False, True),
            ):
                with self.subTest(available=available, index=index_sha, installed=installed):
                    receipt.unlink(missing_ok=True)
                    result = subprocess.run(
                        ["bash", "-ec", '. "$1" && verify_locked_apt_index "$2" "$3" && '
                         'apt-get install -y --no-install-recommends "$2" && '
                         'verify_installed_apt_version "$2"', "bash",
                         str(ROOT / "scripts/locked-apt.sh"), f"nodejs={version}", correct],
                        env=dict(os.environ, PATH=str(directory) + ":" + os.environ["PATH"],
                                 AVAILABLE=available, INDEX_SHA=index_sha, INSTALLED=installed,
                                 INSTALL_RECEIPT=str(receipt)),
                        capture_output=True, text=True, check=False,
                    )
                    self.assertEqual(result.returncode == 0, success, result.stderr)
                    self.assertEqual(receipt.is_file(), invoked)
                    if invoked:
                        self.assertIn("nodejs=" + version, receipt.read_text())
