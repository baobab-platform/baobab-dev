"""Exercise resolver parsing/discovery helpers with network commands refused.

Full exact-version upstream digest verification remains in the image workflow.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class LockedResolverTests(unittest.TestCase):
    def run_helper(self, command, lock='export UV_VERSION=0.13.5\n', locked=True):
        source = (ROOT / 'config/resolve.sh').read_text()
        # Load the actual parser and discovery functions without executing the
        # top-level upstream reads or lock generation. No duplicated algorithm.
        prefix = source.split('# Read versions\n', 1)[0]
        github = 'resolve_github() {' + source.split('resolve_github() {', 1)[1].split('\n}\n', 1)[0] + '\n}\n'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / 'config'
            config.mkdir()
            (config / 'versions.yaml').write_text('{}')
            if lock is not None:
                (config / 'versions.lock').write_text(lock)
            tools = root / 'bin'
            tools.mkdir()
            for name in ('yq', 'curl'):
                tool = tools / name
                tool.write_text('#!/bin/sh\nexit 91\n')
                tool.chmod(0o755)
            script = config / 'resolver-under-test.sh'
            script.write_text(prefix + github + '\n' + command)
            return subprocess.run(['bash', str(script)] + (['--locked'] if locked else []),
                                  env={**os.environ, 'PATH': str(tools) + ':/usr/bin:/bin'},
                                  capture_output=True, text=True)

    def test_frozen_discovery_uses_committed_version_for_all_registries(self):
        for helper in ('resolve_github', 'resolve_npm', 'resolve_npm_registry'):
            with self.subTest(helper=helper):
                r = self.run_helper('yaml() { printf latest; }; ' + helper + ' .test vendor UV_VERSION\n')
                self.assertEqual(0, r.returncode, r.stderr)
                self.assertEqual('0.13.5', r.stdout)

    def test_explicit_manifest_pin_still_overrides_previous_lock(self):
        r = self.run_helper('yaml() { printf 0.14.0; }; resolve_github .test vendor UV_VERSION\n')
        self.assertEqual(0, r.returncode, r.stderr)
        self.assertEqual('0.14.0', r.stdout)

    def test_update_mode_still_discovers_new_versions(self):
        r = self.run_helper('yaml() { printf latest; }; github_latest() { printf 0.14.0; }; resolve_github .test vendor UV_VERSION\n', locked=False)
        self.assertEqual(0, r.returncode, r.stderr)
        self.assertEqual('0.14.0', r.stdout)

    def test_frozen_parser_rejects_missing_duplicate_unresolved_and_shell_content(self):
        for lock in (None, 'export UV_VERSION=0.13.5\nexport UV_VERSION=0.14.0\n',
                     'export UV_VERSION=latest\n', 'export UV_VERSION=$(exit 0)\n',
                     'export UV_VERSION=0.13.5; exit 0\n'):
            with self.subTest(lock=lock):
                r = self.run_helper('locked_version UV_VERSION\n', lock=lock)
                self.assertNotEqual(0, r.returncode)
                self.assertEqual('', r.stdout)

    def test_missing_required_version_never_falls_back_to_latest(self):
        r = self.run_helper('yaml() { printf latest; }; resolve_github .test vendor UV_VERSION\n', lock='export OTHER_VERSION=1.2.3\n')
        self.assertNotEqual(0, r.returncode)
        self.assertIn('Missing or invalid frozen version', r.stderr)


if __name__ == '__main__':
    unittest.main()
