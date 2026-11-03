"""Offline regression tests: DEV-10 Go proxy transient failure tolerance.

The mock 'go' never downloads modules; real Docker+Go qualification remains
mandatory. The wrapper must not hide persistent failures or change sum checks.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/go-mod-download-retry.sh"
BUILDER = ROOT / "scripts/build-security-clis.sh"
DOCKERFILE = ROOT / ".devcontainer/docker/Dockerfile"

FAKE_GO = """#!/usr/bin/env bash
set -euo pipefail
[[ "$*" == "mod download" ]] || exit 77
[[ "${GODEBUG:-}" == "http2client=0" ]] || exit 78
[[ "${GOFLAGS:-}" == "-mod=readonly" ]] || exit 79
n=0
[[ ! -f "$MOCK_GO_COUNT" ]] || n=$(cat "$MOCK_GO_COUNT")
n=$((n + 1))
printf '%s' "$n" > "$MOCK_GO_COUNT"
if (( n <= MOCK_GO_FAIL_BEFORE )); then
  echo 'proxy.golang.org stream error: INTERNAL_ERROR' >&2
  exit 17
fi
"""


class GoModuleRetryTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        for name, source in (
            ("go", FAKE_GO),
            ("sleep", '#!/usr/bin/env bash\necho "$1" >> "$MOCK_SLEEP_LOG"\n'),
        ):
            path = self.root / name
            path.write_text(source)
            path.chmod(0o755)
        self.count = self.root / "count"
        self.sleeps = self.root / "sleeps"
        self.env = {
            **os.environ,
            "PATH": str(self.root) + os.pathsep + os.environ["PATH"],
            "GOFLAGS": "-mod=readonly",
            "MOCK_GO_COUNT": str(self.count),
            "MOCK_SLEEP_LOG": str(self.sleeps),
            "MOCK_GO_FAIL_BEFORE": "0",
        }

    def run_retry(self, fail_before=0, *args):
        env = {**self.env, "MOCK_GO_FAIL_BEFORE": str(fail_before)}
        return subprocess.run(["bash", str(SCRIPT), *args], env=env,
                              capture_output=True, text=True, timeout=12)

    def test_first_attempt_succeeds_without_sleep(self):
        outcome = self.run_retry()
        self.assertEqual(outcome.returncode, 0, outcome.stderr)
        self.assertEqual(self.count.read_text(), "1")
        self.assertFalse(self.sleeps.exists())

    def test_two_transient_failures_then_success(self):
        outcome = self.run_retry(2)
        self.assertEqual(outcome.returncode, 0, outcome.stderr)
        self.assertEqual(self.count.read_text(), "3")
        self.assertEqual(self.sleeps.read_text().splitlines(), ["5", "10"])
        self.assertIn("recovered on attempt 3/4", outcome.stdout)

    def test_persistent_failure_remains_fatal(self):
        outcome = self.run_retry(9)
        self.assertEqual(outcome.returncode, 1)
        self.assertEqual(self.count.read_text(), "4")
        self.assertEqual(self.sleeps.read_text().splitlines(), ["5", "10", "15"])
        self.assertIn("refusing incomplete/unverified", outcome.stderr)

    def test_arguments_cannot_override_download(self):
        outcome = self.run_retry(0, "go", "get", "latest")
        self.assertEqual(outcome.returncode, 2)
        self.assertFalse(self.count.exists())

    def test_docker_security_rebuild_keeps_all_verification_barriers(self):
        script = BUILDER.read_text()
        dockerfile = DOCKERFILE.read_text()
        self.assertIn("bash /build/go-mod-download-retry.sh\n  go mod verify", script)
        self.assertIn("GOFLAGS=-mod=readonly", script)
        self.assertIn('cmp go.mod "/build/security/$tool/go.mod.lock"', script)
        self.assertIn('cmp go.sum "/build/security/$tool/go.sum"', script)
        self.assertIn("go test ./version ./util/buildflags ./store", script)
        self.assertIn(
            "COPY scripts/go-mod-download-retry.sh /build/go-mod-download-retry.sh",
            dockerfile)
        executable = "\n".join(
            line for line in SCRIPT.read_text().splitlines()
            if not line.lstrip().startswith("#")
        )
        self.assertNotIn("GOSUMDB=off", executable)
        self.assertNotIn("GOPROXY=direct", executable)


if __name__ == "__main__":
    unittest.main()
