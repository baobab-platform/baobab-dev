"""Regression coverage for transient crane manifest fetch failures."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/fetch-complete-oci-index.sh"


class FetchCompleteOciIndexRetryTests(unittest.TestCase):
    def test_transient_crane_failure_is_retried_and_complete_index_is_returned(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            state = root / "crane-count"
            bin_dir = root / "bin"
            bin_dir.mkdir()
            crane = bin_dir / "crane"
            crane.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                f"state={str(state)!r}\n"
                "count=0; [[ ! -f \"$state\" ]] || count=$(cat \"$state\")\n"
                "count=$((count + 1)); printf '%s' \"$count\" > \"$state\"\n"
                "if [[ \"$count\" -eq 1 ]]; then exit 7; fi\n"
                "printf '{\"manifests\":[]}\\n'\n",
                encoding="utf-8",
            )
            jq = bin_dir / "jq"
            jq.write_text(
                "#!/usr/bin/env python3\n"
                "import sys\n"
                "query = sys.argv[-1]\n"
                "if 'platform.architecture == $arch' in query:\n"
                "    print('sha256:' + 'a' * 64)\n"
                "elif 'attestation-manifest' in query:\n"
                "    print('sha256:' + 'b' * 64)\n"
                "else:\n"
                "    raise SystemExit(2)\n",
                encoding="utf-8",
            )
            sleep = bin_dir / "sleep"
            sleep.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
            for executable in (crane, jq, sleep):
                executable.chmod(0o755)

            env = os.environ.copy()
            env.update({
                "PATH": str(bin_dir) + os.pathsep + env["PATH"],
                "MANIFEST_RETRY_ATTEMPTS": "2",
                "MANIFEST_RETRY_BASE_DELAY": "0",
                "MANIFEST_RETRY_MAX_DELAY": "0",
            })
            result = subprocess.run(
                ["bash", str(SCRIPT), "ghcr.io/baobab-platform/baobab-dev", "sha256:" + "c" * 64],
                text=True, capture_output=True, env=env, check=False, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(state.read_text(encoding="utf-8"), "2")
            self.assertIn('"manifests":[]', result.stdout)
            self.assertIn("attempt 1/2", result.stderr)


if __name__ == "__main__":
    unittest.main()
