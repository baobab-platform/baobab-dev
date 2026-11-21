from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALIASES = ROOT / "config/bashrc.d/20-aliases.sh"


class PnpmAliasTests(unittest.TestCase):
    def run_aliases(self, package_manager: str | None, commands: str, pin_ok: bool = True):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            trace = root / "trace.log"
            package = {"name": "alias-fixture"}
            if package_manager is not None:
                package["packageManager"] = package_manager
            (root / "package.json").write_text(json.dumps(package), encoding="utf-8")

            helper = bin_dir / "baobab-project-pnpm"
            helper.write_text(
                r"""#!/usr/bin/env bash
if [[ "$1" == pin ]]; then
  printf 'pin\n' >> "$TRACE"
  [[ "${PIN_OK:-1}" == 1 ]] || exit 3
  printf '11.24.0\n'
else
  printf 'helper:%s\n' "$*" >> "$TRACE"
fi
""",
                encoding="utf-8",
            )
            helper.chmod(0o755)

            native = bin_dir / "pnpm"
            native.write_text(
                r"""#!/usr/bin/env bash
printf 'native:%s\n' "$*" >> "$TRACE"
""",
                encoding="utf-8",
            )
            native.chmod(0o755)

            env = os.environ.copy()
            env.update({
                "PATH": f"{bin_dir}:{env['PATH']}",
                "TRACE": str(trace),
                "PIN_OK": "1" if pin_ok else "0",
            })
            result = subprocess.run(
                ["bash", "-c", f'source "{ALIASES}"; {commands}'],
                cwd=root,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            output = trace.read_text(encoding="utf-8").splitlines() if trace.exists() else []
            return result, output

    def test_exact_consumer_pin_routes_all_aliases_through_helper(self):
        result, trace = self.run_aliases(
            "pnpm@11.24.0",
            "ni --frozen-lockfile; nd --host; nb --filter web",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            [line for line in trace if line.startswith("helper:")],
            [
                "helper:install --frozen-lockfile",
                "helper:dev --host",
                "helper:build --filter web",
            ],
        )
        self.assertFalse(any(line.startswith("native:") for line in trace))

    def test_no_project_pin_uses_image_native_pnpm(self):
        result, trace = self.run_aliases(
            None,
            "ni --frozen-lockfile; nd --host; nb --filter web",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            [line for line in trace if line.startswith("native:")],
            [
                "native:install --frozen-lockfile",
                "native:dev --host",
                "native:build --filter web",
            ],
        )

    def test_invalid_or_non_pnpm_project_pin_fails_closed(self):
        for manager, pin_ok in (("yarn@4.18.1", True), ("pnpm@11.invalid", False)):
            with self.subTest(manager=manager):
                result, trace = self.run_aliases(manager, "ni install-arg", pin_ok=pin_ok)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any(line.startswith("native:") for line in trace))


if __name__ == "__main__":
    unittest.main()
