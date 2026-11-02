"""Fail-closed tests for independent Python advisory auditing command."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/audit-python-dependencies.sh"


class IndependentPythonAuditTests(unittest.TestCase):
    def run_source(self, *, fail_at="", hashed=True):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for path in (
                "uv.lock", "pyproject.toml",
                "config/security/pip-vendoring-requirements.txt",
                "config/python-build-constraints.txt",
            ):
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("required")
            binpath = root / "bin"
            binpath.mkdir()
            uv = binpath / "uv"
            uv.write_text("""#!/bin/sh
printf 'uv %s\\n' "$*" >> "$TRACE"
if [ "$1" != "export" ]; then exit 71; fi
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--output-file" ]; then shift; output="$1"; fi
  shift
done
printf 'safe-pkg==1.2.3\\n' > "$output"
if [ "$HASHED" = yes ]; then
  printf '    --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\\n' >> "$output"
fi
""")
            uvx = binpath / "uvx"
            uvx.write_text("""#!/bin/sh
printf 'uvx %s\\n' "$*" >> "$TRACE"
case "$*" in
  *"$FAIL_AT"*) if [ -n "$FAIL_AT" ]; then exit 19; fi ;;
esac
""")
            for tool in (uv, uvx):
                tool.chmod(0o755)
            env = {
                **os.environ,
                "PATH": f"{binpath}:/usr/bin:/bin",
                "TRACE": str(root / "trace"),
                "FAIL_AT": fail_at,
                "HASHED": "yes" if hashed else "no",
            }
            r = subprocess.run(
                ["bash", str(SCRIPT), "--source"],
                cwd=root, env=env, text=True, capture_output=True, check=False,
            )
            log = (root / "trace").read_text() if (root / "trace").exists() else ""
            return r, log

    def test_audits_committed_lock_builder_and_constraints(self):
        result, trace = self.run_source()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("uv export --locked --all-groups --no-emit-project", trace)
        self.assertEqual(trace.count("uvx --from pip-audit==2.10.1"), 3)
        self.assertIn("pip-vendoring-requirements.txt", trace)
        self.assertIn("python-build-constraints.txt", trace)
        self.assertNotIn("--ignore-vuln", trace)

    def test_audit_vulnerability_exit_is_not_suppressed(self):
        result, trace = self.run_source(fail_at="uv-requirements.txt")
        self.assertEqual(result.returncode, 19, result.stdout + result.stderr)
        self.assertEqual(trace.count("uvx --from pip-audit==2.10.1"), 1)

    def test_missing_lock_hashes_are_refused_before_audit(self):
        result, trace = self.run_source(hashed=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("uvx --from pip-audit", trace)


if __name__ == "__main__":
    unittest.main()
