"""Exercise exact-head manifest resolution and writeback without live credentials."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import dev10_lockfile_pr as resolver


class ManifestWritebackTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cwd = Path(self.tmp.name)
        old_cwd = Path.cwd()
        os.chdir(self.cwd)
        self.addCleanup(os.chdir, old_cwd)
        self.git("init", "-q")
        self.git("config", "user.name", "Fixture Preparer")
        self.git("config", "user.email", "fixture@example.invalid")
        (self.cwd / "config").mkdir()
        self.lock = b"export PYTHON_VERSION=3.14.10\nexport PYTHON_MINOR=3.14\n"
        self.files = {"config/versions.lock": self.lock, ".python-version": b"3.14\n"}
        (self.cwd / "config/versions.lock").write_bytes(self.lock)
        (self.cwd / ".python-version").write_bytes(b"3.14\n")
        (self.cwd / "config/versions.yaml").write_text("python: 3.14.10\n")
        base = self.commit()
        (self.cwd / "config/versions.yaml").write_text("python: 3.14.9\n")
        head = self.commit()
        self.event = {"pull_request": {
            "state": "open", "number": 99,
            "base": {"ref": "main", "sha": base, "repo": {"full_name": resolver.REPOSITORY}},
            "head": {"ref": "toolchain/python-pin", "sha": head, "repo": {"full_name": resolver.REPOSITORY}},
        }}

    def git(self, *args):
        return subprocess.check_output(["git", *args], text=True).strip()

    def commit(self):
        self.git("add", ".")
        self.git("commit", "-qm", "fixture")
        return self.git("rev-parse", "HEAD")

    def test_manifest_only_stage_reads_the_reviewed_base_lock(self):
        output = self.cwd / "intent.yaml"
        self.assertTrue(resolver.inspect_change(self.event, trusted=True))
        resolver.stage(self.event, output, trusted=True)
        self.assertEqual(output.read_text(), "python: 3.14.9\n")
        self.assertEqual((self.cwd / "config/versions.lock").read_bytes(), self.lock)

    def test_extra_code_change_is_outside_automatic_writeback_scope(self):
        Path("script.sh").write_text("exit 1\n")
        self.event["pull_request"]["head"]["sha"] = self.commit()
        self.assertFalse(resolver.inspect_change(self.event, trusted=True))

    def test_symlink_manifest_is_not_a_resolver_input(self):
        manifest = Path("config/versions.yaml")
        manifest.unlink()
        manifest.symlink_to("../.python-version")
        self.event["pull_request"]["head"]["sha"] = self.commit()
        with self.assertRaisesRegex(resolver.ResolutionError, "regular Git blob"):
            resolver.stage(self.event, self.cwd / "intent.yaml", trusted=True)

    def test_fork_handoff_receipt_binds_both_generated_files_to_exact_source(self):
        receipt = resolver.resolution_receipt(self.event, self.files)
        pr = self.event["pull_request"]
        self.assertEqual(receipt["head_sha"], pr["head"]["sha"])
        self.assertEqual(receipt["base_sha"], pr["base"]["sha"])
        self.assertEqual(receipt["manifest_sha256"], hashlib.sha256(b"python: 3.14.9\n").hexdigest())
        self.assertEqual(receipt["generated_sha256"], {
            name: hashlib.sha256(content).hexdigest() for name, content in self.files.items()
        })

    def test_fork_receives_read_only_resolution_and_is_ineligible_for_writeback(self):
        self.event["pull_request"]["head"]["repo"]["full_name"] = "fork/baobab-dev"
        self.assertTrue(resolver.inspect_change(self.event, trusted=False))
        with self.assertRaisesRegex(resolver.ResolutionError, "same-repository"):
            resolver.writeback(self.event, self.files, "read", "write")

    def test_noop_avoids_any_remote_operation(self):
        with patch.object(resolver, "rest_request") as read, patch.object(resolver, "request_json") as write:
            self.assertIsNone(resolver.writeback(self.event, self.files, "read", "write"))
        read.assert_not_called()
        write.assert_not_called()

    def test_only_generated_paths_use_an_immutable_head_lease(self):
        self.files["config/versions.lock"] = self.lock.replace(b"3.14.10", b"3.14.9")
        head = self.event["pull_request"]["head"]["sha"]
        result = {"data": {"createCommitOnBranch": {"commit": {"oid": "e" * 40}}}}
        with (patch.object(resolver, "rest_request", return_value=(200, self.event["pull_request"])),
              patch.object(resolver, "request_json", return_value=(200, result)) as api):
            self.assertEqual(resolver.writeback(self.event, self.files, "read", "write"), "e" * 40)
        payload = json.loads(api.call_args.args[0].data)
        draft = payload["variables"]["input"]
        self.assertEqual(draft["expectedHeadOid"], head)
        self.assertEqual(draft["branch"]["branchName"], "toolchain/python-pin")
        self.assertEqual([x["path"] for x in draft["fileChanges"]["additions"]], ["config/versions.lock"])

    def test_head_change_refuses_without_writing(self):
        self.files["config/versions.lock"] = self.lock.replace(b"3.14.10", b"3.14.9")
        current = deepcopy(self.event["pull_request"])
        current["head"]["sha"] = "a" * 40
        with (patch.object(resolver, "rest_request", return_value=(200, current)),
              patch.object(resolver, "request_json") as write,
              self.assertRaisesRegex(resolver.ResolutionError, "changed during resolution")):
            resolver.writeback(self.event, self.files, "read", "write")
        write.assert_not_called()

    def test_forged_key_and_inconsistent_python_pin_are_rejected(self):
        for files in (
            dict(self.files, **{"config/versions.lock": self.lock + b"export EXTRA=1\n"}),
            dict(self.files, **{".python-version": b"3.15\n"}),
        ):
            with self.subTest(files=files), self.assertRaises(resolver.ResolutionError):
                resolver.validate_resolution(files, self.lock)

    def test_generated_source_pin_requires_the_full_commit(self):
        pin = b"export GH_SOURCE_COMMIT=" + b"a" * 40 + b"\n"
        expected_lock = self.lock + pin
        files = dict(self.files, **{"config/versions.lock": expected_lock})
        resolver.validate_resolution(files, expected_lock)
        files["config/versions.lock"] = self.lock + b"export GH_SOURCE_COMMIT=abcdef\n"
        with self.assertRaisesRegex(resolver.ResolutionError, "malformed source commit"):
            resolver.validate_resolution(files, expected_lock)


class ManifestResolverFailureTests(unittest.TestCase):
    def test_unavailable_and_mismatched_python_sources_leave_existing_files_intact(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "config").mkdir()
            shutil.copyfile(ROOT / "config/resolve.sh", root / "config/resolve.sh")
            manifest = root / "intent.yaml"
            manifest.touch()
            lock = root / "config/versions.lock"
            lock.write_text("export PYTHON_VERSION=3.14.10\n")
            output = root / "out"
            (output / "config").mkdir(parents=True)
            files = [output / ".python-version", output / "config/versions.lock"]
            for file in files:
                file.write_text("existing\n")

            for name, script in {
                "yq": (
                    '#!/bin/bash\nif [ "$2" = .languages.python.version ]; then echo 3.14.9; '
                    "else echo " + hashlib.sha256(b"expected-tarball").hexdigest() + "; fi\n"
                ),
                "curl": (
                    '#!/bin/bash\n[ "${FETCH_FAIL:-0}" = 0 ] || exit 22\n'
                    'printf %s unexpected-tarball > "${!#}"\n'
                ),
            }.items():
                executable = root / name
                executable.write_text(script)
                executable.chmod(0o755)
            for flag, message in (("1", "source archive is unavailable"), ("0", "SHA-256 does not match")):
                env = os.environ | {"PATH": str(root) + os.pathsep + os.environ["PATH"], "FETCH_FAIL": flag}
                result = subprocess.run(
                    ["bash", str(root / "config/resolve.sh"), "--manifest", str(manifest),
                     "--output-dir", str(output)], capture_output=True, text=True, check=False, env=env,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                self.assertTrue(all(file.read_text() == "existing\n" for file in files))


if __name__ == "__main__":
    unittest.main()
