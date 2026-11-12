"""DEV-14 non-mutating developer diagnostic safety regression tests."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

script = Path(__file__).resolve().parents[1] / "scripts/dev14-doctor.py"
spec = importlib.util.spec_from_file_location("dev14_doctor", script)
doctor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(doctor)


def git(root: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(root), *args], check=True,
        capture_output=True, text=True,
    )
    return proc.stdout.strip()


def make_shared_repo(parent: Path, *, remote="https://github.com/baobab-platform/shared.git"):
    root = parent / "shared"
    root.mkdir()
    subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
    git(root, "config", "user.name", "DEV-14 test")
    git(root, "config", "user.email", "dev14@example.invalid")
    (root / "contract.yaml").write_text("policy: deny\n", encoding="utf-8")
    git(root, "add", "contract.yaml")
    git(root, "commit", "-m", "fixture")
    git(root, "remote", "add", "origin", remote)
    return root, git(root, "rev-parse", "HEAD")


class DoctorTests(unittest.TestCase):
    def test_minimum_versions(self):
        self.assertTrue(doctor.meets_version("Python 3.14.3", (3, 14)))
        self.assertFalse(doctor.meets_version("Python 3.13.16", (3, 14)))
        self.assertTrue(doctor.meets_version("rustc 1.88.0 (123)", (1, 88)))
        self.assertFalse(doctor.meets_version("rustc 1.87.9", (1, 88)))
        self.assertTrue(doctor.python_line_supported("Python 3.14.6"))
        self.assertFalse(doctor.python_line_supported("Python 3.13.16"))
        self.assertFalse(doctor.python_line_supported("Python 3.15.0"))
        self.assertEqual(
            doctor.SHARED_PIN,
            "32b71f3335e566daeb58246f17fcbbf162cf7f53",
        )

    def test_canonical_shared_remote_accepts_https_and_ssh(self):
        for remote in (
            "https://github.com/baobab-platform/shared.git",
            "https://github.com/baobab-platform/shared",
            "git@github.com:baobab-platform/shared.git",
            "ssh://git@github.com/baobab-platform/shared.git",
        ):
            with self.subTest(remote=remote):
                self.assertTrue(doctor.is_canonical_shared_remote(remote))

    def test_canonical_shared_remote_rejects_other_hosts_and_embedded_credentials(self):
        for remote in (
            "https://github.com.evil.example/baobab-platform/shared.git",
            "https://github.com/attacker/shared.git",
            "https://token@github.com/baobab-platform/shared.git",
            "http://github.com/baobab-platform/shared.git",
            "file:///workspace/shared",
        ):
            with self.subTest(remote=remote):
                self.assertFalse(doctor.is_canonical_shared_remote(remote))

    def test_missing_rust_and_docker_block_payments(self):
        with patch.object(doctor.shutil, "which", return_value=None):
            result = doctor.inspect("payments-sandbox")
        self.assertIn("rustc", result["blocked_prerequisites"])
        self.assertIn("docker", result["blocked_prerequisites"])
        self.assertEqual(result["engine_runtime"], "NOT_OBSERVED")
        self.assertFalse(result["production_authorized"])

    def test_valid_local_toolchain_never_proves_engine_execution(self):
        with patch.object(doctor.shutil, "which", return_value="/usr/bin/tool"):
            with patch.object(doctor, "probe", return_value=(True, "Python 3.14.0")):
                result = doctor.inspect("pulse-intelligence")
        self.assertEqual(result["result"], "BLOCKED")
        self.assertIn("shared_contract_pin", result["blocked_prerequisites"])
        self.assertEqual(result["eng_onb_runtime_cases"], "NOT_EXECUTED")

    def test_checkout_matches_real_clean_shared_repository(self):
        with tempfile.TemporaryDirectory() as folder:
            root, sha = make_shared_repo(Path(folder))
            self.assertEqual(
                doctor.inspect_shared_checkout(root, expected_pin=sha), "MATCHED"
            )

    def test_checkout_rejects_real_untrusted_origin(self):
        with tempfile.TemporaryDirectory() as folder:
            root, sha = make_shared_repo(
                Path(folder), remote="https://github.com/attacker/shared.git"
            )
            self.assertEqual(
                doctor.inspect_shared_checkout(root, expected_pin=sha),
                "UNTRUSTED_REMOTE",
            )

    def test_checkout_rejects_wrong_pin_and_dirty_tracked_content(self):
        with tempfile.TemporaryDirectory() as folder:
            root, sha = make_shared_repo(Path(folder))
            self.assertEqual(
                doctor.inspect_shared_checkout(root, expected_pin="0" * 40),
                "MISMATCH",
            )
            (root / "contract.yaml").write_text("policy: allow\n", encoding="utf-8")
            self.assertEqual(
                doctor.inspect_shared_checkout(root, expected_pin=sha),
                "DIRTY_WORKTREE",
            )

    def test_assume_unchanged_cannot_hide_modified_tracked_content(self):
        with tempfile.TemporaryDirectory() as folder:
            root, sha = make_shared_repo(Path(folder))
            git(root, "update-index", "--assume-unchanged", "contract.yaml")
            (root / "contract.yaml").write_text("policy: allow\n", encoding="utf-8")
            self.assertEqual(
                doctor.inspect_shared_checkout(root, expected_pin=sha),
                "INCOMPLETE_INDEX",
            )

    def test_skip_worktree_cannot_hide_modified_tracked_content(self):
        with tempfile.TemporaryDirectory() as folder:
            root, sha = make_shared_repo(Path(folder))
            git(root, "update-index", "--skip-worktree", "contract.yaml")
            (root / "contract.yaml").write_text("policy: allow\n", encoding="utf-8")
            self.assertEqual(
                doctor.inspect_shared_checkout(root, expected_pin=sha),
                "INCOMPLETE_INDEX",
            )

    def test_sparse_checkout_and_sparse_index_are_refused(self):
        for setting in ("core.sparseCheckout", "core.sparseIndex"):
            with self.subTest(setting=setting):
                with tempfile.TemporaryDirectory() as folder:
                    root, sha = make_shared_repo(Path(folder))
                    git(root, "config", setting, "true")
                    self.assertEqual(
                        doctor.inspect_shared_checkout(root, expected_pin=sha),
                        "INCOMPLETE_INDEX",
                    )

    def test_fsmonitor_and_credential_hooks_are_not_executed_and_index_is_not_mutated(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            root, sha = make_shared_repo(base)
            marker = base / "hook-was-executed"
            hook = base / "fsmonitor-hook"
            hook.write_text(
                "#!/bin/sh\nprintf executed > " + str(marker) + "\n",
                encoding="utf-8",
            )
            hook.chmod(0o755)
            git(root, "config", "core.fsmonitor", str(hook))
            git(root, "config", "credential.helper", str(hook))
            index = root / ".git" / "index"
            before = (index.read_bytes(), index.stat().st_mtime_ns)

            self.assertEqual(
                doctor.inspect_shared_checkout(root, expected_pin=sha), "MATCHED"
            )
            after = (index.read_bytes(), index.stat().st_mtime_ns)
            self.assertEqual(after, before)
            self.assertFalse(marker.exists())

    def test_submodule_fsmonitor_hook_and_index_are_also_read_only(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            root, _ = make_shared_repo(base)
            submodule_source = base / "submodule-source"
            submodule_source.mkdir()
            subprocess.run(["git", "-C", str(submodule_source), "init", "-q"], check=True)
            git(submodule_source, "config", "user.name", "DEV-14 test")
            git(submodule_source, "config", "user.email", "dev14@example.invalid")
            (submodule_source / "native.txt").write_text("native\n", encoding="utf-8")
            git(submodule_source, "add", "native.txt")
            git(submodule_source, "commit", "-m", "submodule fixture")
            subprocess.run([
                "git", "-c", "protocol.file.allow=always", "-C", str(root),
                "submodule", "add", str(submodule_source), "modules/native",
            ], check=True, capture_output=True, text=True)
            git(root, "add", "modules/native")
            git(root, "commit", "-m", "add native submodule")
            sha = git(root, "rev-parse", "HEAD")

            marker_file = base / "submodule-hook-was-executed"
            hook = base / "submodule-fsmonitor-hook"
            hook.write_text(
                "#!/bin/sh\nprintf executed > " + str(marker_file) + "\n",
                encoding="utf-8",
            )
            hook.chmod(0o755)
            submodule = root / "modules" / "native"
            git(submodule, "config", "core.fsmonitor", str(hook))
            super_index = root / ".git" / "index"
            sub_index = root / ".git" / "modules" / "modules" / "native" / "index"
            before = (
                super_index.read_bytes(), super_index.stat().st_mtime_ns,
                sub_index.read_bytes(), sub_index.stat().st_mtime_ns,
            )

            self.assertEqual(
                doctor.inspect_shared_checkout(root, expected_pin=sha), "MATCHED"
            )
            after = (
                super_index.read_bytes(), super_index.stat().st_mtime_ns,
                sub_index.read_bytes(), sub_index.stat().st_mtime_ns,
            )
            self.assertEqual(after, before)
            self.assertFalse(marker_file.exists())

    def test_git_environment_overrides_cannot_redirect_checkout_probe(self):
        with tempfile.TemporaryDirectory() as folder:
            root, sha = make_shared_repo(Path(folder))
            with patch.dict(os.environ, {
                "GIT_DIR": str(Path(folder) / "not-the-repository"),
                "GIT_INDEX_FILE": str(Path(folder) / "foreign-index"),
            }):
                self.assertEqual(
                    doctor.inspect_shared_checkout(root, expected_pin=sha), "MATCHED"
                )

    def test_long_repository_path_is_not_truncated(self):
        with tempfile.TemporaryDirectory() as folder:
            parent = Path(folder)
            for part in ("a" * 42, "b" * 42, "c" * 42):
                parent = parent / part
            parent.mkdir(parents=True)
            root, sha = make_shared_repo(parent)
            self.assertGreater(len(str(root)), 120)
            self.assertEqual(
                doctor.inspect_shared_checkout(root, expected_pin=sha), "MATCHED"
            )

    def test_checkout_must_be_repository_root(self):
        with tempfile.TemporaryDirectory() as folder:
            root, sha = make_shared_repo(Path(folder))
            nested = root / "nested"
            nested.mkdir()
            self.assertEqual(
                doctor.inspect_shared_checkout(nested, expected_pin=sha),
                "NOT_REPOSITORY_ROOT",
            )

    def test_shared_symlink_not_followed(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            root, _ = make_shared_repo(base)
            link = base / "link"
            link.symlink_to(root, target_is_directory=True)
            self.assertEqual(doctor.inspect_shared_checkout(link), "REFUSED")

    def test_unknown_profile_rejected(self):
        with self.assertRaisesRegex(ValueError, "UNKNOWN_DEV14_PROFILE"):
            doctor.inspect("production-admin")


if __name__ == "__main__":
    unittest.main()
