"""Fix-history evidence is conservative and never assigns a CVE disposition."""
from pathlib import Path
import importlib.util
import subprocess
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "fix_history", ROOT / "scripts/audit_ubuntu_kernel_fix_history.py"
)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def git(path, *args, check=True):
    return subprocess.run(
        ["git", "-C", str(path), *args], check=check,
        capture_output=True, text=True,
    ).stdout.strip()


class UbuntuFixHistoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.ubuntu = root / "ubuntu"
        self.ubuntu.mkdir()
        git(self.ubuntu, "init", "-q")
        git(self.ubuntu, "config", "user.name", "DEV10 Test")
        git(self.ubuntu, "config", "user.email", "dev10-test@example.invalid")
        (self.ubuntu / "drivers").mkdir()
        (self.ubuntu / "drivers/example.c").write_text(
            "int example(void) { return 0; }\n", encoding="utf-8"
        )
        git(self.ubuntu, "add", ".")
        git(self.ubuntu, "commit", "-qm", "Ubuntu source base")
        git(self.ubuntu, "remote", "add", "origin", m.SOURCE_REPO)

        self.bare = root / "stable.git"
        subprocess.run(["git", "init", "--bare", "-q", str(self.bare)], check=True)
        git(self.ubuntu, "remote", "add", "stable", str(self.bare))
        git(self.ubuntu, "push", "-q", "stable", "HEAD:refs/heads/main")
        self.upstream_repo = root / "upstream"
        subprocess.run(["git", "clone", "-q", str(self.ubuntu), str(self.upstream_repo)], check=True)
        git(self.upstream_repo, "config", "user.name", "Upstream Test")
        git(self.upstream_repo, "config", "user.email", "upstream@example.invalid")
        git(self.upstream_repo, "remote", "set-url", "origin", str(self.bare))
        self.candidate_root = root / "candidate-objects"
        self.candidate_root.mkdir()
        git(self.candidate_root, "init", "-q")
        git(self.candidate_root, "remote", "add", "stable", str(self.bare))
        self.remotes = {"stable": str(self.bare), "linus": str(self.bare)}
        self.binary_source = {
            "schema": "baobab.dev10.ubuntu-binary-source-provenance.v1",
            "binary_package": "linux-libc-dev",
            "binary_version": "7.0.0-43.43",
            "architecture": "amd64",
            "source_package": "linux",
            "source_version": "7.0.0-43.43",
            "release_pocket": "resolute-updates",
            "binary_status": "install ok installed",
            "apt_candidate_version": "7.0.0-43.43",
            "apt_package_metadata_sha256": "a" * 64,
            "apt_policy_sha256": "b" * 64,
            "apt_madison_sha256": "c" * 64,
            "apt_package_deb_sha256": "d" * 64,
            "apt_package_deb_filename": "linux-libc-dev_7.0.0-43.43_amd64.deb",
            "apt_package_index_sha256": [{"sha256": "e" * 64, "index_name": "Packages"}],
            "installed_package_metadata_sha256": "f" * 64,
            "ubuntu_base_image": "ubuntu@sha256:" + "1" * 64,
        }
        self.tag_commit = ""
        self.lock = types.SimpleNamespace(
            inventory_count=298,
            package_version="7.0.0-43.43",
            ubuntu_tag=m.LOCK.ubuntu_tag,
            ubuntu_tag_commit="",
            binary_source=self.binary_source,
        )

    def candidate(self, value="int example(void) { return 1; }\n"):
        (self.upstream_repo / "drivers/example.c").write_text(value, encoding="utf-8")
        git(self.upstream_repo, "add", ".")
        git(self.upstream_repo, "commit", "-qm", "upstream security fix")
        git(self.upstream_repo, "push", "-q", "origin", "HEAD")
        return git(self.upstream_repo, "rev-parse", "HEAD")

    def records(self, reference=None):
        rows = []
        ubuntu_rows = []
        for index in range(298):
            cve = f"CVE-2026-{30000 + index}"
            refs = [reference] if index == 0 and reference else []
            rows.append({
                "cve": cve, "upstream_paths": ["drivers/example.c"],
                "candidate_upstream_fix_references": refs, "error": "",
            })
            ubuntu_rows.append({
                "cve": cve,
                "upstream_path_correspondence": [{
                    "upstream_path": "drivers/example.c",
                    "same_basename_candidates": [],
                }],
            })
        return (
            {"package": "linux-libc-dev=7.0.0-43.43", "records": rows},
            {"records": ubuntu_rows},
        )

    def run_audit(self, reference=None, expected_commit=None):
        git(self.ubuntu, "tag", "-f", self.lock.ubuntu_tag)
        self.tag_commit = git(self.ubuntu, "rev-parse", "HEAD")
        self.lock.ubuntu_tag_commit = self.tag_commit
        upstream, ubuntu_paths = self.records(reference)
        with mock.patch.object(m, "LOCK", self.lock):
            return m.audit(
                upstream, ubuntu_paths, self.ubuntu, self.candidate_root,
                self.binary_source, expected_commit or self.tag_commit,
                self.remotes, {"upstream_evidence_sha256": "a" * 64},
            )

    def test_exact_upstream_commit_ancestor_is_recorded_without_fix_disposition(self):
        sha = self.candidate()
        git(self.ubuntu, "fetch", "-q", "stable", sha)
        git(self.ubuntu, "merge", "--ff-only", sha)
        report = self.run_audit("https://git.kernel.org/stable/c/" + sha)
        candidate = report["records"][0]["candidates"][0]
        self.assertTrue(candidate["exact_commit_ancestor_of_ubuntu_tag"])
        self.assertEqual(candidate["assessment"], "EXACT_UPSTREAM_COMMIT_IN_UBUNTU_ANCESTRY")
        self.assertEqual(report["counts"], {"under_investigation": 298})
        self.assertEqual(report["records"][0]["disposition"], "under_investigation")

    def test_cherry_pick_with_trailer_and_matching_patch_id_is_reported(self):
        sha = self.candidate()
        git(self.ubuntu, "fetch", "-q", "stable", sha)
        git(self.ubuntu, "cherry-pick", "-q", "-x", sha)
        report = self.run_audit("https://git.kernel.org/stable/c/" + sha)
        candidate = report["records"][0]["candidates"][0]
        self.assertFalse(candidate["exact_commit_ancestor_of_ubuntu_tag"])
        self.assertEqual(candidate["assessment"], "UNIQUE_STABLE_PATCH_ID_CORRESPONDENCE")
        self.assertEqual(len(candidate["patch_id_matches"]), 1)
        self.assertEqual(len(candidate["backport_trailer_matches"]), 1)
        self.assertEqual(report["counts"], {"under_investigation": 298})

    def test_unrelated_change_is_not_reported_as_a_backport(self):
        sha = self.candidate()
        (self.ubuntu / "drivers/example.c").write_text(
            "int example(void) { return 7; }\n", encoding="utf-8"
        )
        git(self.ubuntu, "add", ".")
        git(self.ubuntu, "commit", "-qm", "unrelated source change")
        report = self.run_audit("https://git.kernel.org/stable/c/" + sha)
        candidate = report["records"][0]["candidates"][0]
        self.assertEqual(candidate["assessment"],
                         "NO_PATCH_ID_MATCH_IN_COMPLETE_SELECTED_PATH_HISTORY")
        self.assertEqual(candidate["patch_id_matches"], [])

    def test_missing_candidate_object_is_an_explicit_evidence_gap(self):
        sha = "1" * 40
        report = self.run_audit("https://git.kernel.org/stable/c/" + sha)
        candidate = report["records"][0]["candidates"][0]
        self.assertEqual(candidate["assessment"], "candidate_commit_unavailable")
        self.assertEqual(report["counts"], {"under_investigation": 298})

    def test_invalid_candidate_reference_is_not_trusted(self):
        report = self.run_audit("https://example.invalid/commit/123")
        record = report["records"][0]
        self.assertEqual(record["candidate_count"], 0)
        self.assertEqual(record["invalid_reference_count"], 1)
        self.assertEqual(record["disposition"], "under_investigation")

    def test_absent_candidate_reference_remains_under_investigation(self):
        report = self.run_audit()
        self.assertEqual(report["records"][0]["candidate_count"], 0)
        self.assertEqual(report["counts"], {"under_investigation": 298})

    def test_shallow_history_is_rejected(self):
        sha = git(self.ubuntu, "rev-parse", "HEAD")
        shallow_file = self.ubuntu / ".git/shallow"
        shallow_file.write_text(sha + "\n", encoding="ascii")
        upstream, ubuntu_paths = self.records()
        with unittest.mock.patch.object(m, "LOCK", self.lock):
            with self.assertRaisesRegex(m.EvidenceError, "history is shallow"):
                m.audit(
                    upstream, ubuntu_paths, self.ubuntu, self.candidate_root,
                    self.binary_source, sha, self.remotes, {},
                )

    def test_wrong_tag_commit_is_rejected(self):
        upstream, ubuntu_paths = self.records()
        git(self.ubuntu, "tag", "-f", self.lock.ubuntu_tag)
        self.tag_commit = git(self.ubuntu, "rev-parse", "HEAD")
        self.lock.ubuntu_tag_commit = self.tag_commit
        with unittest.mock.patch.object(m, "LOCK", self.lock):
            self.lock.ubuntu_tag_commit = "0" * 40
        with mock.patch.object(m, "LOCK", self.lock):
            with self.assertRaisesRegex(m.EvidenceError, "do not match"):
                m.audit(
                    upstream, ubuntu_paths, self.ubuntu, self.candidate_root,
                    self.binary_source, "0" * 40, self.remotes, {},
                )


if __name__ == "__main__":
    unittest.main()
