"""Fix-history evidence is conservative and never assigns a CVE disposition."""
from pathlib import Path
import importlib.util
import os
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
            "apt_exact_version_pockets": ["resolute-updates"],
            "apt_package_metadata_sha256": "a" * 64,
            "apt_policy_sha256": "b" * 64,
            "apt_madison_sha256": "c" * 64,
            "apt_package_deb_sha256": m.LOCK.binary_artifact_sha256["amd64"],
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
            binary_source=m.LOCK.binary_source,
            binary_artifact_sha256=m.LOCK.binary_artifact_sha256,
            observed_kernel_cves=m.LOCK.observed_kernel_cves,
        )

    def candidate(self, value="int example(void) { return 1; }\n"):
        (self.upstream_repo / "drivers/example.c").write_text(value, encoding="utf-8")
        git(self.upstream_repo, "add", ".")
        git(self.upstream_repo, "commit", "-qm", "upstream security fix")
        git(self.upstream_repo, "push", "-q", "origin", "HEAD:refs/heads/main")
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

    def run_audit(self, reference=None, expected_commit=None, **kwargs):
        git(self.ubuntu, "tag", "-f", self.lock.ubuntu_tag)
        self.tag_commit = git(self.ubuntu, "rev-parse", "HEAD")
        self.lock.ubuntu_tag_commit = self.tag_commit
        upstream, ubuntu_paths = self.records(reference)
        with mock.patch.object(m, "LOCK", self.lock):
            return m.audit(
                upstream, ubuntu_paths, self.ubuntu, self.candidate_root,
                self.binary_source, expected_commit or self.tag_commit,
                self.remotes, {"upstream_evidence_sha256": "a" * 64},
                **kwargs,
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
        git(self.ubuntu, "cherry-pick", "-x", sha)
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

    def test_backport_trailer_without_patch_equivalence_stays_unverified(self):
        sha = self.candidate()
        git(self.ubuntu, "fetch", "-q", "stable", sha)
        (self.ubuntu / "drivers/example.c").write_text(
            "int example(void) { return 2; }\n", encoding="utf-8"
        )
        git(self.ubuntu, "add", ".")
        git(self.ubuntu, "commit", "-qm", "Backport from commit " + sha)
        report = self.run_audit("https://git.kernel.org/stable/c/" + sha)
        candidate = report["records"][0]["candidates"][0]
        self.assertEqual(candidate["assessment"], "BACKPORT_TRAILER_WITHOUT_PATCH_ID_MATCH")
        self.assertEqual(len(candidate["backport_trailer_matches"]), 1)
        self.assertEqual(candidate["patch_id_matches"], [])

    def test_duplicate_patch_ids_are_ambiguous(self):
        sha = self.candidate()
        git(self.ubuntu, "fetch", "-q", "stable", sha)
        git(self.ubuntu, "cherry-pick", "-x", sha)
        first = git(self.ubuntu, "rev-parse", "HEAD")
        git(self.ubuntu, "revert", "--no-edit", first)
        git(self.ubuntu, "cherry-pick", "-x", sha)
        report = self.run_audit("https://git.kernel.org/stable/c/" + sha)
        candidate = report["records"][0]["candidates"][0]
        self.assertEqual(candidate["assessment"], "AMBIGUOUS_STABLE_PATCH_ID_CORRESPONDENCE")
        self.assertEqual(len(candidate["patch_id_matches"]), 2)

    def test_truncated_history_never_claims_a_unique_patch_match(self):
        sha = self.candidate()
        git(self.ubuntu, "fetch", "-q", "stable", sha)
        git(self.ubuntu, "cherry-pick", "-x", sha)
        (self.ubuntu / "drivers/example.c").write_text(
            "int example(void) { return 3; }\n", encoding="utf-8"
        )
        git(self.ubuntu, "add", ".")
        git(self.ubuntu, "commit", "-qm", "later unrelated edit")
        with mock.patch.object(m, "MAX_PATH_HISTORY_COMMITS", 1):
            report = self.run_audit("https://git.kernel.org/stable/c/" + sha)
        candidate = report["records"][0]["candidates"][0]
        self.assertTrue(candidate["history_search"]["truncated"])
        self.assertEqual(candidate["assessment"], "PATCH_ID_MATCH_FOUND_BUT_HISTORY_TRUNCATED")

    def test_unavailable_downstream_patch_id_refuses_complete_correspondence(self):
        sha = self.candidate()
        downstream = git(self.ubuntu, "rev-parse", "HEAD")
        read_patch = m.patch_id
        with mock.patch.object(m, "patch_id", side_effect=lambda repo, commit: (
            None if commit == downstream else read_patch(repo, commit)
        )):
            report = self.run_audit("https://git.kernel.org/stable/c/" + sha)
        candidate = report["records"][0]["candidates"][0]
        self.assertEqual(candidate["assessment"], "DOWNSTREAM_PATCH_EVIDENCE_INCOMPLETE")
        self.assertFalse(candidate["history_search"]["complete_for_selected_paths"])
        self.assertEqual(candidate["history_search"]["patch_id_unavailable_count"], 1)
        self.assertEqual(candidate["history_search"]["patch_id_unavailable_commits"], [downstream])

    def test_upstream_fetch_timeout_retains_under_investigation(self):
        sha = "1" * 40
        with mock.patch.object(m, "fetch_candidates", side_effect=subprocess.TimeoutExpired("git fetch", 1)):
            report = self.run_audit("https://git.kernel.org/stable/c/" + sha)
        candidate = report["records"][0]["candidates"][0]
        self.assertEqual(candidate["assessment"], "candidate_fetch_timed_out")
        self.assertIsNone(candidate["exact_commit_ancestor_of_ubuntu_tag"])
        self.assertEqual(report["counts"], {"under_investigation": 298})

    def test_timed_out_fetch_releases_only_its_shallow_lock(self):
        bin_path = self.candidate_root.parent / "bin"
        bin_path.mkdir()
        executable = bin_path / "git"
        executable.write_text("#!/bin/sh\n"
                              "if [ \"${HANG_FETCH:-}\" = yes ]; then\n"
                              "  touch \"$2/.git/shallow.lock\"\n"
                              "  sleep 20 &\n"
                              "  wait\n"
                              "fi\n")
        executable.chmod(0o755)
        lock = self.candidate_root / ".git/shallow.lock"
        with mock.patch.dict(os.environ, {"PATH": str(bin_path) + ":" + os.environ["PATH"], "HANG_FETCH": "yes"}):
            with self.assertRaises(subprocess.TimeoutExpired):
                m.fetch_candidates(self.candidate_root, "stable", ["1" * 40], 0.3)
            self.assertFalse(lock.exists())
            with mock.patch.dict(os.environ, {"HANG_FETCH": "no"}):
                self.assertEqual(m.fetch_candidates(self.candidate_root, "stable", ["1" * 40], 1).returncode, 0)
                lock.write_text("owned by another Git process")
                with self.assertRaisesRegex(m.EvidenceError, "pre-existing shallow lock"):
                    m.fetch_candidates(self.candidate_root, "stable", ["1" * 40], 1)
                self.assertEqual(lock.read_text(), "owned by another Git process")

    def test_non_utf8_history_message_does_not_hide_an_exact_ascii_backport_reference(self):
        sha = self.candidate()
        message = b"Historical subject with a legacy byte " + bytes([0xe9]) + b"\n\n"
        message += f"(cherry picked from commit {sha})\n".encode("ascii")
        subprocess.run(
            ["git", "-C", str(self.ubuntu), "-c", "i18n.commitEncoding=UTF-8",
             "commit", "--allow-empty", "-q", "-F", "-"], input=message, check=True, capture_output=True,
        )
        head = git(self.ubuntu, "rev-parse", "HEAD")
        self.assertEqual(m.trailer_index(self.ubuntu, head, {sha}), {sha: [head]})

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

    def test_expired_analysis_budget_records_every_cve_and_known_trailer(self):
        sha = self.candidate()
        git(self.ubuntu, "commit", "--allow-empty", "-qm", f"Backport from commit {sha}")
        head = git(self.ubuntu, "rev-parse", "HEAD")
        report = self.run_audit("https://git.kernel.org/stable/c/" + sha, analysis_seconds=0)
        candidate = report["records"][0]["candidates"][0]
        self.assertEqual(candidate["assessment"], "ANALYSIS_BUDGET_EXHAUSTED")
        self.assertIsNone(candidate["exact_commit_ancestor_of_ubuntu_tag"])
        self.assertEqual(candidate["backport_trailer_matches"], [{"commit": head, "patch_id": None}])
        self.assertTrue(report["analysis_budget_exhausted"])
        self.assertEqual(report["record_count"], 298)

    def test_ancestor_membership_is_verified_before_backport_budget(self):
        sha = self.candidate()
        git(self.ubuntu, "fetch", "-q", "stable", sha)
        git(self.ubuntu, "merge", "--ff-only", sha)
        report = self.run_audit("https://git.kernel.org/stable/c/" + sha, analysis_seconds=0)
        entry = report["records"][0]["candidates"][0]
        self.assertTrue(entry["exact_commit_ancestor_of_ubuntu_tag"])
        self.assertEqual(entry["ubuntu_merge_base"], sha)
        self.assertEqual(report["assessment_counts"]["EXACT_UPSTREAM_COMMIT_IN_UBUNTU_ANCESTRY"], 1)

    def test_absent_candidate_reference_remains_under_investigation(self):
        report = self.run_audit()
        self.assertEqual(report["records"][0]["candidate_count"], 0)
        self.assertEqual(report["counts"], {"under_investigation": 298})

    def test_observed_scope_retains_every_deferred_reference_without_fetching(self):
        self.lock.observed_kernel_cves = {"CVE-2026-30001"}
        with mock.patch.object(m, "ensure_candidate_object", side_effect=AssertionError("unexpected fetch")):
            report = self.run_audit("https://git.kernel.org/stable/c/" + "a" * 40, scope="observed")
        self.assertEqual(report["selected_cve_count"], 1)
        self.assertEqual(report["record_count"], 298)
        self.assertEqual(report["records"][0]["candidates"][0]["assessment"],
                         "DEFERRED_OUTSIDE_OBSERVED_SCOPE")
        self.assertFalse(report["analysis_budget_exhausted"])

    def test_batched_patch_ids_equal_each_individual_complete_diff(self):
        commits = []
        for index in range(5):
            (self.ubuntu / "note").write_text(str(index))
            git(self.ubuntu, "add", ".")
            git(self.ubuntu, "commit", "-qm", "change")
            commits.append(git(self.ubuntu, "rev-parse", "HEAD"))
        cache = {}
        m.prime_patch_ids(self.ubuntu, commits, cache, m.monotonic() + 30)
        for sha in commits:
            self.assertEqual(cache[str(self.ubuntu.resolve()), sha], m.patch_id(self.ubuntu, sha))

    def test_shallow_history_is_rejected(self):
        sha = git(self.ubuntu, "rev-parse", "HEAD")
        git(self.ubuntu, "tag", self.lock.ubuntu_tag, sha)
        shallow_file = self.ubuntu / ".git/shallow"
        shallow_file.write_text(sha + "\n", encoding="ascii")
        upstream, ubuntu_paths = self.records()
        self.lock.ubuntu_tag_commit = sha
        with mock.patch.object(m, "LOCK", self.lock):
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
        self.lock.ubuntu_tag_commit = "0" * 40
        with mock.patch.object(m, "LOCK", self.lock):
            with self.assertRaisesRegex(m.EvidenceError, "do not match"):
                m.audit(
                    upstream, ubuntu_paths, self.ubuntu, self.candidate_root,
                    self.binary_source, "0" * 40, self.remotes, {},
                )




class SourceReviewTests(unittest.TestCase):
    def test_inspects_verified_debian_bytes_and_reports_unknown_content(self):
        import hashlib
        from reconcile_ubuntu_image_findings import payload_contents
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package = root / "package"
            (package / "DEBIAN").mkdir(parents=True)
            (package / "DEBIAN/control").write_text(
                "Package: witness\nVersion: 1\nArchitecture: amd64\n"
                "Maintainer: Test <test@example.invalid>\nDescription: fixture\n")
            header = package / "usr/include/example.h"
            header.parent.mkdir(parents=True)
            header.write_text('#include <private/reviewed.h>\n#include GENERATED_HEADER\n')
            tool = package / "usr/bin/example"
            tool.parent.mkdir(parents=True)
            tool.write_bytes(b"\x7fELF")
            tool.chmod(0o755)
            deb = root / "amd64" / f"linux-libc-dev_{m.LOCK.package_version}_amd64.deb"
            deb.parent.mkdir()
            subprocess.run(["dpkg-deb", "--build", str(package), str(deb)],
                           capture_output=True, check=True)
            with self.assertRaisesRegex(ValueError, "unreviewed"):
                payload_contents(root, "amd64", "0" * 64)
            info, includes = payload_contents(root, "amd64", hashlib.sha256(deb.read_bytes()).hexdigest())
            self.assertEqual(includes["reviewed.h"], {"/usr/include/example.h"})
            self.assertEqual(info["headers_with_nonliteral_includes"], ["/usr/include/example.h"])
            self.assertEqual(info["other_entries"], ["/usr/bin/example"])
            self.assertEqual(info["elf_or_archive_files"], info["other_entries"])
            self.assertEqual(info["executable_mode_files"], info["other_entries"])

    def test_file_evidence_is_bound_to_tag_commit_and_exact_lead(self):
        import copy
        import json
        from reconcile_ubuntu_image_findings import source_review
        rules = json.loads((ROOT / "security/evidence/dev10-run533-leads.json").read_bytes())
        tag = rules["reviewed_ubuntu_tag"]
        for lead in rules["leads"]:
            entry = rules["source_reviews"][lead["ubuntu"]]
            witness = dict(**lead, same_ordered_edits=True, stable_patch_equivalence=True,
                           ubuntu_edit_sha256=entry["edit_sha256"], upstream_edit_sha256=entry["edit_sha256"],
                           ubuntu_patch_id=entry["patch_id"], upstream_patch_id=entry["patch_id"],
                           tag_path_comparison=copy.deepcopy(entry["paths"]))
            self.assertEqual(source_review(witness, rules, tag), entry["observation"])
            self.assertIn("REVIEW_REQUIRED", source_review(witness, rules, "0" * 40))
            for change in ({"upstream": "a" * 40}, {"same_ordered_edits": False},
                           {"ubuntu_patch_id": "0" * 40}, {"stable_patch_equivalence": False}, {"tag_path_comparison": []}):
                self.assertIn("REVIEW_REQUIRED", source_review(witness | change, rules, tag))
            witness["tag_path_comparison"][0]["at_tag"] = "different"
            self.assertIn("REVIEW_REQUIRED", source_review(witness, rules, tag))


if __name__ == "__main__":
    unittest.main()
