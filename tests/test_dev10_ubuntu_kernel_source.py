"""Offline release-tag source checks never turn path presence into CVE clearance."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("ubuntu_git", root / "scripts/audit_ubuntu_kernel_git_paths.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class UbuntuSourceVerificationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        def git(*args):
            return subprocess.run(["git", "-C", str(self.repo), *args],
                                  check=True, capture_output=True)
        git("init", "-q")
        git("config", "user.name", "DEV10 Test")
        git("config", "user.email", "dev10-test@example.invalid")
        (self.repo / "drivers").mkdir()
        (self.repo / "drivers" / "example.c").write_text("/* fixture */\n")
        (self.repo / "include" / "linux").mkdir(parents=True)
        (self.repo / "include" / "linux" / "example.h").write_text("/* private fixture */\n")
        git("remote", "add", "origin", m.SOURCE_REPO)
        for path in [
            "include/linux/bpf_verifier.h",
            "kernel/bpf/liveness.c", "kernel/bpf/verifier.c",
            "drivers/android/binder_alloc.c", "drivers/android/binder_alloc.h",
            "kernel/bpf/arraymap.c",
            "drivers/net/wireless/marvell/libertas/tx.c",
            "fs/smb/server/smb2pdu.c",
        ]:
            target = self.repo / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("/* source fixture */\\n")
        git("add", ".")
        git("commit", "-qm", "fixture kernel source")
        git("tag", m.RELEASE_TAG)
        self.tag_commit = subprocess.run(
            ["git", "-C", str(self.repo), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        generic = [{
                "cve": f"CVE-2026-{30000+i}",
                "upstream_paths": (["include/linux/example.h"] if i < 47 else
                                   ["drivers/example.c"]),
                "affected_headers": (["include/linux/example.h"] if i < 47 else []),
                "candidate_upstream_fix_references": [],
                "error": ""
            } for i in range(287)]
        self.upstream = {
            "package": "linux-libc-dev=" + m.RELEASE_VERSION,
            "records": generic + [
                {"cve": "CVE-2022-50240", "upstream_paths": [
                    "drivers/android/binder_alloc.c", "drivers/android/binder_alloc.h",
                    "drivers/android/binder_alloc_selftest.c"],
                 "affected_headers": ["drivers/android/binder_alloc.h"],
                 "candidate_upstream_fix_references": [], "error": ""},
                {"cve": "CVE-2026-72198", "upstream_paths": ["fs/ntfs/attrib.c"],
                 "affected_headers": [], "candidate_upstream_fix_references": [], "error": ""},
                {"cve": "CVE-2026-90217", "upstream_paths": ["kernel/bpf/states.c"],
                 "affected_headers": [], "candidate_upstream_fix_references": [], "error": ""},
                {"cve": "CVE-2026-98084", "upstream_paths": ["kernel/bpf/backtrack.c"],
                 "affected_headers": [], "candidate_upstream_fix_references": [], "error": ""},
                {"cve": "CVE-2026-98085", "upstream_paths": ["kernel/bpf/backtrack.c"],
                 "affected_headers": [], "candidate_upstream_fix_references": [], "error": ""},
                {"cve": "CVE-2026-98376", "upstream_paths": [
                    "kernel/bpf/arraymap.c",
                    "tools/testing/selftests/bpf/prog_tests/percpu_array_inner_map.c"],
                 "affected_headers": [], "candidate_upstream_fix_references": [], "error": ""},
                {"cve": "CVE-2026-98649", "upstream_paths": ["arch/s390/kvm/gmap/gmap.c"],
                 "affected_headers": [], "candidate_upstream_fix_references": [], "error": ""},
                {"cve": "CVE-2026-98652", "upstream_paths": ["arch/s390/kvm/s390/interrupt.c"],
                 "affected_headers": [], "candidate_upstream_fix_references": [], "error": ""},
                {"cve": "CVE-2026-98869", "upstream_paths": [
                    "include/linux/bpf_verifier.h", "kernel/bpf/fixups.c",
                    "kernel/bpf/liveness.c", "kernel/bpf/verifier.c"],
                 "affected_headers": ["include/linux/bpf_verifier.h"],
                 "candidate_upstream_fix_references": ["https://git.kernel.org/stable/c/7ce090afbf725e25fff29caacce1eaf8459b1117"], "error": ""},
                {"cve": "CVE-2026-98890", "upstream_paths": [
                    "drivers/net/wireless/marvell/libertas/tx.c"],
                 "affected_headers": [], "candidate_upstream_fix_references": [
                    "https://git.kernel.org/stable/c/68c92c991ddb75dfd3fd62a94a1d4d2dde44dc3c",
                    "https://git.kernel.org/stable/c/d865dd6de8295f2bfaa83f0f5d49d2bef1543065",
                    "https://git.kernel.org/stable/c/6576baa3fdbaa91fa75e4ba27095f4b8a27349a8",
                    "https://git.kernel.org/stable/c/b657cc98d7936c5d9ed7e0e1944ad0e1f36375bb",
                    "https://git.kernel.org/stable/c/443fac3de65c76544b450b9f9903be8989150d55",
                    "https://git.kernel.org/stable/c/cdcfd662c67833d89ee3d912efde2eb67c8a7326",
                    "https://git.kernel.org/stable/c/13ff543e0b2c713aedeaadadde686686e949dc78"], "error": ""},
                {"cve": "CVE-2026-99083", "upstream_paths": [
                    "fs/smb/server/smb2pdu.c"],
                 "affected_headers": [], "candidate_upstream_fix_references": [
                    "https://git.kernel.org/stable/c/59c6dcc5dd9dafe764ca0d40525933b2be69b059",
                    "https://git.kernel.org/stable/c/80af1bde97d5a85ad6f2c40ca894ccc8fa75a27a",
                    "https://git.kernel.org/stable/c/517404e157395d0f8da125ca956c566895dfcd06",
                    "https://git.kernel.org/stable/c/4722d06b2907585074252061b1024a696c1cfc23",
                    "https://git.kernel.org/stable/c/23a0be6a84a38ac169eeab49017934e8e27c65f0"], "error": ""},
            ]
        }

    @property
    def binary_source(self):
        return {
            "schema": "baobab.dev10.ubuntu-binary-source-provenance.v1",
            "binary_package": "linux-libc-dev",
            "binary_version": m.RELEASE_VERSION,
            "architecture": "amd64",
            "source_package": "linux",
            "source_version": m.RELEASE_VERSION,
            "release_pocket": "resolute-updates",
            "binary_status": "install ok installed",
            "apt_candidate_version": m.RELEASE_VERSION,
            "apt_package_metadata_sha256": "a" * 64,
            "apt_policy_sha256": "b" * 64,
            "apt_madison_sha256": "c" * 64,
            "apt_package_deb_sha256": "d" * 64,
            "apt_package_deb_filename": f"linux-libc-dev_{m.RELEASE_VERSION}_amd64.deb",
            "apt_package_index_sha256": [{"sha256": "e" * 64, "index_name": "Packages"}],
            "installed_package_metadata_sha256": "f" * 64,
            "ubuntu_base_image": "ubuntu@sha256:" + "1" * 64,
        }

    def inspect(self, upstream=None, paths=None, **kwargs):
        return m.inspect(upstream or self.upstream, self.repo, paths or set(),
                         binary_source=kwargs.pop("binary_source", self.binary_source),
                         expected_commit=kwargs.pop("expected_commit", self.tag_commit),
                         **kwargs)

    def test_binary_source_mapping_must_match_the_reviewed_package_identity(self):
        source = dict(self.binary_source)
        source["source_package"] = "linux-raspi"
        with self.assertRaisesRegex(ValueError, "mismatched Ubuntu binary/source package identity"):
            self.inspect(binary_source=source)

    def test_298_paths_present_but_no_automatic_fix_or_vex(self):
        report = self.inspect()
        self.assertEqual(report["counts"], {"under_investigation": 298})
        self.assertEqual(report["path_counts"], {
            "PATHS_PRESENT_NONDISCRIMINATING": 289,
            "SOME_UPSTREAM_PATHS_MISSING": 9,
        })
        missing_cves = {r["cve"] for r in report["records"]
                        if r["upstream_paths_missing_from_ubuntu_snapshot"]}
        self.assertEqual(missing_cves, {
            "CVE-2022-50240", "CVE-2026-72198", "CVE-2026-90217",
            "CVE-2026-98084", "CVE-2026-98085", "CVE-2026-98376",
            "CVE-2026-98649", "CVE-2026-98652", "CVE-2026-98869",
        })

        self.assertEqual(len(report["records"]), 298)
        self.assertEqual(sum(bool(r["kernel_private_header_paths"]) for r in report["records"]), 49)
        self.assertTrue(all(
            r["ubuntu_source_paths_present"]
            for r in report["records"]
            if r["ubuntu_source_path_status"] == "PATHS_PRESENT_NONDISCRIMINATING"
        ))
        self.assertTrue(all(r["ubuntu_fix_commit_verified"] is False for r in report["records"]))
        self.assertTrue(all(r["uapi_abi_macro_indirect_exposure"] == "under_investigation"
                            for r in report["records"]))

    def test_three_new_cves_have_individual_ubuntu_tag_paths(self):
        report = self.inspect()
        by_cve = {row["cve"]: row for row in report["records"]}
        self.assertEqual(by_cve["CVE-2026-98869"]["ubuntu_source_paths_present"], [
            "include/linux/bpf_verifier.h", "kernel/bpf/liveness.c",
            "kernel/bpf/verifier.c"])
        self.assertEqual(
            by_cve["CVE-2026-98869"]["upstream_paths_missing_from_ubuntu_snapshot"],
            ["kernel/bpf/fixups.c"])
        self.assertEqual(by_cve["CVE-2026-98869"]["ubuntu_source_path_status"],
                         "SOME_UPSTREAM_PATHS_MISSING")
        missing = next(item for item in by_cve["CVE-2026-98869"]["upstream_path_correspondence"]
                       if item["upstream_path"] == "kernel/bpf/fixups.c")
        self.assertEqual(missing["ubuntu_tag_status"], "missing")
        self.assertEqual(missing["same_basename_candidates"], [])
        self.assertTrue(all(by_cve[cve]["ubuntu_source_path_status"] == "PATHS_PRESENT_NONDISCRIMINATING"
                            for cve in ("CVE-2026-98890", "CVE-2026-99083")))
        self.assertEqual(report["counts"], {"under_investigation": 298})
        self.assertEqual(by_cve["CVE-2026-98890"]["ubuntu_source_paths_present"], [
            "drivers/net/wireless/marvell/libertas/tx.c"])
        self.assertEqual(by_cve["CVE-2026-99083"]["ubuntu_source_paths_present"], [
            "fs/smb/server/smb2pdu.c"])
        self.assertTrue(all(by_cve[cve]["ubuntu_fix_commit_verified"] is False
                            for cve in ("CVE-2026-98869", "CVE-2026-98890", "CVE-2026-99083")))

    def test_wrong_source_origin_rejected(self):
        subprocess.run(["git", "-C", str(self.repo), "remote", "set-url",
                        "origin", "https://example.invalid/linux"], check=True)
        with self.assertRaisesRegex(ValueError, "official"):
            self.inspect()

    def test_missing_path_not_misclassified_safe(self):
        self.upstream["records"][0]["upstream_paths"] = ["drivers/missing.c"]
        report = self.inspect()
        self.assertEqual(report["records"][0]["upstream_paths_missing_from_ubuntu_snapshot"],
                         ["drivers/missing.c"])
        self.assertEqual(report["records"][0]["binary_disposition"], "under_investigation")

    def test_moved_or_retagged_release_commit_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "release-tag mismatch"):
            self.inspect(expected_commit="0" * 40)

    def test_git_quoted_paths_are_compared_without_c_style_quoting(self):
        odd = self.repo / "drivers" / "dräft.c"
        odd.write_text("/* non-ASCII path fixture */\n")
        subprocess.run(["git", "-C", str(self.repo), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.repo), "commit", "-qm", "add quoted path"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "tag", "-f", m.RELEASE_TAG], check=True)
        self.tag_commit = subprocess.run(
            ["git", "-C", str(self.repo), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        self.upstream["records"][0]["upstream_paths"] = ["drivers/dräft.c"]
        report = self.inspect()
        self.assertEqual(report["records"][0]["ubuntu_source_paths_present"],
                         ["drivers/dräft.c"])

    def test_control_characters_and_backslashes_in_paths_are_rejected(self):
        for bad in ("drivers/a\nb.c", "drivers/a\\\\b.c", "drivers/a\x00b.c"):
            with self.subTest(path=bad), self.assertRaisesRegex(ValueError, "invalid upstream source path"):
                m.validate_upstream_path("CVE-2026-30000", bad)

    def test_same_basename_candidates_are_ranked_and_capped(self):
        for i in range(12):
            path = self.repo / "kernel" / "drivers" / f"sub{i}" / "missing.c"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture\\n")
        subprocess.run(["git", "-C", str(self.repo), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.repo), "commit", "-qm", "candidate paths"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "tag", "-f", m.RELEASE_TAG], check=True)
        self.tag_commit = subprocess.run(
            ["git", "-C", str(self.repo), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        self.upstream["records"][0]["upstream_paths"] = ["kernel/drivers/missing.c"]
        report = self.inspect()
        item = report["records"][0]["upstream_path_correspondence"][0]
        self.assertEqual(len(item["same_basename_candidates"]), m.MAX_BASENAME_CANDIDATES)
        self.assertEqual(item["same_basename_candidate_count"], 12)
        self.assertTrue(item["same_basename_candidates_truncated"])

    def test_partial_source_inventory_rejected(self):
        self.upstream["records"].pop()
        with self.assertRaisesRegex(ValueError, "missing/duplicate"):
            self.inspect()


if __name__ == "__main__":
    unittest.main()
