"""Canonical OSV parsing is provenance-only and never emits a VEX disposition."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import audit_canonical_osv as audit


def sample(cve="CVE-2026-98869", binary_version="7.0.0-43.43"):
    return {
        "schema_version": "1.7.0",
        "id": f"UBUNTU-{cve}",
        "upstream": [cve],
        "published": "2026-10-21T15:17:00Z",
        "modified": "2026-11-17T14:57:09Z",
        "affected": [{
            "package": {
                "ecosystem": "Ubuntu:26.04:LTS",
                "name": "linux",
                "purl": "pkg:deb/ubuntu/linux@7.0.0-43.43?arch=source&distro=resolute",
            },
            "versions": ["7.0.0-43.43"],
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
            "ecosystem_specific": {"binaries": [{
                "binary_name": "linux-libc-dev",
                "binary_version": binary_version,
            }]},
        }],
    }


class CanonicalOSVEvidenceTests(unittest.TestCase):
    def write(self, root, cve, data):
        path = root / "osv/cve" / cve[4:8] / f"UBUNTU-{cve}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_pinned_record_digest_and_target_binary_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write(root, "CVE-2026-98869", sample())
            output = root / "evidence/canonical-osv.json"
            row = audit.extract_record(
                "CVE-2026-98869", root, "2026-11-18T12:00:00Z",
                output.parent / "canonical-osv-raw",
            )
            self.assertEqual(row["release_evidence"], "TARGET_BINARY_VERSION_LISTED_AS_AFFECTED")
            self.assertEqual(row["ubuntu_26_04_linux_source_entries"][0]["linux_libc_dev_binary_versions"],
                             ["7.0.0-43.43"])
            self.assertEqual(len(row["raw_sha256"]), 64)
            self.assertEqual(row["disposition"], "UNDER_INVESTIGATION_NO_VEX_NO_EXCEPTION")
            self.assertTrue((output.parent / "canonical-osv-raw" / "UBUNTU-CVE-2026-98869.json").exists())

    def test_source_version_does_not_imply_explicit_binary_listing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cve = "CVE-2026-98869"
            self.write(root, cve, sample(binary_version="7.0.0-42"))
            row = audit.extract_record(cve, root, "2026-11-18T12:00:00Z", root / "raw")
            self.assertEqual(row["release_evidence"], "SOURCE_VERSION_AFFECTED_BINARY_VERSION_UNLISTED")

    def test_absent_release_entry_is_an_evidence_gap_not_not_affected(self):
        data = sample()
        data["affected"] = []
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write(root, "CVE-2026-98869", data)
            row = audit.extract_record(
                "CVE-2026-98869", root, "2026-11-18T12:00:00Z", root / "raw"
            )
            self.assertEqual(row["release_evidence"], "NO_UBUNTU_26_04_LINUX_SOURCE_ENTRY")
            self.assertEqual(row["disposition"], "UNDER_INVESTIGATION_NO_VEX_NO_EXCEPTION")

    def test_identity_mismatch_fails_closed(self):
        data = sample()
        data["id"] = "UBUNTU-CVE-2026-00001"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write(root, "CVE-2026-98869", data)
            with self.assertRaisesRegex(ValueError, "identity/upstream"):
                audit.extract_record(
                    "CVE-2026-98869", root, "2026-11-18T12:00:00Z", root / "raw"
                )

    def test_checkout_must_match_locked_canonical_commit(self):
        class Git:
            returncode = 0
            stdout = "0" * 40 + "\n"
        with patch.object(audit.subprocess, "run", return_value=Git()):
            with self.assertRaisesRegex(ValueError, "Canonical OSV checkout"):
                audit.require_git_revision(Path("/tmp/fake"))


if __name__ == "__main__":
    unittest.main()
