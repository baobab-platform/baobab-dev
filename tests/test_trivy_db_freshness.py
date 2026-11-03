"""Fail-closed verification of Trivy vulnerability/Java DB provenance."""
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from verify_trivy_db_freshness import InvalidDatabase, qualify  # noqa: E402


class TrivyDBFreshnessTest(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        self.now = datetime(2026, 11, 3, 9, 0, tzinfo=timezone.utc)
        for name in ("db", "java-db"):
            (self.root / name).mkdir()
            self.write(name)

    def write(self, name, *, updated_hours=1, next_hours=4, downloaded_hours=1,
              version=2, omit=None):
        doc = {"Version": version,
               "UpdatedAt": (self.now - timedelta(hours=updated_hours)).isoformat(),
               "NextUpdate": (self.now + timedelta(hours=next_hours)).isoformat(),
               "DownloadedAt": (self.now - timedelta(hours=downloaded_hours)).isoformat()}
        if omit:
            del doc[omit]
        (self.root / name / "metadata.json").write_text(json.dumps(doc))

    def test_valid_both_databases(self):
        evidence = qualify(self.root, now=self.now)
        self.assertEqual(set(evidence["databases"]), {"db", "java-db"})
        for value in evidence["databases"].values():
            self.assertEqual(len(value["metadata_sha256"]), 64)

    def test_missing_java_db_denied(self):
        (self.root / "java-db" / "metadata.json").unlink()
        with self.assertRaises(InvalidDatabase):
            qualify(self.root, now=self.now)

    def test_stale_vulnerability_db_denied(self):
        self.write("db", updated_hours=37)
        with self.assertRaisesRegex(InvalidDatabase, "stale"):
            qualify(self.root, now=self.now)

    def test_stale_java_db_denied(self):
        self.write("java-db", updated_hours=73)
        with self.assertRaisesRegex(InvalidDatabase, "stale"):
            qualify(self.root, now=self.now)

    def test_expired_next_update_denied(self):
        self.write("db", next_hours=-1)
        with self.assertRaisesRegex(InvalidDatabase, "NextUpdate expired"):
            qualify(self.root, now=self.now)

    def test_missing_field_denied(self):
        self.write("db", omit="DownloadedAt")
        with self.assertRaises(InvalidDatabase):
            qualify(self.root, now=self.now)

    def test_far_future_denied(self):
        self.write("db", next_hours=200)
        with self.assertRaises(InvalidDatabase):
            qualify(self.root, now=self.now)

    def test_malformed_json_denied(self):
        (self.root / "java-db" / "metadata.json").write_text("{not-json")
        with self.assertRaises(InvalidDatabase):
            qualify(self.root, now=self.now)

    def test_future_update_denied(self):
        self.write("db", updated_hours=-3)
        with self.assertRaises(InvalidDatabase):
            qualify(self.root, now=self.now)


if __name__ == "__main__":
    unittest.main()
