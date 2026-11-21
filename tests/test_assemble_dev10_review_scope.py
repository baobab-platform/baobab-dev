"""Review-scope assembly: exact eight-CVE ceiling and fail-closed evidence."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from assemble_dev10_review_scope import assemble
from evaluate_protected_risk_decision import ARCHES, PROFILES, DecisionDenied

CVES = [f"CVE-2026-{10000+i}" for i in range(8)]
DIGEST = "sha256:" + "a"*64

class AssemblyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.entries = []
        for i, (profile, arch) in enumerate(
            (p,a) for p in sorted(PROFILES) for a in sorted(ARCHES)):
            report = {
                "SchemaVersion": 2, "ArtifactType": "container_image",
                "Trivy": {"Version": "0.73.0"},
                "Metadata": {
                    "RepoDigests": [f"ghcr.io/baobab-platform/baobab-dev@{DIGEST}"],
                    "ImageConfig": {"os":"linux", "architecture":arch.split("/")[1]},
                },
                "Results": [{
                    "Target":"os", "Type":"ubuntu",
                    "Vulnerabilities":[{
                        "VulnerabilityID":c, "PkgName":"linux-libc-dev",
                        "InstalledVersion":"7.0.0-43.43", "Severity":"HIGH",
                    } for c in CVES],
                }],
            }
            filename = Path(self.tmp.name)/f"{i}.json"
            filename.write_text(json.dumps(report))
            self.entries.append({
                "profile":profile, "architecture":arch, "digest":DIGEST,
                "report":str(filename), "database_evidence":"db-sha256-test",
                "captured_at":"2026-11-16T09:00:00Z",
            })

    def test_complete_eight_matrix_stays_pending(self):
        out = assemble(self.entries)
        self.assertEqual(out["status"], "pending_independent_review")
        self.assertIsNone(out["approved_by"])
        self.assertEqual(len(out["findings"]), 8)
        self.assertEqual(len(out["exact_digest_evidence"]), 8)
        self.assertFalse(out["release_authorized"])

    def test_missing_or_duplicate_matrix_refused(self):
        for entries in (self.entries[:-1], self.entries[:-1]+[self.entries[0]]):
            with self.assertRaises(DecisionDenied):
                assemble(entries)

    def test_digest_mismatch_refused(self):
        self.entries[0]["digest"] = "sha256:"+"b"*64
        with self.assertRaises(DecisionDenied):
            assemble(self.entries)

    def test_missing_database_provenance_refused(self):
        self.entries[0]["database_evidence"] = None
        with self.assertRaises(DecisionDenied):
            assemble(self.entries)

    def test_new_cve_or_fixed_version_refused(self):
        path = Path(self.entries[0]["report"])
        report = json.loads(path.read_text())
        report["Results"][0]["Vulnerabilities"].append({
            "VulnerabilityID":"CVE-2026-99999",
            "PkgName":"linux-libc-dev", "InstalledVersion":"7.0.0-43.43",
            "Severity":"HIGH",
        })
        path.write_text(json.dumps(report))
        with self.assertRaises(DecisionDenied):
            assemble(self.entries)
        report["Results"][0]["Vulnerabilities"].pop()
        report["Results"][0]["Vulnerabilities"][0]["FixedVersion"]="7.0.0-44"
        path.write_text(json.dumps(report))
        with self.assertRaises(DecisionDenied):
            assemble(self.entries)

    def test_secret_finding_refused(self):
        path = Path(self.entries[0]["report"])
        report = json.loads(path.read_text())
        report["Results"][0]["Secrets"]=[{"RuleID":"sensitive"}]
        path.write_text(json.dumps(report))
        with self.assertRaises(DecisionDenied):
            assemble(self.entries)

if __name__ == "__main__":
    unittest.main()
