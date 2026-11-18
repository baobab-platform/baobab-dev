"""Contract tests for the reusable DEV-10 development-risk decision record."""
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "security/decisions/development/foundation.schema.json"
PROPOSAL_PATH = ROOT / "security/decisions/development/foundation.proposal.json"
DECISION_PATH = ROOT / "security/decisions/development/foundation.json"

EXPECTED_CVES = {
    "CVE-2022-50240", "CVE-2025-40190", "CVE-2026-68103",
    "CVE-2026-72198", "CVE-2026-74578", "CVE-2026-89805",
    "CVE-2026-98376", "CVE-2026-98420",
}

EXPECTED_AMENDMENT_CVES = EXPECTED_CVES | {
    "CVE-2026-98869", "CVE-2026-98890", "CVE-2026-99083",
    "CVE-2026-112366",
}


class DevelopmentRiskDecisionRecordTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = json.loads(SCHEMA_PATH.read_text())
        cls.proposal = json.loads(PROPOSAL_PATH.read_text())

    def test_schema_and_proposal_are_v2_and_proposal_is_inactive(self):
        self.assertEqual(self.schema["properties"]["schema_version"]["const"], 2)
        self.assertEqual(self.proposal["schema_version"], 2)
        self.assertEqual(self.proposal["record_type"], "proposed_approved_form")
        self.assertEqual(self.proposal["status"], "pending_independent_review")
        self.assertIsNone(self.proposal["prepared_by"])
        self.assertIsNone(self.proposal["prepared_by_id"])
        self.assertIsNone(self.proposal["approval_evidence"])
        self.assertNotIn("approval_id", self.proposal)
        self.assertNotIn("approved_at", self.proposal)
        self.assertNotIn("approved_by", self.proposal)
        self.assertNotIn("approved_by_id", self.proposal)

    def test_proposal_covers_exact_twelve_findings_without_activating_them(self):
        proposal = self.proposal
        self.assertEqual(proposal["status"], "pending_independent_review")
        self.assertEqual(proposal["finding_count"], 12)
        self.assertEqual(len(proposal["findings"]), 12)
        self.assertEqual(
            {item["cve"] for item in proposal["findings"]},
            EXPECTED_AMENDMENT_CVES,
        )
        ubuntu = [item for item in proposal["findings"] if item["type"] == "ubuntu"]
        node = [item for item in proposal["findings"] if item["type"] == "node-pkg"]
        self.assertEqual(len(ubuntu), 11)
        self.assertEqual(len(node), 1)
        self.assertEqual(
            {(item["package"], item["version"]) for item in ubuntu},
            {("linux-libc-dev", "7.0.0-43.43")},
        )
        self.assertEqual(
            {(item["package"], item["version"]) for item in node},
            {("picomatch", "4.0.5")},
        )
        self.assertEqual(
            set(proposal["profiles"]),
            {"final", "frontend", "frontend-e2e", "infra"},
        )
        self.assertEqual(
            set(proposal["architectures"]),
            {"linux/amd64", "linux/arm64"},
        )
        self.assertEqual(proposal["expires_at"], "2026-11-26T00:00:00Z")
        self.assertEqual(proposal["evidence_lock_sha256"], "d0ea5dd7b2901d05d2504301f88db69f0c3fe46d52ac9465c51da2549eeab812")
        self.assertNotIn("44297169413", proposal["notes"])
        self.assertNotIn("14424421569", proposal["notes"])
        self.assertIsNone(proposal["prepared_by"])
        self.assertIsNone(proposal["prepared_by_id"])
        self.assertIsNone(proposal["approval_evidence"])
        self.assertNotIn("approval_id", proposal)
        self.assertNotIn("approved_at", proposal)
        self.assertNotIn("approved_by_id", proposal)

    def test_twelve_finding_schema_requires_evidence_lock_but_legacy_eight_does_not(self):
        condition = next(
            item for item in self.schema["allOf"]
            if item.get("if", {}).get("properties", {}).get("finding_count") == {"const": 12}
        )
        self.assertIn("evidence_lock_sha256", condition["then"]["required"])
        eight = {
            "schema_version": 2,
            "record_type": "proposed_approved_form",
            "status": "approved",
            "revoked_at": None,
            "repository": "baobab-platform/baobab-dev",
            "image_repository": "ghcr.io/baobab-platform/baobab-dev",
            "environment": "development",
            "execution_scope": {
                "pull_request_base": "main",
                "push_ref": "refs/heads/main",
                "pull_request_head_repository": "baobab-platform/baobab-dev",
            },
            "profiles": ["final", "frontend", "frontend-e2e", "infra"],
            "architectures": ["linux/amd64", "linux/arm64"],
            "prepared_by": "reviewed",
            "prepared_by_id": 1,
            "approval_evidence": "https://github.com/baobab-platform/baobab-dev/pull/1",
            "expires_at": "2026-11-26T00:00:00Z",
            "findings": [],
            "finding_count": 8,
            "notes": "legacy eight-finding record",
        }
        self.assertNotIn("evidence_lock_sha256", eight)

    def test_approved_schema_requires_numeric_preparer_identity(self):
        approved = self.schema["allOf"][0]["then"]["properties"]
        self.assertEqual(approved["prepared_by_id"]["type"], "integer")
        self.assertGreaterEqual(approved["prepared_by_id"]["minimum"], 1)
        self.assertEqual(approved["prepared_by"]["type"], "string")
        self.assertEqual(approved["approval_evidence"]["type"], "string")

    def test_final_decision_contract_when_separate_decision_pr_is_present(self):
        if not DECISION_PATH.exists():
            self.skipTest("The final record is introduced by the separate decision PR")
        decision = json.loads(DECISION_PATH.read_text())
        self.assertTrue(set(self.schema["required"]).issubset(decision))
        self.assertTrue(set(decision).issubset(self.schema["properties"]))
        self.assertEqual(decision["schema_version"], 2)
        self.assertEqual(decision["record_type"], "proposed_approved_form")
        self.assertEqual(decision["status"], "approved")
        self.assertIsNone(decision["revoked_at"])
        self.assertEqual(decision["repository"], "baobab-platform/baobab-dev")
        self.assertEqual(decision["image_repository"], "ghcr.io/baobab-platform/baobab-dev")
        self.assertEqual(decision["environment"], "development")
        self.assertEqual(set(decision["profiles"]), {"final", "frontend", "frontend-e2e", "infra"})
        self.assertEqual(set(decision["architectures"]), {"linux/amd64", "linux/arm64"})
        self.assertEqual(decision["expires_at"], "2026-11-26T00:00:00Z")
        self.assertEqual(decision["finding_count"], len(decision["findings"]))
        if decision["finding_count"] == 12:
            self.assertRegex(decision["evidence_lock_sha256"], r"^[a-f0-9]{64}$")
        else:
            self.assertNotIn("evidence_lock_sha256", decision)
        observed_cves = {item["cve"] for item in decision["findings"]}
        self.assertIn(decision["finding_count"], {8, 12})
        if decision["finding_count"] == 8:
            self.assertEqual(observed_cves, EXPECTED_CVES)
            self.assertTrue(all(item["type"] == "ubuntu" for item in decision["findings"]))
        else:
            self.assertEqual(observed_cves, EXPECTED_AMENDMENT_CVES)
            self.assertEqual(sum(item["type"] == "ubuntu" for item in decision["findings"]), 11)
            self.assertEqual(sum(item["type"] == "node-pkg" for item in decision["findings"]), 1)
        for item in decision["findings"]:
            self.assertEqual(item["severity"], "HIGH")
            if item["type"] == "ubuntu":
                self.assertEqual(item["package"], "linux-libc-dev")
                self.assertEqual(item["version"], "7.0.0-43.43")
            else:
                self.assertEqual(item["type"], "node-pkg")
                self.assertEqual(item["package"], "picomatch")
                self.assertEqual(item["version"], "4.0.5")
        self.assertIsInstance(decision["prepared_by_id"], int)
        self.assertGreater(decision["prepared_by_id"], 0)
        self.assertTrue(decision["prepared_by"].strip())
        self.assertRegex(
            decision["approval_evidence"],
            r"^https://github\.com/baobab-platform/baobab-dev/pull/[1-9][0-9]*$",
        )
        self.assertNotIn("approval_id", decision)
        self.assertNotIn("approved_at", decision)
        self.assertNotIn("approved_by", decision)
        self.assertNotIn("approved_by_id", decision)
        scope = decision["execution_scope"]
        self.assertEqual(scope, {
            "pull_request_base": "main",
            "push_ref": "refs/heads/main",
            "pull_request_head_repository": "baobab-platform/baobab-dev",
        })
        self.assertIn("#74", decision["notes"])
        self.assertNotRegex(decision["notes"].lower(), r"authoriz(?:e|es|ed) (?:release|production)")



@unittest.skipUnless(shutil.which("check-jsonschema"), "check-jsonschema is installed in the policy CI job")
class Draft202012SchemaValidationTests(unittest.TestCase):
    def validate(self, document):
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "candidate.json"
            candidate.write_text(json.dumps(document))
            return subprocess.run(
                [
                    "check-jsonschema",
                    "--schemafile",
                    str(SCHEMA_PATH),
                    str(candidate),
                ],
                capture_output=True,
                text=True,
                check=False,
            )

    def test_both_committed_records_validate_against_the_schema(self):
        for path in (PROPOSAL_PATH, DECISION_PATH):
            with self.subTest(path=path.name):
                result = subprocess.run(
                    [
                        "check-jsonschema",
                        "--schemafile",
                        str(SCHEMA_PATH),
                        str(path),
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_schema_rejects_extra_properties_invalid_date_and_identity_scope_or_count(self):
        original = json.loads(DECISION_PATH.read_text())
        mutations = {
            "extra property": lambda item: item.update({"unexpected": True}),
            "invalid date": lambda item: item.update({"revoked_at": "not-a-date"}),
            "invalid numeric identity": lambda item: item.update({"prepared_by_id": 0}),
            "widened execution scope": lambda item: item["execution_scope"].update({"pull_request_base": "release"}),
            "finding count mismatch": lambda item: item.update({"finding_count": 7}),
            "unsupported intermediate count": lambda item: item.update({"finding_count": 9}),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                candidate = json.loads(json.dumps(original))
                mutate(candidate)
                result = self.validate(candidate)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
