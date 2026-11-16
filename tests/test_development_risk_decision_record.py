"""Contract tests for the reusable DEV-10 development-risk decision record."""
import json
import re
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


class DevelopmentRiskDecisionRecordTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = json.loads(SCHEMA_PATH.read_text())
        cls.proposal = json.loads(PROPOSAL_PATH.read_text())

    def test_schema_and_proposal_are_v2_and_proposal_is_inactive(self):
        self.assertEqual(self.schema["properties"]["schema_version"]["const"], 2)
        self.assertEqual(self.proposal["schema_version"], 2)
        self.assertEqual(self.proposal["status"], "pending_independent_review")
        self.assertIsNone(self.proposal["prepared_by"])
        self.assertIsNone(self.proposal["prepared_by_id"])
        self.assertIsNone(self.proposal["approval_evidence"])
        self.assertNotIn("approval_id", self.proposal)
        self.assertNotIn("approved_at", self.proposal)
        self.assertNotIn("approved_by", self.proposal)
        self.assertNotIn("approved_by_id", self.proposal)

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
        self.assertEqual(set(decision), set(self.schema["properties"]))
        self.assertEqual(decision["schema_version"], 2)
        self.assertEqual(decision["status"], "approved")
        self.assertIsNone(decision["revoked_at"])
        self.assertEqual(decision["repository"], "baobab-platform/baobab-dev")
        self.assertEqual(decision["image_repository"], "ghcr.io/baobab-platform/baobab-dev")
        self.assertEqual(decision["environment"], "development")
        self.assertEqual(set(decision["profiles"]), {"final", "frontend", "frontend-e2e", "infra"})
        self.assertEqual(set(decision["architectures"]), {"linux/amd64", "linux/arm64"})
        self.assertEqual(decision["expires_at"], "2026-11-26T00:00:00Z")
        self.assertEqual(decision["finding_count"], 8)
        self.assertEqual({item["cve"] for item in decision["findings"]}, EXPECTED_CVES)
        for item in decision["findings"]:
            self.assertEqual(item["package"], "linux-libc-dev")
            self.assertEqual(item["version"], "7.0.0-43.43")
            self.assertEqual(item["severity"], "HIGH")
            self.assertEqual(item["type"], "ubuntu")
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
        self.assertIn("#62", decision["notes"])
        self.assertIn("#71", decision["notes"])
        self.assertIn("#74", decision["notes"])
        self.assertNotRegex(decision["notes"].lower(), r"authoriz(?:e|es|ed) (?:release|production)")


if __name__ == "__main__":
    unittest.main()
