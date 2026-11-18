import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from github_identity_roles import (
    Classification, IdentityError, Role, resolve_actor, require_human_eligibility,
)


class IdentityRoleTests(unittest.TestCase):
    def test_commit_service_user_is_exclusion_evidence_only(self):
        evidence = resolve_actor({"type": "User", "id": 19864447},
                                 role=Role.COMMITTER, source="rest_exact_sha",
                                 exact_sha="a" * 40)
        self.assertEqual(evidence.user_id, 19864447)
        self.assertEqual(evidence.classification, Classification.USER)
        with self.assertRaises(IdentityError):
            require_human_eligibility(evidence, trusted_ids={19864447})

    def test_no_rest_fallback_for_reviewer_or_owner(self):
        for role in (Role.REVIEWER, Role.OWNER, Role.PR_AUTHOR, Role.WORKFLOW_INITIATOR):
            with self.subTest(role=role), self.assertRaises(IdentityError):
                resolve_actor({"type": "User", "id": 10}, role=role,
                              source="rest_exact_sha", exact_sha="a" * 40)

    def test_bad_actor_and_ids_fail_closed(self):
        for actor in (None, {}, {"type": "App", "id": 10},
                      {"type": "User", "id": True},
                      {"type": "User", "id": "10"},
                      {"type": "User", "id": 0}):
            with self.subTest(actor=actor), self.assertRaises(IdentityError):
                resolve_actor(actor, role=Role.COMMITTER, source="graphql")

    def test_bot_cannot_be_approved(self):
        evidence = resolve_actor({"type": "Bot", "id": 11},
                                 role=Role.REVIEWER, source="rest_reviews")
        with self.assertRaises(IdentityError):
            require_human_eligibility(evidence, trusted_ids={11})

    def test_user_type_alone_cannot_approve(self):
        evidence = resolve_actor({"type": "User", "id": 12},
                                 role=Role.REVIEWER, source="rest_reviews")
        with self.assertRaisesRegex(IdentityError, "human eligibility"):
            require_human_eligibility(evidence, trusted_ids={12})
