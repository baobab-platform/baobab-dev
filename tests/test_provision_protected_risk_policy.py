"""Regression tests for authenticated DEV-10 policy provisioning."""
import copy
import datetime as dt
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location(
    "dev10_policy_provisioner",
    ROOT / "scripts/provision_protected_risk_policy.py",
)
provisioner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(provisioner)

DECISION = provisioner.json.loads(
    (ROOT / "security/decisions/development/foundation.json").read_text()
)
NOW = dt.datetime(2026, 11, 17, tzinfo=dt.timezone.utc)
HEAD = "a" * 40
TRUSTED = {356890520: "sknabusiu"}
AUTHOR = 350241706


class DecisionContractTests(unittest.TestCase):
    def test_exact_candidate_record_is_accepted_for_provisioning(self):
        result = provisioner.validate_decision(
            copy.deepcopy(DECISION), decision_pr=76, now=NOW
        )
        self.assertEqual(result["status"], "approved")

    def test_rejects_nonapproved_revoked_or_wrong_record_type(self):
        mutations = (
            ("pending", lambda item: item.update(status="pending_independent_review")),
            ("revoked", lambda item: item.update(revoked_at="2026-11-17T00:00:00Z")),
            ("wrong type", lambda item: item.update(record_type="active")),
        )
        for label, mutate in mutations:
            with self.subTest(label=label):
                candidate = copy.deepcopy(DECISION)
                mutate(candidate)
                with self.assertRaises(provisioner.ProvisioningError):
                    provisioner.validate_decision(candidate, decision_pr=76, now=NOW)

    def test_rejects_widened_scope_and_inventory(self):
        mutations = (
            ("extra field", lambda item: item.update(unexpected=True)),
            ("wrong repository", lambda item: item.update(repository="other/repo")),
            ("release environment", lambda item: item.update(environment="production")),
            ("wrong PR evidence", lambda item: item.update(
                approval_evidence="https://github.com/baobab-platform/baobab-dev/pull/75"
            )),
            ("wrong profile", lambda item: item["profiles"].append("release")),
            ("wrong architecture", lambda item: item["architectures"].append("linux/s390x")),
            ("wrong expiry", lambda item: item.update(expires_at="2026-12-01T00:00:00Z")),
            ("finding count", lambda item: item.update(finding_count=7)),
            ("new CVE", lambda item: item["findings"][0].update(cve="CVE-2099-00001")),
            ("fixed version signal inventory mutation", lambda item: item["findings"][0].update(
                version="7.0.0-44.44"
            )),
            ("duplicate finding", lambda item: item["findings"].__setitem__(1, item["findings"][0])),
            ("preparer identity", lambda item: item.update(prepared_by_id=0)),
        )
        for label, mutate in mutations:
            with self.subTest(label=label):
                candidate = copy.deepcopy(DECISION)
                mutate(candidate)
                with self.assertRaises(provisioner.ProvisioningError):
                    provisioner.validate_decision(candidate, decision_pr=76, now=NOW)

    def test_rejects_expired_decision(self):
        with self.assertRaisesRegex(provisioner.ProvisioningError, "expired"):
            provisioner.validate_decision(
                copy.deepcopy(DECISION),
                decision_pr=76,
                now=dt.datetime(2026, 11, 27, tzinfo=dt.timezone.utc),
            )


class OwnerConcurrenceTests(unittest.TestCase):
    def test_requires_attributable_owner_comment_on_the_decision_pr(self):
        comments = [{
            "id": 6924572973,
            "user": {"id": 49340314, "login": "bjnabs"},
            "body": "@wekhason, I acknowledge this new reusable policy, and owner concurrence is hereby recorded.",
            "created_at": "2026-11-16T14:00:00Z",
            "updated_at": "2026-11-16T14:00:00Z",
        }]
        self.assertEqual(
            provisioner.verify_owner_concurrence(
                comments, merged_at="2026-11-17T02:00:00Z"
            ),
            {
                "owner_id": 49340314,
                "owner_comment_id": 6924572973,
                "owner_concurrence_at": "2026-11-16T14:00:00Z",
            },
        )

    def test_rejects_owner_concurrence_created_or_edited_after_merge(self):
        for updated_at in ("2026-11-18T00:00:00Z", "2026-11-16T13:00:00Z"):
            comments = [{
                "id": 6924572973,
                "user": {"id": 49340314},
                "body": "new reusable policy; owner concurrence is hereby recorded",
                "created_at": "2026-11-16T14:00:00Z",
                "updated_at": updated_at,
            }]
            with self.subTest(updated_at=updated_at), self.assertRaises(provisioner.ProvisioningError):
                provisioner.verify_owner_concurrence(
                    comments, merged_at="2026-11-17T02:00:00Z"
                )


    def test_rejects_other_author_or_nonconcurrence_comment(self):
        cases = (
            [{"id": 1, "user": {"id": 350241706},
              "body": "owner concurrence is hereby recorded for the new reusable policy"}],
            [{"id": 2, "user": {"id": 49340314},
              "body": "I acknowledge the new reusable policy"}],
            [],
        )
        for comments in cases:
            with self.subTest(comments=comments), self.assertRaises(provisioner.ProvisioningError):
                provisioner.verify_owner_concurrence(
                    comments, merged_at="2026-11-17T02:00:00Z"
                )


class IndependentApprovalTests(unittest.TestCase):
    @staticmethod
    def review(review_id, state, submitted_at, commit_id=HEAD, reviewer_id=356890520):
        return {
            "id": review_id,
            "state": state,
            "submitted_at": submitted_at,
            "commit_id": commit_id,
            "user": {"id": reviewer_id, "login": "sknabusiu"},
        }

    def select(self, reviews, contributors=None, trusted=None):
        return provisioner.select_independent_approval(
            reviews,
            head=HEAD,
            trusted_reviewers=trusted or TRUSTED,
            author_id=AUTHOR,
            contributors=set() if contributors is None else contributors,
        )

    def test_accepts_latest_trusted_independent_exact_head_approval(self):
        result = self.select([
            self.review(10, "COMMENTED", "2026-11-16T10:00:00Z"),
            self.review(11, "APPROVED", "2026-11-17T01:29:41Z"),
        ])
        self.assertEqual(result["approval_id"], "github-review-11")
        self.assertEqual(result["approved_by_id"], 356890520)
        self.assertEqual(result["owner_id"], 49340314)
        self.assertEqual(result["owner_comment_id"], 6924572973)
        self.assertEqual(result["owner_concurrence_at"], "2026-11-16T14:00:00Z")

    def test_later_comment_changes_requested_or_dismissal_invalidates_approval(self):
        for state in ("COMMENTED", "CHANGES_REQUESTED", "DISMISSED"):
            with self.subTest(state=state), self.assertRaises(provisioner.ProvisioningError):
                self.select([
                    self.review(10, "APPROVED", "2026-11-16T10:00:00Z"),
                    self.review(11, state, "2026-11-17T01:30:00Z"),
                ])

    def test_rejects_stale_head_untrusted_reviewer_and_contributor(self):
        cases = (
            ("stale head", [self.review(10, "APPROVED", "2026-11-17T01:00:00Z", "b" * 40)], None, TRUSTED),
            ("untrusted", [self.review(10, "APPROVED", "2026-11-17T01:00:00Z")], None, {999: "other"}),
            ("reviewer contributed", [self.review(10, "APPROVED", "2026-11-17T01:00:00Z")], {356890520}, TRUSTED),
            ("author self approval", [self.review(10, "APPROVED", "2026-11-17T01:00:00Z", reviewer_id=AUTHOR)], None, {AUTHOR: "wekhason"}),
        )
        for label, reviews, contributors, trusted in cases:
            with self.subTest(label=label), self.assertRaises(provisioner.ProvisioningError):
                self.select(reviews, contributors=contributors, trusted=trusted)

    def test_rejects_unresolved_identity_unknown_state_and_naive_timestamp(self):
        malformed = [
            {"id": 1, "state": "APPROVED", "submitted_at": "2026-11-17T01:00:00Z",
             "commit_id": HEAD, "user": {"id": None}},
            self.review(2, "PENDING_REVIEW", "2026-11-17T01:00:00Z"),
            self.review(3, "APPROVED", "2026-11-17T01:00:00"),
        ]
        for review in malformed:
            with self.subTest(review=review), self.assertRaises(provisioner.ProvisioningError):
                self.select([review])


class MergedCustodyTests(unittest.TestCase):
    def setUp(self):
        self.raw = provisioner.json.dumps(DECISION, separators=(",", ":")).encode()
        self.encoded = provisioner.base64.b64encode(self.raw).decode()
        self.merge_sha = "b" * 40
        self.pull = {
            "state": "closed",
            "merged": True,
            "merged_at": "2026-11-17T02:00:00Z",
            "base": {"ref": "main", "repo": {"full_name": provisioner.REPOSITORY}},
            "head": {"sha": HEAD, "repo": {"full_name": provisioner.REPOSITORY}},
            "merge_commit_sha": self.merge_sha,
            "user": {"id": AUTHOR, "login": "wekhason"},
        }
        self.files = [{"filename": provisioner.DECISION_PATH, "status": "added"}]
        self.content = {"type": "file", "encoding": "base64", "content": self.encoded}
        self.comparison = {
            "status": "ahead",
            "merge_base_commit": {"sha": self.merge_sha},
        }
        self.comments = [{
            "id": 6924572973,
            "user": {"id": 49340314, "login": "bjnabs"},
            "body": "I acknowledge this new reusable policy, and owner concurrence is hereby recorded.",
            "created_at": "2026-11-16T14:00:00Z",
            "updated_at": "2026-11-16T14:00:00Z",
        }]
        self.reviews = [{
            "id": 99,
            "state": "APPROVED",
            "submitted_at": "2026-11-17T01:29:41Z",
            "commit_id": HEAD,
            "user": {"id": 356890520, "login": "sknabusiu"},
        }]

    def api_sequence(self, main_content=None, reviews=None, comments=None):
        return [
            (200, self.pull),
            (200, self.files),
            (200, self.content),
            (200, self.content),
            (200, self.content if main_content is None else main_content),
            (200, self.comparison),
            (200, self.comments if comments is None else comments),
            (200, self.reviews if reviews is None else reviews),
        ]

    def verify(self, api_sequence=None, contributors=None, expected_head=HEAD):
        with patch.object(provisioner, "api_request", side_effect=api_sequence or self.api_sequence()), \
             patch.object(provisioner, "collect_pr", return_value=(
                 AUTHOR, set() if contributors is None else contributors
             )):
            return provisioner.verify_merged_custody(
                "token", DECISION, 76, expected_head, TRUSTED
            )

    def test_verifies_merged_head_review_contributors_and_merge_ancestry(self):
        result = self.verify()
        self.assertEqual(result["decision_pr_head"], HEAD)
        self.assertEqual(result["merge_commit_sha"], self.merge_sha)
        self.assertEqual(result["approval_id"], "github-review-99")
        self.assertEqual(result["approved_by_id"], 356890520)

    def test_rejects_unmerged_pr_and_wrong_approved_head(self):
        unmerged = dict(self.pull, merged=False)
        with self.assertRaisesRegex(provisioner.ProvisioningError, "must be merged"):
            self.verify(api_sequence=[(200, unmerged)])
        with self.assertRaisesRegex(provisioner.ProvisioningError, "expected head"):
            self.verify(expected_head="c" * 40)

    def test_rejects_main_bytes_different_from_reviewed_pr_bytes(self):
        changed = {
            "type": "file", "encoding": "base64",
            "content": provisioner.base64.b64encode(self.raw + b" ").decode(),
        }
        with self.assertRaisesRegex(provisioner.ProvisioningError, "bytes differ"):
            self.verify(api_sequence=self.api_sequence(main_content=changed))

    def test_contents_decoder_accepts_API_base64_line_wrapping(self):
        wrapped = self.encoded[:20] + "\n" + self.encoded[20:]
        payload = {"type": "file", "encoding": "base64", "content": wrapped}
        with patch.object(provisioner, "api_request", return_value=(200, payload)):
            self.assertEqual(
                provisioner.contents_bytes("token", provisioner.DECISION_PATH, HEAD),
                self.raw,
            )

    def test_rejects_merge_commit_bytes_different_from_reviewed_head(self):
        changed = {
            "type": "file", "encoding": "base64",
            "content": provisioner.base64.b64encode(self.raw + b" ").decode(),
        }
        sequence = self.api_sequence()
        sequence[3] = (200, changed)
        with self.assertRaisesRegex(provisioner.ProvisioningError, "merge-commit"):
            self.verify(api_sequence=sequence)

    def test_rejects_nonancestor_merge_commit(self):
        comparison = {"status": "ahead", "merge_base_commit": {"sha": "c" * 40}}
        sequence = self.api_sequence()
        sequence[5] = (200, comparison)
        with self.assertRaisesRegex(provisioner.ProvisioningError, "not an ancestor"):
            self.verify(api_sequence=sequence)

    def test_rejects_stale_approval_or_reviewer_contributor(self):
        stale_reviews = [dict(self.reviews[0], commit_id="c" * 40)]
        with self.assertRaisesRegex(provisioner.ProvisioningError, "no current-head"):
            self.verify(api_sequence=self.api_sequence(reviews=stale_reviews))
        with self.assertRaisesRegex(provisioner.ProvisioningError, "no current-head"):
            self.verify(contributors={356890520})

    def test_rejects_missing_owner_concurrence_and_uses_numeric_preparer_identity(self):
        no_owner = self.api_sequence(comments=[])
        with self.assertRaisesRegex(provisioner.ProvisioningError, "owner concurrence"):
            self.verify(api_sequence=no_owner)
        renamed_login = dict(self.pull, user={"id": AUTHOR, "login": "renamed-wekhason"})
        sequence = self.api_sequence()
        sequence[0] = (200, renamed_login)
        result = self.verify(api_sequence=sequence)
        self.assertEqual(result["approved_by_id"], 356890520)


class RepositoryVariableTests(unittest.TestCase):
    HASH = "a" * 64

    def test_same_existing_hash_is_idempotent(self):
        with patch.object(provisioner, "api_request", return_value=(200, {"value": self.HASH})) as api:
            self.assertEqual(provisioner.provision_variable("token", self.HASH), "already_provisioned")
            api.assert_called_once()

    def test_different_existing_hash_is_never_overwritten(self):
        with patch.object(provisioner, "api_request", return_value=(200, {"value": "b" * 64})) as api:
            with self.assertRaisesRegex(provisioner.ProvisioningError, "refusing overwrite"):
                provisioner.provision_variable("token", self.HASH)
            api.assert_called_once()

    def test_missing_hash_is_created_and_read_back(self):
        with patch.object(provisioner, "api_request", side_effect=[
            (404, None), (201, {"name": provisioner.VARIABLE_NAME}),
            (200, {"value": self.HASH}),
        ]) as api:
            self.assertEqual(provisioner.provision_variable("token", self.HASH), "provisioned")
            self.assertEqual(api.call_count, 3)

    def test_create_race_is_accepted_only_when_exact_hash_won(self):
        with patch.object(provisioner, "api_request", side_effect=[
            (404, None), (422, None), (200, {"value": self.HASH}),
        ]):
            self.assertEqual(provisioner.provision_variable("token", self.HASH), "already_provisioned")
        with patch.object(provisioner, "api_request", side_effect=[
            (404, None), (422, None), (200, {"value": "b" * 64}),
        ]):
            with self.assertRaises(provisioner.ProvisioningError):
                provisioner.provision_variable("token", self.HASH)


if __name__ == "__main__":
    unittest.main()
