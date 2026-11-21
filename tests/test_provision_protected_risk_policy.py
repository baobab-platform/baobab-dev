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


class GraphQLCustodyDiagnosticsTests(unittest.TestCase):
    def test_graphql_errors_include_bounded_safe_message_type_and_path(self):
        from custody_independence import CustodyError, _graphql
        response = {"errors": [{
            "message": "Resource not accessible by integration",
            "type": "FORBIDDEN",
            "path": ["repository", "pullRequest", "github_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"],
            "extensions": {"secret": "must-not-appear"},
        }]}
        with patch("github_api_transport._OPENER.open") as urlopen:
            urlopen.return_value.__enter__.return_value.read.return_value = (
                provisioner.json.dumps(response).encode()
            )
            with self.assertRaises(CustodyError) as caught:
                _graphql("not-a-real-token", "query { viewer { login } }", {})
        message = str(caught.exception)
        self.assertIn("Resource not accessible by integration", message)
        self.assertIn("FORBIDDEN", message)
        self.assertIn("repository.pullRequest", message)
        self.assertNotIn("github_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ", message)
        self.assertNotIn("must-not-appear", message)
        self.assertNotIn("not-a-real-token", message)

    def test_http_error_reports_status_and_github_message_not_raw_body(self):
        import io
        from custody_independence import CustodyError, _graphql
        body = provisioner.json.dumps({
            "message": "Resource not accessible by integration",
            "documentation_url": "https://example.invalid/private",
        }).encode()
        error = provisioner.urllib.error.HTTPError(
            "https://api.github.com/graphql", 403, "Forbidden", {}, io.BytesIO(body)
        )
        with patch("github_api_transport._OPENER.open", side_effect=error):
            with self.assertRaises(CustodyError) as caught:
                _graphql("not-a-real-token", "query { viewer { login } }", {})
        self.assertIn("HTTP 403", str(caught.exception))
        self.assertIn("Resource not accessible by integration", str(caught.exception))
        self.assertNotIn("documentation_url", str(caught.exception))
        self.assertNotIn("not-a-real-token", str(caught.exception))

    def test_sanitizer_redacts_github_token_formats(self):
        from custody_independence import _safe_detail
        bearer_value = "sample" + "credential" + "value"
        detail = _safe_detail(
            "Bearer " + bearer_value + " github_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        )
        self.assertNotIn(bearer_value, detail)
        self.assertNotIn("github_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", detail)
        self.assertIn("[REDACTED]", detail)
        self.assertIn("[REDACTED_GITHUB_TOKEN]", detail)

    def test_provisioner_error_handler_reports_original_error(self):
        import contextlib
        import io
        import os
        argv = ["provisioner", "--expected-head-sha", "a" * 40]
        stderr = io.StringIO()
        with patch.object(provisioner.sys, "argv", argv), \
             patch.dict(os.environ, {"GH_TOKEN": "test-token", "GITHUB_REF": "refs/heads/main", "GITHUB_REPOSITORY": "baobab-platform/baobab-dev"}), \
             patch.object(provisioner.Path, "read_bytes", side_effect=OSError("simulated file read failure")), \
             contextlib.redirect_stderr(stderr):
            result = provisioner.main()
        self.assertEqual(result, 2)
        self.assertIn("simulated file read failure", stderr.getvalue())
        self.assertNotIn("NameError", stderr.getvalue())

    def test_graphql_timeout_fails_closed_with_specific_diagnostic(self):
        from custody_independence import CustodyError, _graphql
        with patch("github_api_transport._OPENER.open", side_effect=TimeoutError()):
            with self.assertRaisesRegex(CustodyError, "timed out"):
                _graphql("token", "query { viewer { login } }", {})

    def test_graphql_invalid_json_fails_closed_without_echoing_body(self):
        from custody_independence import CustodyError, _graphql
        with patch("github_api_transport._OPENER.open") as urlopen:
            urlopen.return_value.__enter__.return_value.read.return_value = b"not-json-secret"
            with self.assertRaises(CustodyError) as caught:
                _graphql("token", "query { viewer { login } }", {})
        self.assertIn("invalid JSON", str(caught.exception))
        self.assertNotIn("not-json-secret", str(caught.exception))

    def test_http_malformed_body_reports_status_without_echoing_body(self):
        import io
        from custody_independence import CustodyError, _graphql
        error = provisioner.urllib.error.HTTPError(
            "https://api.github.com/graphql", 502, "Bad Gateway", {},
            io.BytesIO(b"upstream-secret-body"),
        )
        with patch("github_api_transport._OPENER.open", side_effect=error):
            with self.assertRaises(CustodyError) as caught:
                _graphql("token", "query { viewer { login } }", {})
        self.assertIn("HTTP 502", str(caught.exception))
        self.assertNotIn("upstream-secret-body", str(caught.exception))

    def test_graphql_secret_bearing_error_fields_are_redacted(self):
        from custody_independence import CustodyError, _graphql
        response = {"errors": [{
            "message": "authorization: supersecret github_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            "type": "token=anothersecret",
            "path": ["repository", {"secret": "must-not-appear"}],
            "extensions": {"secret": "must-not-appear"},
        }]}
        with patch("github_api_transport._OPENER.open") as urlopen:
            urlopen.return_value.__enter__.return_value.read.return_value = (
                provisioner.json.dumps(response).encode()
            )
            with self.assertRaises(CustodyError) as caught:
                _graphql("not-a-real-token", "query { viewer { login } }", {})
        message = str(caught.exception)
        self.assertIn("repository", message)
        self.assertNotIn("supersecret", message)
        self.assertNotIn("anothersecret", message)
        self.assertNotIn("github_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ", message)
        self.assertNotIn("must-not-appear", message)

    def test_graphql_error_path_is_bounded_and_ignores_non_scalar_components(self):
        from custody_independence import _graphql_error_summary
        path = ["x" * 100 for _ in range(8)] + [{"secret": "never-render"}]
        message = _graphql_error_summary([{"message": "bad query", "path": path}])
        self.assertLessEqual(len(message), 520)
        self.assertNotIn("never-render", message)

    def test_malformed_graphql_error_shape_fails_closed_with_diagnostic(self):
        from custody_independence import CustodyError, _graphql
        with patch("github_api_transport._OPENER.open") as urlopen:
            urlopen.return_value.__enter__.return_value.read.return_value = b'{"errors":{}}'
            with self.assertRaisesRegex(CustodyError, "invalid errors field"):
                _graphql("token", "query { viewer { login } }", {})


    def test_unknown_github_error_messages_are_not_echoed(self):
        from custody_independence import _graphql_error_summary
        message = _graphql_error_summary([{
            "message": "authorization=runtime-secret-should-never-appear",
            "type": "UNRECOGNIZED_SECRET_TYPE",
            "path": ["repository", "token=runtime-secret"],
        }])
        self.assertIn("unrecognized GitHub error", message)
        self.assertIn("repository", message)
        self.assertNotIn("runtime-secret", message)
        self.assertNotIn("UNRECOGNIZED_SECRET_TYPE", message)
        self.assertNotIn("token=", message)


class DecisionContractTests(unittest.TestCase):
    def test_exact_candidate_record_is_accepted_for_provisioning(self):
        result = provisioner.validate_decision(
            copy.deepcopy(DECISION), decision_pr=92, now=NOW
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
                    provisioner.validate_decision(candidate, decision_pr=92, now=NOW)

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
                version="7.0.0-43.43"
            )),
            ("duplicate finding", lambda item: item["findings"].__setitem__(1, item["findings"][0])),
            ("preparer identity", lambda item: item.update(prepared_by_id=0)),
        )
        for label, mutate in mutations:
            with self.subTest(label=label):
                candidate = copy.deepcopy(DECISION)
                mutate(candidate)
                with self.assertRaises(provisioner.ProvisioningError):
                    provisioner.validate_decision(candidate, decision_pr=92, now=NOW)

    def test_rejects_expired_decision(self):
        with self.assertRaisesRegex(provisioner.ProvisioningError, "expired"):
            provisioner.validate_decision(
                copy.deepcopy(DECISION),
                decision_pr=92,
                now=dt.datetime(2026, 11, 27, tzinfo=dt.timezone.utc),
            )


class OwnerConcurrenceTests(unittest.TestCase):
    def test_requires_attributable_owner_comment_on_the_decision_pr(self):
        comments = [{
            "id": 7063076588,
            "user": {"id": 350241706, "login": "wekhason"},
            "body": "I accept, on a temporary development-only basis, the exact 30-finding inventory; accountable-owner concurrence.",
            "created_at": "2026-11-21T09:00:00Z",
            "updated_at": "2026-11-21T09:00:00Z",
        }]
        self.assertEqual(
            provisioner.verify_owner_concurrence(
                comments, merged_at="2026-11-22T02:00:00Z"
            ),
            {
                "owner_id": 350241706,
                "owner_comment_id": 7063076588,
                "owner_concurrence_at": "2026-11-21T13:10:21Z",
            },
        )

    def test_rejects_owner_concurrence_created_or_edited_after_merge(self):
        for updated_at in ("2026-11-23T00:00:00Z", "2026-11-21T08:00:00Z"):
            comments = [{
                "id": 7063076588,
                "user": {"id": 350241706},
                "body": "exact 30-finding inventory; accountable-owner concurrence",
                "created_at": "2026-11-21T09:00:00Z",
                "updated_at": updated_at,
            }]
            with self.subTest(updated_at=updated_at), self.assertRaises(provisioner.ProvisioningError):
                provisioner.verify_owner_concurrence(
                    comments, merged_at="2026-11-22T02:00:00Z"
                )


    def test_rejects_other_author_or_nonconcurrence_comment(self):
        cases = (
            [{"id": 1, "user": {"id": 49340314},
              "body": "owner concurrence is hereby recorded for the new reusable policy"}],
            [{"id": 2, "user": {"id": 350241706},
              "body": "I acknowledge the new reusable policy"}],
            [],
        )
        for comments in cases:
            with self.subTest(comments=comments), self.assertRaises(provisioner.ProvisioningError):
                provisioner.verify_owner_concurrence(
                    comments, merged_at="2026-11-22T02:00:00Z"
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
        self.assertEqual(result["reviewer"], "sknabusiu")
        self.assertEqual(result["approved_at"], "2026-11-17T01:29:41Z")

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
            "merged_at": "2026-11-22T02:00:00Z",
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
            "id": 7063076588,
            "user": {"id": 350241706, "login": "wekhason"},
            "body": "I accept, on a temporary development-only basis, the exact 30-finding inventory; accountable-owner concurrence.",
            "created_at": "2026-11-21T09:00:00Z",
            "updated_at": "2026-11-21T09:00:00Z",
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
                "token", DECISION, 92, expected_head, TRUSTED
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


class ImageScanScopeTests(unittest.TestCase):
    def test_custodian_scripts_are_not_misclassified_as_image_build_inputs(self):
        workflow = (ROOT / ".github/workflows/foundation.yml").read_text()
        publish = (ROOT / ".github/workflows/publish.yml").read_text()
        dockerfile = (ROOT / ".devcontainer/docker/Dockerfile").read_text()
        broad_scripts_match = workflow.index("scripts/*|.baobab/repository.yaml")
        for path in (
            "scripts/provision_protected_risk_policy.py",
            "scripts/custody_independence.py",
            "scripts/github_api_transport.py",
        ):
            self.assertLess(workflow.index(path), broad_scripts_match)
            self.assertIn('!'+path, publish)
            self.assertNotIn(path, dockerfile)
        self.assertIn("scripts/bootstrap.sh", dockerfile)
        self.assertIn("scripts/verify.sh", dockerfile)


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


class ProvisioningWorkflowSecurityTests(unittest.TestCase):
    def test_write_credential_is_isolated_from_human_approval_environment(self):
        workflow = (ROOT / ".github/workflows/provision-dev10-risk-policy.yml").read_text()
        authorize, provision = workflow.split("  provision:", 1)
        self.assertIn("environment: dev10-security-policy-read", authorize)
        self.assertNotIn("DEV10_POLICY_PROVISIONER_TOKEN", authorize)
        self.assertIn("needs: authorize", provision)
        self.assertIn("environment: dev10-security-policy-provision", provision)
        self.assertIn("GH_TOKEN: $" + "{{ secrets.DEV10_POLICY_PROVISIONER_TOKEN }}", provision)
        self.assertIn("github.ref == 'refs/heads/main'", provision)
        self.assertNotIn("actions: write", workflow)


class TransportHardeningTests(unittest.TestCase):
    def test_sanitizer_redacts_basic_json_credentials_urls_and_jwts(self):
        import base64
        from custody_independence import _safe_detail
        basic = base64.b64encode(b"user:pw").decode()
        token_value = "alpha" + "bravo" + "charlie" + "1234567890"
        password_value = "pass" + "phrase" + "1234567890"
        github_token = "gh" + "p_" + ("A" * 40)
        jwt_header = base64.urlsafe_b64encode(b'{"alg":"HS256"}').decode().rstrip("=")
        jwt_payload = base64.urlsafe_b64encode(b'{"sub":"user"}').decode().rstrip("=")
        jwt = jwt_header + "." + jwt_payload + "." + ("S" * 24)
        userinfo = "alice" + ":" + "pw" + "@"
        hostile = (
            "Authorization: Basic " + basic + " "
            + provisioner.json.dumps({"token": token_value, "password": password_value}) + " "
            + "X_TOKEN_" + github_token + " "
            + "https://" + userinfo + "example.invalid/path " + jwt
        )
        safe = _safe_detail(hostile)
        for secret in (basic, token_value, password_value, github_token, userinfo, jwt_header):
            self.assertNotIn(secret, safe)
        self.assertIn("[REDACTED_JWT]", safe)

    def test_sanitizer_removes_ansi_nul_and_bidi_controls_and_command_prefix(self):
        from custody_independence import _safe_detail
        safe = _safe_detail("::error::bad\x1b[31m\x00\u202equery")
        self.assertNotIn("\x1b", safe)
        self.assertNotIn("\x00", safe)
        self.assertNotIn("\u202e", safe)
        self.assertFalse(safe.startswith("::"))

    def test_github_transport_rejects_cross_origin_redirect(self):
        import urllib.error
        import urllib.request
        from github_api_transport import _SameHostRedirect
        request = urllib.request.Request(
            "https://api.github.com/graphql",
            headers={"Authorization": "Bearer test-secret"},
        )
        with self.assertRaises(urllib.error.HTTPError):
            _SameHostRedirect().redirect_request(
                request, None, 302, "Found", {}, "https://attacker.invalid/collect"
            )

    def test_github_transport_rejects_non_api_initial_destination(self):
        import urllib.request
        from github_api_transport import open_github
        request = urllib.request.Request(
            "https://attacker.invalid/collect",
            headers={"Authorization": "Bearer test-secret"},
        )
        with self.assertRaisesRegex(ValueError, "api.github.com"):
            open_github(request)

    def test_github_transport_rejects_oversized_response(self):
        from github_api_transport import read_bounded
        class OversizedResponse:
            def read(self, amount):
                self.amount = amount
                return b"x" * amount
        response = OversizedResponse()
        with self.assertRaisesRegex(ValueError, "1 MiB"):
            read_bounded(response)
        self.assertEqual(response.amount, 1_048_577)

    def test_provisioner_rejects_arbitrary_absolute_api_url_before_network(self):
        with self.assertRaisesRegex(provisioner.ProvisioningError, "must target api.github.com"):
            provisioner.api_request(
                "test-secret", "GET", "https://attacker.invalid/steal"
            )

    def test_provisioner_rejects_network_path_reference(self):
        with self.assertRaisesRegex(provisioner.ProvisioningError, "repository-relative"):
            provisioner.api_request("test-secret", "GET", "//attacker.invalid/steal")


if __name__ == "__main__":
    unittest.main()
