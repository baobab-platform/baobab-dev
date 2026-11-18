"""DEV-10 R5 source invariants for separation of release privileges."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/publish.yml"
INTEGRITY = ROOT / ".github/workflows/registry-integrity.yml"


def jobs() -> dict[str, str]:
    source = WORKFLOW.read_text()
    markers = list(re.finditer(r"(?m)^  ([a-z][a-z0-9-]+):[ \t]*$", source))
    return {match.group(1): source[match.end():
            markers[i + 1].start() if i + 1 < len(markers) else len(source)]
            for i, match in enumerate(markers)}


def active_yaml(job: str) -> str:
    # Documentation comments must not be interpreted as executable grants.
    return "\n".join(line for line in job.splitlines()
                     if not line.lstrip().startswith("#"))


class R5ReleaseBoundaryTests(unittest.TestCase):
    def test_no_pr_or_main_registry_write_in_build(self):
        pull_request = source.split("  pull_request:", 1)[1].split("  workflow_dispatch:", 1)[0]
        self.assertNotIn("branches:", pull_request,
                         "stacked security PRs must not be stranded by transient base-branch allowlists")
        build = active_yaml(jobs()["build"])
        self.assertRegex(build, r"(?m)^\s+permissions:\s*\n\s+contents: read\s*$")
        self.assertNotIn("packages: write", build)
        self.assertNotIn("docker/login-action@", build)
        self.assertNotIn("push-by-digest=true", build)
        self.assertIn("Scan built container with Trivy", build)

    def test_local_runtime_qualification_runs_after_scan_denial_when_build_succeeded(self):
        build = active_yaml(jobs()["build"])
        self.assertIn("id: build-local-image", build)
        self.assertIn(
            "if: ${{ !cancelled() && steps.build-local-image.outcome == 'success' "
            "&& matrix.target != 'final' }}",
            build,
        )
        self.assertIn(
            "if: ${{ !cancelled() && steps.build-local-image.outcome == 'success' "
            "&& (matrix.target == 'frontend' || matrix.target == 'frontend-e2e') "
            "&& matrix.platform == 'linux/amd64' }}",
            build,
        )
        # These tests must not become a way around the required Trivy gate.
        self.assertIn("Scan built container with Trivy", build)
        self.assertIn("--exit-code 1", build)

    def test_tag_only_exact_digest_security_is_required(self):
        run = jobs()["release-digests"]
        self.assertIn("needs: [sanity-check, build]", run)
        self.assertIn("needs.sanity-check.outputs.is_release == 'true'", run)
        self.assertIn("packages: write", run)
        self.assertIn("Scan EXACT registry architecture digest with fresh Trivy DBs", run)
        self.assertIn("CHILD_DIGEST: ${{ steps.exact.outputs.child }}", run)
        self.assertIn("--ignorefile /dev/null", run)
        self.assertIn("--exit-code 1", run)
        self.assertNotIn("scripts/dev10_kernel_risk_gate.py", run)
        self.assertIn("if (( rc != 1 )); then", run)
        self.assertIn("Residual vulnerabilities in a tagged remote image require separately authenticated exact-digest release approval", run)
        self.assertIn("trivy image --download-db-only", run)
        self.assertIn("trivy image --download-java-db-only", run)
        self.assertIn("verify_trivy_db_freshness.py", run)

    def test_historical_development_risk_gate_is_retired_and_disclosure_only(self):
        gate = (ROOT / "scripts/dev10_kernel_risk_gate.py").read_text()
        self.assertIn("Retired legacy DEV-10 risk gate", gate)
        self.assertIn("HISTORICAL_DISCLOSURE_IMAGE_REFS", gate)
        self.assertIn("HISTORICAL_DISCLOSURE_RC_REF", gate)
        self.assertIn("is_historical_development_risk_disclosure_ref", gate)
        self.assertIn("def validate(*_args, **_kwargs):", gate)
        self.assertIn("cannot authorize release publication or promotion", gate)
        self.assertIn("raise RiskGateError", gate)
        validation = active_yaml(jobs()["build"])
        exact = active_yaml(jobs()["release-digests"])
        self.assertIn("--exit-code 1", validation)
        self.assertIn("--exit-code 1", exact)
        self.assertIn("--ignorefile /dev/null", validation)
        self.assertIn("--ignorefile /dev/null", exact)
        self.assertIn("summarize-trivy-vulnerabilities.py", exact)
        self.assertIn("if (( rc != 1 )); then", exact)
        self.assertNotIn("dev10_kernel_risk_gate.py", exact)
        self.assertIn("needs: [sanity-check, build]", exact)
        self.assertNotIn("packages: write", validation)
        self.assertIn("name: dev10-release-promotion", jobs()["promote"])

    def test_exact_rc_series_publishes_full_pipeline_but_ga_advances_aliases(self):
        source = WORKFLOW.read_text()
        self.assertIn("scripts/release_tag_policy.py", source)
        self.assertIn('echo "is_release=true"', source)
        self.assertIn('is_stable_release=$(is_stable_release "$GITHUB_REF_NAME")', source)
        self.assertIn("name: dev10-release-promotion", jobs()["promote"])
        self.assertIn("prerelease: ${{ needs.sanity-check.outputs.is_stable_release != 'true' }}", active_yaml(jobs()["release"]))
        self.assertIn("type=semver,pattern={{major}}.{{minor}}", source)
        self.assertIn("enable=${{ needs.sanity-check.outputs.is_stable_release == 'true' }}", source)
        script = (ROOT / "scripts/promote_release_tags.sh").read_text()
        self.assertIn("PROMOTED_FOUR_RC_VERSIONS_NO_ALIASES", script)
        self.assertIn("PROMOTED_FOUR_TARGETS_AND_ALIASES", script)
        self.assertIn("if (( is_release_candidate == 0 )); then", script)
        self.assertIn('for prefix in "$major_minor" "$major" latest;', script)
        registry = INTEGRITY.read_text()
        self.assertIn("releases/tags/", registry)
        self.assertIn("TRIGGER_SHA", registry)

    def test_signing_then_protected_approval_then_release(self):
        run = jobs()
        self.assertIn("needs: [release-digests, sanity-check]", run["publish"])
        self.assertNotIn("crane tag", active_yaml(run["publish"]))
        self.assertIn("Verify both signed architecture-specific SLSA and SPDX payloads", run["publish"])
        self.assertIn("verify_signed_release_predicates.py", run["publish"])
        self.assertIn("name: dev10-release-promotion", run["promote"])
        self.assertIn("needs: [publish, ga-reuse, sanity-check]", run["promote"])
        self.assertIn("needs.ga-reuse.result == 'success'", run["promote"])
        self.assertIn("needs.publish.result == 'success'", run["promote"])
        self.assertIn("name: Reuse qualified RC OCI digests for GA", run["ga-reuse"])
        self.assertIn("is_stable_release == 'true'", run["ga-reuse"])
        self.assertIn("verify_rc_ga_workflow.py", run["promote"])
        self.assertIn("verify_release_environment.py", run["promote"])
        self.assertIn("promote_release_tags.sh", run["promote"])
        self.assertIn("Preserve promotion journal", run["promote"])
        self.assertIn("needs: [promote, sanity-check, ga-reuse]", run["release"])
        self.assertIn("needs.promote.result == 'success'", run["release"])

    def test_development_scans_run_without_manual_environment_pause(self):
        foundation = (ROOT / ".github/workflows/foundation.yml").read_text()
        gate_match = re.search(
            r"(?ms)^  dev10-container-risk:\n(.*?)(?=^  [a-z0-9-]+:|\Z)",
            foundation,
        )
        self.assertIsNotNone(gate_match)
        self.assertNotIn("environment:", gate_match.group(1))
        build = active_yaml(jobs()["build"])
        self.assertNotIn("dev10-security-policy-read", build)
        promote = active_yaml(jobs()["promote"])
        self.assertIn("name: dev10-release-promotion", promote)
        self.assertIn("environment:", promote)

    def test_release_publication_and_promotion_never_consume_dev10_risk_authority(self):
        release_scan = active_yaml(jobs()["release-digests"])
        publish = active_yaml(jobs()["publish"])
        promote = active_yaml(jobs()["promote"])
        for workflow_job in (release_scan, publish, promote):
            self.assertNotIn("DEV10_PROTECTED_DECISION_SHA256", workflow_job)
            self.assertNotIn("DEV10_SECURITY_APPROVER_LOGINS", workflow_job)
            self.assertNotIn("verify_protected_policy_hash.py", workflow_job)
        self.assertIn(
            "development-only acceptance is insufficient",
            release_scan,
        )
        self.assertIn(
            "Residual vulnerabilities in a tagged remote image require separately authenticated exact-digest release approval",
            release_scan,
        )
        self.assertIn("verify_digest_security_decision.py", promote)
        self.assertIn("verify_release_environment.py", promote)

    def test_release_promotion_never_reuses_development_risk_authority(self):
        promote = active_yaml(jobs()["promote"])
        self.assertNotIn("DEV10_PROTECTED_DECISION_SHA256", promote)
        self.assertNotIn("DEV10_SECURITY_APPROVER_LOGINS", promote)
        self.assertNotIn("verify_protected_risk_custody.py", promote)
        self.assertNotIn('decision_file="security/decisions/$RELEASE_TAG', promote)
        self.assertIn("scripts/evaluate_protected_risk_decision.py", promote)
        self.assertNotIn("decision_args", promote)
        evaluator = (ROOT / "scripts/verify_digest_security_decision.py").read_text()
        self.assertIn("legacy free-text release decisions are not authenticated", evaluator)
        self.assertIn("protected custody required", evaluator)

    def test_slsa_v1_predicate_serialization_and_legacy_scope(self):
        source = WORKFLOW.read_text()
        # Cosign's slsaprovenance1 typed writer drops unknown protobuf
        # fields. R5 must sign the canonical URI through the generic
        # JSON-preserving writer, but still verify as SLSA v1.
        self.assertIn('--type "https://slsa.dev/provenance/v1"', source)
        self.assertIn('[[ "${PREDICATE_TYPE}" == "slsaprovenance1" ]]', source)
        self.assertIn('--type slsaprovenance1', source)
        self.assertIn('--expected-subject "$DIGEST"', source)
        integrity = INTEGRITY.read_text()
        self.assertIn('verify_legacy_provenance.py', integrity)
        self.assertIn('LEGACY_SLSA_PROTOBUF_COMPATIBLE_NOT_FULL_CONTENT_EQUIVALENCE',
                      integrity)
        self.assertIn('STRICT_SIGNED_NATIVE_CONTENT_VERIFIED', integrity)

    def test_dev10_inventory_and_policy_changes_trigger_full_image_matrix(self):
        source = WORKFLOW.read_text()
        for path in (
            "docs/assessments/dev10-kernel-cves-298.tsv",
            "docs/assessments/dev10-canonical-cve-status-20261118.tsv",
            "security/evidence/**",
            "security/decisions/development/foundation.schema.json",
            "security/decisions/development/foundation.json",
            "security/decisions/development/foundation.proposal.json",
            "scripts/evaluate_protected_risk_decision.py",
            "scripts/verify_protected_policy_hash.py",
        ):
            with self.subTest(path=path):
                self.assertGreaterEqual(source.count(f'"{path}"'), 2,
                                        "push and pull_request must both requalify")
        build = active_yaml(jobs()["build"])
        self.assertIn("matrix.target", build)
        self.assertIn("matrix.platform", build)
        self.assertIn("linux/amd64", build)
        self.assertIn("linux/arm64", build)
        for profile in ("final", "frontend", "frontend-e2e", "infra"):
            with self.subTest(profile=profile):
                self.assertIn(profile, build)

    def test_independent_integrity_monitor_is_read_only(self):
        source = INTEGRITY.read_text()
        self.assertIn("packages: read", source)
        self.assertNotIn("packages: write", source)
        self.assertIn("verify_release_contracts.py", source)
        self.assertIn("scripts/verify-image.sh", source)
        self.assertIn("github.event.workflow_run.conclusion == 'success'", source)


if __name__ == "__main__":
    unittest.main()
