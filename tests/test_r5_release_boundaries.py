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
        build = active_yaml(jobs()["build"])
        self.assertRegex(build, r"(?m)^\s+permissions:\s*\n\s+contents: read\s*$")
        self.assertNotIn("packages: write", build)
        self.assertNotIn("docker/login-action@", build)
        self.assertNotIn("push-by-digest=true", build)
        self.assertIn("Scan built container with Trivy", build)

    def test_tag_only_exact_digest_security_is_required(self):
        run = jobs()["release-digests"]
        self.assertIn("needs: [sanity-check, build]", run)
        self.assertIn("needs.sanity-check.outputs.is_release == 'true'", run)
        self.assertIn("packages: write", run)
        self.assertIn("Scan EXACT registry architecture digest with fresh Trivy DBs", run)
        self.assertIn("CHILD_DIGEST: ${{ steps.exact.outputs.child }}", run)
        self.assertIn("--ignorefile /dev/null", run)
        self.assertIn("--exit-code 1", run)
        self.assertIn("scripts/dev10_kernel_risk_gate.py", run)
        self.assertIn("--raw-trivy \"$RUNNER_TEMP/trivy-exact-raw.json\"", run)
        self.assertIn("--inventory docs/assessments/dev10-kernel-cves.tsv", run)
        self.assertIn("--ref \"${GITHUB_REF}\"", run)
        self.assertIn("if (( rc != 1 )); then", run)
        self.assertIn("dev10-executive-risk-acceptance.json", run)
        self.assertIn("trivy image --download-db-only", run)
        self.assertIn("trivy image --download-java-db-only", run)
        self.assertIn("verify_trivy_db_freshness.py", run)

    def test_versioned_development_image_distribution_is_exactly_v150(self):
        gate = (ROOT / "scripts/dev10_kernel_risk_gate.py").read_text()
        self.assertIn('APPROVED_DEVELOPMENT_IMAGE_REF = "refs/tags/v1.5.0"', gate)
        self.assertIn("is_dev_image_release", gate)
        self.assertIn("now < EXPIRY", gate)
        validation = active_yaml(jobs()["build"])
        exact = active_yaml(jobs()["release-digests"])
        self.assertIn("--exit-code 1", validation)
        self.assertIn("--exit-code 1", exact)
        self.assertIn("--ignorefile /dev/null", validation)
        self.assertIn("--ignorefile /dev/null", exact)
        self.assertIn("summarize-trivy-vulnerabilities.py", exact)
        self.assertIn("if (( rc != 1 )); then", exact)
        self.assertIn("dev10_kernel_risk_gate.py", exact)
        self.assertIn("needs: [sanity-check, build]", exact)
        self.assertNotIn("packages: write", validation)
        self.assertIn("name: dev10-release-promotion", jobs()["promote"])

    def test_signing_then_protected_approval_then_release(self):
        run = jobs()
        self.assertIn("needs: [release-digests, sanity-check]", run["publish"])
        self.assertNotIn("crane tag", active_yaml(run["publish"]))
        self.assertIn("Verify both signed architecture-specific SLSA and SPDX payloads", run["publish"])
        self.assertIn("verify_signed_release_predicates.py", run["publish"])
        self.assertIn("name: dev10-release-promotion", run["promote"])
        self.assertIn("needs: [publish, sanity-check]", run["promote"])
        self.assertIn("verify_release_environment.py", run["promote"])
        self.assertIn("promote_release_tags.sh", run["promote"])
        self.assertIn("Preserve promotion journal", run["promote"])
        self.assertIn("needs: [promote, sanity-check]", run["release"])

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

    def test_independent_integrity_monitor_is_read_only(self):
        source = INTEGRITY.read_text()
        self.assertIn("packages: read", source)
        self.assertNotIn("packages: write", source)
        self.assertIn("verify_release_contracts.py", source)
        self.assertIn("scripts/verify-image.sh", source)
        self.assertIn("github.event.workflow_run.conclusion == 'success'", source)


if __name__ == "__main__":
    unittest.main()
