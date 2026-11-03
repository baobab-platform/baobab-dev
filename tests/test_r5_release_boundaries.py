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


class R5ReleaseBoundaryTests(unittest.TestCase):
    def test_no_pr_or_main_registry_write_in_build(self):
        build = jobs()["build"]
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
        self.assertIn("CHILD_DIGEST: ${ steps.exact.outputs.child }}", run)
        self.assertIn("--ignorefile /dev/null", run)
        self.assertIn("--exit-code 1", run)
        self.assertNotIn("scripts/dev10_kernel_risk_gate.py", run)
        self.assertIn("trivy image --download-db-only", run)
        self.assertIn("trivy image --download-java-db-only", run)
        self.assertIn("verify_trivy_db_freshness.py", run)

    def test_signing_then_protected_approval_then_release(self):
        run = jobs()
        self.assertIn("needs: [release-digests, sanity-check]", run["publish"])
        self.assertNotIn("crane tag", run["publish"])
        self.assertIn("name: dev10-release-promotion", run["promote"])
        self.assertIn("needs: [publish, sanity-check]", run["promote"])
        self.assertIn("verify_release_environment.py", run["promote"])
        self.assertIn("promote_release_tags.sh", run["promote"])
        self.assertIn("Preserve promotion journal", run["promote"])
        self.assertIn("needs: [promote, sanity-check]", run["release"])

    def test_independent_integrity_monitor_is_read_only(self):
        source = INTEGRITY.read_text()
        self.assertIn("packages: read", source)
        self.assertNotIn("packages: write", source)
        self.assertIn("verify_release_contracts.py", source)
        self.assertIn("scripts/verify-image.sh", source)
        self.assertIn("github.event.workflow_run.conclusion == 'success'", source)


if __name__ == "__main__":
    unittest.main()
