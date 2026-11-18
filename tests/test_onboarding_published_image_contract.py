"""Static contract tests for the published-image onboarding boundary."""
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/ci/onboarding-published-image.sh"
WORKFLOW = ROOT / ".github/workflows/dev10-onboarding.yml"


class PublishedImageOnboardingContractTests(unittest.TestCase):
    def test_script_parses_and_keeps_source_and_consumer_paths_distinct(self):
        subprocess.run(["bash", "-n", str(SCRIPT)], check=True)
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("SRC_DIR=/source", text)
        self.assertIn("CONSUMER_DIR=/tmp/dev10-consumer", text)
        self.assertIn('bash "$SRC_DIR/scripts/post-create.sh"', text)
        self.assertNotIn("export WORKSPACE_DIR=", text)
        self.assertNotIn("assert_workspace", text)

    def test_workflow_passes_a_script_not_nested_container_shell_text(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("bash /source/scripts/ci/onboarding-published-image.sh", text)
        self.assertNotIn('docker run --rm -e HOME=/tmp/dev10-home \\\n            -v "$GITHUB_WORKSPACE:/source:ro" "$IMAGE_REF" bash -c', text)

    def test_reviewed_code_runs_from_read_only_source_mount(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('bash "$SRC_DIR/scripts/post-create.sh"', text)
        self.assertIn('bash "$SRC_DIR/scripts/verify.sh"', text)


if __name__ == "__main__":
    unittest.main()
