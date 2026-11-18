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
        self.assertIn('IMAGE_REF="${IMAGE_REF:?immutable image reference is required}"', text)
        self.assertIn('ghcr\\.io/baobab-platform/baobab-dev@sha256:', text)
        self.assertIn('getent passwd "$(id -u)"', text)
        self.assertIn("CONSUMER_DIR=/tmp/dev10-consumer", text)
        self.assertIn('bash "$SRC_DIR/scripts/post-create.sh"', text)
        self.assertNotIn("export WORKSPACE_DIR=", text)
        self.assertNotIn("assert_workspace", text)
        self.assertIn('if WORKSPACE_DIR="$PROJECT_DIR" bash "$SRC_DIR/scripts/verify.sh"', text)
        self.assertIn('if [[ "$BUILD_PROFILE" == "infra" ]]; then', text)
        self.assertIn('Skipping in-image Python unit suite: infra profile intentionally excludes Python', text)

    def test_workflow_passes_a_script_not_nested_container_shell_text(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("bash /source/scripts/ci/onboarding-published-image.sh", text)
        self.assertIn("cancel-in-progress: ${{ github.ref_name != 'main' && !startsWith(github.ref, 'refs/tags/') }}", text)
        self.assertNotIn("-e HOME=/tmp/dev10-home", text)
        self.assertIn('docker run --rm -e EXPECTED_PROFILE=', text)
        self.assertIn('if "${{ matrix.profile }}" == "frontend-e2e"; then', text)
        self.assertIn('docker run --rm --user 0:0', text)
        self.assertIn('cp -a "$browser_source/." /evidence/browser-cache/', text)
        self.assertIn('chmod -R a+rX /evidence/browser-cache', text)
        self.assertIn('-e PLAYWRIGHT_BROWSERS_PATH=/evidence/browser-cache', text)

    def test_profile_contracts_and_historical_verifier_status_are_explicit(self):
        script = SCRIPT.read_text(encoding="utf-8")
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('-e EXPECTED_PROFILE="${{ matrix.profile }}"', workflow)
        self.assertNotIn('-e BAOBAB_BUILD_PROFILE=', workflow)
        self.assertIn('if [[ "$BUILD_PROFILE" != "infra" ]]', script)
        self.assertIn('"HISTORICAL_BASELINE_UNQUALIFIED"', script)
        self.assertIn('"playwright_chromium_verified"', script)
        self.assertNotIn('python3 - "$verify_log"', script)
        self.assertIn('"image_ref": "$IMAGE_REF"', script)
        self.assertIn('baobab-dev@sha256:[a-f0-9]{64}', script)
        for profile in ("final", "frontend", "frontend-e2e", "infra"):
            self.assertIn("profile: " + profile, workflow)
        self.assertIn('stable_profile_images[$profile].index_digest', workflow)
        self.assertIn("dev10-onboarding-verification-${{ matrix.profile }}-${{ matrix.architecture }}", workflow)


    def test_exact_profile_and_non_root_runtime_are_passed_to_container(self):
        script = SCRIPT.read_text(encoding="utf-8")
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('export BAOBAB_BUILD_PROFILE="$BUILD_PROFILE"', script)
        self.assertIn('EXPECTED_PROFILE="${EXPECTED_PROFILE:?expected matrix profile is required}"', script)
        self.assertIn('BUILD_PROFILE="${BAOBAB_BUILD_PROFILE:?published image must declare its baked profile}"', script)
        self.assertIn('if [[ "$EXPECTED_PROFILE" == "final" ]]; then', script)
        self.assertIn('EXPECTED_RUNTIME_PROFILE="full"', script)
        self.assertIn('[[ "$BUILD_PROFILE" == "$EXPECTED_RUNTIME_PROFILE" ]] ', script)
        self.assertIn('-e EXPECTED_PROFILE="${{ matrix.profile }}" ', workflow)
        self.assertNotIn('-e BAOBAB_BUILD_PROFILE="${{ matrix.profile }}" ', workflow)
        self.assertIn('[[ "$(id -u)" -ne 0 ]]', script)
        self.assertIn('[[ "$EXPECTED_PROFILE" == "frontend-e2e" && "$playwright_verified" != true ]]' , script)
        self.assertIn('stable_profile_images[$profile].signer_tag', workflow)

    def test_reviewed_code_runs_from_read_only_source_mount(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('bash "$SRC_DIR/scripts/post-create.sh"', text)
        self.assertIn('bash "$SRC_DIR/scripts/verify.sh"', text)
        self.assertIn('exec bash /source/scripts/verify.sh "$@"', text)
        self.assertIn('exec bash /source/scripts/summary.sh "$@"', text)


if __name__ == "__main__":
    unittest.main()
