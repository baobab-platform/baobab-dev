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
        self.assertIn('if [[ "${{ matrix.profile }}" == "frontend-e2e" ]]; then', text)
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

    def test_manifest_reconciliation_runs_after_a_historical_lifecycle_refusal(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        reconcile = workflow.split("  image-binary-reconciliation:\n", 1)[1]
        reconcile = reconcile.split("  dev10-image-observed-41-binary-manifests:\n", 1)[0]
        self.assertIn("      - published-image", reconcile)
        self.assertIn("if: ${{ !cancelled() && needs.source.result == 'success' }}", reconcile)
        self.assertIn('--require-all-profiles', reconcile)

    def test_container_workspace_variables_are_not_expanded_by_host_shell(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        step = workflow.split("      - name: A failed final verifier", 1)[1]
        self.assertIn("bash -c '", step)
        container_script = step.split("bash -c '", 1)[1].split("\n            ' || result=$?", 1)[0]
        host_command = step.split("bash -c '", 1)[0]
        self.assertIn('export PATH=/tmp/dev10-fail/bin:$PATH WORKSPACE_DIR=/tmp/dev10-fail', container_script)
        self.assertIn('cd "$WORKSPACE_DIR"', container_script)
        self.assertNotIn("$WORKSPACE_DIR", host_command)
        self.assertNotIn('bash -c "', step)

    def test_reviewed_code_runs_from_read_only_source_mount(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('bash "$SRC_DIR/scripts/post-create.sh"', text)
        self.assertIn('bash "$SRC_DIR/scripts/verify.sh"', text)
        self.assertIn('bash /source/scripts/verify.sh "$@" > /tmp/dev10-post-create-verify.log 2>&1', text)
        self.assertIn('status=$?', text)
        self.assertIn('>> /tmp/dev10-post-create-verify-statuses', text)
        self.assertIn('exit 0', text)
        self.assertIn('post_create_verify_status="$(tail -n 1 /tmp/dev10-post-create-verify-statuses', text)
        self.assertIn('playwright_package="$(npm root -g)/playwright"', text)
        self.assertIn('chromium.launch({ headless: true })', text)
        self.assertIn('Playwright Chromium launches as $(id -un)', text)
        self.assertIn('exec bash /source/scripts/summary.sh "$@"', text)


if __name__ == "__main__":
    unittest.main()
