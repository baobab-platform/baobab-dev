#!/usr/bin/env bash
# Exercise the immutable historical profile image on its native architecture.
# The checkout is read-only; project and consumer workspaces are writable.
set -euo pipefail

SRC_DIR=/source
PROJECT_DIR=/tmp/dev10-project
CONSUMER_DIR=/tmp/dev10-consumer
TOOLS_DIR=/tmp/dev10-tools
EVIDENCE_FILE=/evidence/onboarding-verification.json
EXPECTED_PROFILE="${EXPECTED_PROFILE:?expected matrix profile is required}"
IMAGE_REF="${IMAGE_REF:?immutable image reference is required}"
[[ "$IMAGE_REF" =~ ^ghcr\.io/baobab-platform/baobab-dev@sha256:[a-f0-9]{64}$ ]] || {
  echo "Onboarding requires the exact immutable Baobab GHCR index digest" >&2
  exit 2
}
BUILD_PROFILE="${BAOBAB_BUILD_PROFILE:?published image must declare its baked profile}"
EXPECTED_RUNTIME_PROFILE="$EXPECTED_PROFILE"
if [[ "$EXPECTED_PROFILE" == "final" ]]; then
  EXPECTED_RUNTIME_PROFILE="full"
fi
[[ "$BUILD_PROFILE" == "$EXPECTED_RUNTIME_PROFILE" ]] || {
  echo "Published image profile mismatch: expected $EXPECTED_RUNTIME_PROFILE for $EXPECTED_PROFILE, found $BUILD_PROFILE" >&2
  exit 2
}
export BAOBAB_BUILD_PROFILE="$BUILD_PROFILE"

require_source() {
  [[ -f "$SRC_DIR/scripts/post-create.sh" && -x "$SRC_DIR/scripts/project-pnpm.sh" ]] || {
    echo "Reviewed source checkout is incomplete" >&2
    ls -la "$SRC_DIR/scripts" >&2 || true
    exit 2
  }
}

require_source
[[ "$(id -u)" -ne 0 ]] || { echo "Published image onboarding must run as its non-root runtime user" >&2; exit 2; }
[[ "$(getent passwd "$(id -u)" | cut -d: -f6)" == "$HOME" ]] || { echo "Container HOME must remain the image runtime user home" >&2; exit 2; }
mkdir -p "$HOME" "$PROJECT_DIR" "$TOOLS_DIR" /evidence
cp -a "$SRC_DIR/." "$PROJECT_DIR/"
test -f "$PROJECT_DIR/scripts/post-create.sh"

# Install the repository-pinned uv with an architecture-specific checksum.
mkdir -p /tmp/dev10-uv
case "$(uname -m)" in
  x86_64)
    uv_asset=uv-x86_64-unknown-linux-gnu.tar.gz
    uv_sha=a7fbaff2b9a271d85c1bdb540941090fd1ce011797b4abeb48e4dcd39c2471d5
    ;;
  aarch64)
    uv_asset=uv-aarch64-unknown-linux-gnu.tar.gz
    uv_sha=0797542018e541a9288855df555c8077eed06f7a47d206362030480e8ecc9f3d
    ;;
  *)
    echo "Unsupported onboarding architecture: $(uname -m)" >&2
    exit 2
    ;;
esac
curl -fsSL --retry 5 --retry-all-errors \
  "https://github.com/astral-sh/uv/releases/download/0.13.9/$uv_asset" \
  -o /tmp/dev10-uv/uv.tar.gz
echo "$uv_sha  /tmp/dev10-uv/uv.tar.gz" | sha256sum --check --strict
tar -xzf /tmp/dev10-uv/uv.tar.gz -C /tmp/dev10-uv
mapfile -t uv_bins < <(find /tmp/dev10-uv -type f -name uv -perm -u+x -print)
(( ${#uv_bins[@]} == 1 )) || {
  echo "Expected exactly one executable uv in verified archive" >&2
  exit 2
}
install "${uv_bins[0]}" "$TOOLS_DIR/uv"
uv_version="$("$TOOLS_DIR/uv" --version)"
[[ "$uv_version" == "uv 0.13.9"* ]] || {
  echo "Expected uv 0.13.9, got: $uv_version" >&2
  exit 2
}
cat > "$TOOLS_DIR/baobab-summary" <<'SH'
#!/usr/bin/env bash
exec bash /source/scripts/summary.sh "$@"
SH
cat > "$TOOLS_DIR/baobab-verify" <<'SH'
#!/usr/bin/env bash
exec bash /source/scripts/verify.sh "$@"
SH
chmod +x "$TOOLS_DIR/baobab-summary" "$TOOLS_DIR/baobab-verify"
export PATH="$TOOLS_DIR:$PATH"

# Lifecycle scripts are executed from the read-only checkout while WORKSPACE_DIR
# points only to the writable project copy.
(
  cd "$PROJECT_DIR"
  WORKSPACE_DIR="$PROJECT_DIR" bash "$SRC_DIR/scripts/post-create.sh" --stage=post-create
)
if [[ "$BUILD_PROFILE" == "infra" ]]; then
  echo "Skipping in-image Python unit suite: infra profile intentionally excludes Python"
else
  python3 -B -m unittest discover -s "$PROJECT_DIR/tests" -v
fi

# The infra image intentionally has no Node/pnpm toolchain. Other profiles
# exercise both the image-pinned pnpm and exact consumer packageManager pins.
if [[ "$BUILD_PROFILE" != "infra" ]]; then
  [[ "$(cd / && pnpm --version)" == "12.16.1" ]]
  for pnpm_version in 12.16.1 11.24.0; do
    rm -rf "$CONSUMER_DIR"
    mkdir -p "$CONSUMER_DIR"
    cp -R "$SRC_DIR/tests/fixtures/pnpm-workspace/." "$CONSUMER_DIR/"
    mv "$CONSUMER_DIR/package.json.fixture" "$CONSUMER_DIR/package.json"
    mv "$CONSUMER_DIR/frontend/package.json.fixture" "$CONSUMER_DIR/frontend/package.json"
    cp -R "$SRC_DIR/config" "$CONSUMER_DIR/config"
    sed -i "s/pnpm@12[.]16[.]1/pnpm@${pnpm_version}/" "$CONSUMER_DIR/package.json"
    echo "Testing consumer packageManager pnpm@${pnpm_version}"
    (
      cd "$CONSUMER_DIR"
      WORKSPACE_DIR="$CONSUMER_DIR" bash "$SRC_DIR/scripts/post-create.sh" --stage=post-create
    )
    test ! -f "$CONSUMER_DIR/frontend/package-lock.json"
  done
else
  echo "Skipping Node/pnpm fixtures: infra profile deliberately excludes Node"
fi

# Run the full verifier as the image's non-root runtime user. The 1.5.1
# historical image may fail newer tool-version checks; retain that outcome as
# an explicit unqualified baseline instead of suppressing it or calling it green.
verify_log=/tmp/dev10-verify.log
if WORKSPACE_DIR="$PROJECT_DIR" bash "$SRC_DIR/scripts/verify.sh" >"$verify_log" 2>&1; then
  verify_status=0
else
  verify_status=$?
fi
cat "$verify_log"
playwright_verified=false
if grep -Fq "Playwright Chromium launches as" "$verify_log"; then
  playwright_verified=true
fi
if (( verify_status == 0 )); then
  verify_label="VERIFIED"
else
  verify_label="HISTORICAL_BASELINE_UNQUALIFIED"
fi
# Preserve the verifier's bounded check messages without depending on Python
# (which the infra profile intentionally excludes).
failed_check_count="$(grep -c '✘' "$verify_log" || true)"
# Keep evidence generation independent of the profile's installed language
# runtimes: the infra image intentionally contains no Python interpreter.
cat > "$EVIDENCE_FILE" <<EOF
{
  "schema": "baobab.dev10.historical-onboarding-verification.v1",
  "image_profile": "$EXPECTED_PROFILE",
  "runtime_profile": "$BUILD_PROFILE",
  "image_ref": "$IMAGE_REF",
  "runtime_uid": $(id -u),
  "runtime_user": "$(id -un)",
  "verify_exit_status": $verify_status,
  "verify_status": "$verify_label",
  "playwright_chromium_verified": $playwright_verified,
  "failed_check_count": $failed_check_count,
  "release_qualification": false,
  "note": "A historical 1.5.1 image verification result is diagnostic only and never qualifies a new release."
}
EOF
if [[ "$EXPECTED_PROFILE" == "frontend-e2e" && "$playwright_verified" != true ]]; then
  echo "frontend-e2e requires a successful non-root Playwright Chromium launch" >&2
  exit 1
fi
if (( verify_status != 0 )); then
  echo "::warning::Historical image verifier failed; evidence is HISTORICAL_BASELINE_UNQUALIFIED"
fi\\r'/}"
  failed_line="${failed_line//{
  "schema": "baobab.dev10.historical-onboarding-verification.v1",
  "image_profile": "$EXPECTED_PROFILE",
  "runtime_profile": "$BUILD_PROFILE",
  "image_ref": "$IMAGE_REF",
  "runtime_uid": $(id -u),
  "runtime_user": "$(id -un)",
  "verify_exit_status": $verify_status,
  "verify_status": "$verify_label",
  "playwright_chromium_verified": $playwright_verified,
  "failed_checks": [],
  "release_qualification": false,
  "note": "A historical 1.5.1 image verification result is diagnostic only and never qualifies a new release."
}
EOF
if [[ "$EXPECTED_PROFILE" == "frontend-e2e" && "$playwright_verified" != true ]]; then
  echo "frontend-e2e requires a successful non-root Playwright Chromium launch" >&2
  exit 1
fi
if (( verify_status != 0 )); then
  echo "::warning::Historical image verifier failed; evidence is HISTORICAL_BASELINE_UNQUALIFIED"
fi\\t'/\\\\t}"
  failed_line="${failed_line//\\\\/\\\\\\\\}"
  failed_line="${failed_line//\"/\\\\\"}"
  [[ "$failed_checks_json" == '[' ]] || failed_checks_json+=','
  failed_checks_json+="\"$failed_line\""
done < "$clean_verify_log"
failed_checks_json+=']'
# Keep evidence generation independent of the profile's installed language
# runtimes: the infra image intentionally contains no Python interpreter.
cat > "$EVIDENCE_FILE" <<EOF
{
  "schema": "baobab.dev10.historical-onboarding-verification.v1",
  "image_profile": "$EXPECTED_PROFILE",
  "runtime_profile": "$BUILD_PROFILE",
  "image_ref": "$IMAGE_REF",
  "runtime_uid": $(id -u),
  "runtime_user": "$(id -un)",
  "verify_exit_status": $verify_status,
  "verify_status": "$verify_label",
  "playwright_chromium_verified": $playwright_verified,
  "failed_checks": [],
  "release_qualification": false,
  "note": "A historical 1.5.1 image verification result is diagnostic only and never qualifies a new release."
}
EOF
if [[ "$EXPECTED_PROFILE" == "frontend-e2e" && "$playwright_verified" != true ]]; then
  echo "frontend-e2e requires a successful non-root Playwright Chromium launch" >&2
  exit 1
fi
if (( verify_status != 0 )); then
  echo "::warning::Historical image verifier failed; evidence is HISTORICAL_BASELINE_UNQUALIFIED"
fi