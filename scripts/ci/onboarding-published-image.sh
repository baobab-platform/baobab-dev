#!/usr/bin/env bash
# Exercise the immutable historical profile image on its native architecture.
# The checkout is read-only; project and consumer workspaces are writable.
set -euo pipefail

SRC_DIR=/source
PROJECT_DIR=/tmp/dev10-project
CONSUMER_DIR=/tmp/dev10-consumer
TOOLS_DIR=/tmp/dev10-tools
EVIDENCE_FILE=/evidence/onboarding-verification.json
BUILD_PROFILE="${BAOBAB_BUILD_PROFILE:-full}"

require_source() {
  [[ -f "$SRC_DIR/scripts/post-create.sh" && -x "$SRC_DIR/scripts/project-pnpm.sh" ]] || {
    echo "Reviewed source checkout is incomplete" >&2
    ls -la "$SRC_DIR/scripts" >&2 || true
    exit 2
  }
}

require_source
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
export PATH="$TOOLS_DIR:$PATH"

# Lifecycle scripts are executed from the read-only checkout while WORKSPACE_DIR
# points only to the writable project copy.
(
  cd "$PROJECT_DIR"
  WORKSPACE_DIR="$PROJECT_DIR" bash "$SRC_DIR/scripts/post-create.sh" --stage=post-create
)
python3 -B -m unittest discover -s "$PROJECT_DIR/tests" -v

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
set +e
WORKSPACE_DIR="$PROJECT_DIR" bash "$SRC_DIR/scripts/verify.sh" >"$verify_log" 2>&1
verify_status=$?
set -e
cat "$verify_log"
python3 - "$verify_log" "$EVIDENCE_FILE" "$BUILD_PROFILE" "$verify_status" <<'PY'
import json
import re
import sys
from pathlib import Path

log_path, evidence_path, profile, exit_status = sys.argv[1:]
text = Path(log_path).read_text(encoding="utf-8", errors="replace")
clean = re.sub(r"\x1b\[[0-9;]*m", "", text)
failed = [line.strip() for line in clean.splitlines() if "✘" in line]
evidence = {
    "schema": "baobab.dev10.historical-onboarding-verification.v1",
    "image_profile": profile,
    "runtime_uid": __import__("os").getuid(),
    "runtime_user": __import__("getpass").getuser(),
    "verify_exit_status": int(exit_status),
    "verify_status": "VERIFIED" if int(exit_status) == 0 else "HISTORICAL_BASELINE_UNQUALIFIED",
    "playwright_chromium_verified": "Playwright Chromium launches as" in clean,
    "failed_checks": failed,
    "release_qualification": False,
    "note": "A historical 1.5.1 image verification result is diagnostic only and never qualifies a new release.",
}
Path(evidence_path).write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
if int(exit_status) != 0:
    print("::warning::Historical image verifier failed; evidence is HISTORICAL_BASELINE_UNQUALIFIED")
PY
