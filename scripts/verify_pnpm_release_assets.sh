#!/usr/bin/env bash
# Verify pnpm's native Linux release archives against GitHub's signed SLSA
# provenance and the exact publisher asset SHA-256 values committed in
# config/versions.yaml. This is intentionally separate from the Docker build:
# the resolver qualifies publisher bytes before any image consumes them.
set -Eeuo pipefail

usage() {
  echo "Usage: $0 <pnpm-version> <linux-amd64-sha256> <linux-arm64-sha256>" >&2
  exit 2
}

[[ $# -eq 3 ]] || usage
version="$1"
expected_amd64="$2"
expected_arm64="$3"

if [[ ! "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  echo "::error::pnpm version must be canonical stable SemVer" >&2
  exit 1
fi
for digest in "$expected_amd64" "$expected_arm64"; do
  if [[ ! "$digest" =~ ^[a-f0-9]{64}$ ]]; then
    echo "::error::pnpm publisher SHA-256 values must be 64 lowercase hex characters" >&2
    exit 1
  fi
done

# gh <=2.101.0 had prefix/case matching defects in --signer-workflow and
# --source-ref. Require the fixed implementation before trusting those flags.
gh_version="$(gh version | awk 'NR == 1 { print $3 }')"
if [[ ! "$gh_version" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
  echo "::error::Could not parse GitHub CLI version: ${gh_version:-missing}" >&2
  exit 1
fi
gh_major="${BASH_REMATCH[1]}"
gh_minor="${BASH_REMATCH[2]}"
if (( gh_major < 2 || (gh_major == 2 && gh_minor < 102) )); then
  echo "::error::GitHub CLI >=2.102.0 is required for exact attestation identity checks (found: $gh_version)" >&2
  exit 1
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

verify_asset() {
  local asset="$1"
  local expected="$2"
  local actual
  local file="$tmp_dir/$asset"

  curl --fail --location --silent --show-error --retry 3 \
    "https://github.com/pnpm/pnpm/releases/download/v${version}/${asset}" \
    --output "$file"

  # GitHub Actions requires GH_TOKEN for GitHub CLI API access. Keep the
  # caller's read-only Actions token so public publisher attestations can be
  # retrieved; never discard authentication inside the verifier subprocess.
  gh attestation verify "$file" \
    --repo pnpm/pnpm \
    --signer-workflow pnpm/pnpm/.github/workflows/release.yml \
    --source-ref "refs/tags/v${version}" \
    --cert-oidc-issuer "https://token.actions.githubusercontent.com" \
    --predicate-type "https://slsa.dev/provenance/v1"

  actual="$(sha256sum "$file" | awk '{ print $1 }')"
  if [[ "$actual" != "$expected" ]]; then
    echo "::error::Publisher-attested pnpm asset ${asset} SHA-256 mismatch: expected ${expected}, got ${actual}" >&2
    return 1
  fi
  echo "[OK] ${asset}: signed publisher provenance and SHA-256 ${actual}" >&2
}

verify_asset "pnpm-linux-x64.tar.gz" "$expected_amd64"
verify_asset "pnpm-linux-arm64.tar.gz" "$expected_arm64"
