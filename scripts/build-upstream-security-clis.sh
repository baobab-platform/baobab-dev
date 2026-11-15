#!/usr/bin/env bash
# Rebuild upstream gh/cosign from exact reviewed release-tag commits.
# Release metadata comes from versions.lock; no binary is accepted as "DEV".
set -euo pipefail
export PATH="/build/go/bin:$PATH" GOTOOLCHAIN=local CGO_ENABLED=0
export GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org

# The lock is the sole version source. The pinned source commits below are
# independently checked against the corresponding upstream release tags.
# shellcheck disable=SC1091
. /build/versions.lock
: "$GH_VERSION" "$COSIGN_VERSION"

go version | grep -F 'go1.27.3'
mkdir -p /out

prepare_source() {
  local tool="$1" repo="$2" commit="$3" version="$4"
  local dest="/build/upstream-$tool" tag_commit source_date_epoch

  mkdir -p "$dest"
  git -C "$dest" init -q
  git -C "$dest" remote add origin "$repo"
  git -C "$dest" fetch --depth 1 origin "$commit"
  git -C "$dest" checkout --detach -q FETCH_HEAD

  [[ "$(git -C "$dest" rev-parse HEAD)" == "$commit" ]] || {
    echo "::error::Upstream $tool source commit mismatch" >&2
    exit 1
  }

  git -C "$dest" fetch --depth 1 origin "refs/tags/v$version"
  tag_commit="$(git -C "$dest" rev-parse 'FETCH_HEAD^{commit}')"
  [[ "$tag_commit" == "$commit" ]] || {
    echo "::error::Upstream $tool tag v$version resolves to $tag_commit, expected $commit" >&2
    exit 1
  }
  git -C "$dest" checkout --detach -q "$commit"

  source_date_epoch="$(git -C "$dest" show -s --format=%ct HEAD)"
  printf '%s\n' "$source_date_epoch"
}

verify_fixed_xnet() {
  local tool="$1" dest="$2" selected
  (
    cd "$dest"
    # The upstream release source is retained, with only the reviewed x/net
    # security override applied and verified against the Go checksum database.
    go get golang.org/x/net@v0.62.0
    go mod tidy
    go mod verify
    selected="$(go list -m -f '{{.Version}}' golang.org/x/net)"
    [[ "$selected" == "v0.62.0" ]] || {
      echo "::error::$tool selected x/net $selected, not v0.62.0" >&2
      exit 1
    }
  )
}

build_gh() {
  local repo="https://github.com/cli/cli.git"
  local commit="89d7dcec017194af1d6f8853176b2dae9c1da762"
  local dest="/build/upstream-gh" source_date_epoch

  source_date_epoch="$(prepare_source gh "$repo" "$commit" "$GH_VERSION")"
  verify_fixed_xnet gh "$dest"

  (
    cd "$dest"
    # Use GitHub CLI's own build task so Version and Date are injected using
    # the same linker variables as upstream release builds.
    mkdir -p bin
    go run script/build.go bin/gh \
      "GH_VERSION=$GH_VERSION" \
      "SOURCE_DATE_EPOCH=$source_date_epoch"
  )

  install -m 0755 "$dest/bin/gh" /out/gh
  go version -m /out/gh | tee /out/gh.buildinfo
  grep -E 'golang.org/x/net[[:space:]]+v0.62.0[[:space:]]' /out/gh.buildinfo

  /out/gh version > /out/gh.version 2>&1 || /out/gh --version > /out/gh.version 2>&1
  grep -F "gh version $GH_VERSION" /out/gh.version
}

build_cosign() {
  local repo="https://github.com/sigstore/cosign.git"
  local commit="0e48502cf5ef34e2e60bbd3617aa19945712f705"
  local dest="/build/upstream-cosign" source_date_epoch

  source_date_epoch="$(prepare_source cosign "$repo" "$commit" "$COSIGN_VERSION")"
  verify_fixed_xnet cosign "$dest"

  (
    cd "$dest"
    # Cosign's Makefile is its authoritative release build: it injects
    # GitVersion, GitCommit, GitTreeState and reproducible BuildDate.
    # Go 1.18+ VCS stamping sets debug.BuildInfo.Main.Version to a
    # pseudo-version. release-utils prefers that value over its gitVersion
    # linker variable, so disable automatic stamping and supply the exact
    # release identity through Cosign's supported Makefile variables.
    # Command-line assignments take precedence over upstream Makefile defaults.
    GOFLAGS=-buildvcs=false make \
      "GIT_VERSION=v$COSIGN_VERSION" \
      "SOURCE_DATE_EPOCH=$source_date_epoch" \
      cosign
  )

  install -m 0755 "$dest/cosign" /out/cosign
  go version -m /out/cosign | tee /out/cosign.buildinfo
  grep -E 'golang.org/x/net[[:space:]]+v0.62.0[[:space:]]' /out/cosign.buildinfo

  /out/cosign version > /out/cosign.version 2>&1
  cat /out/cosign.version

  assert_version_field() {
    local field="$1" expected="$2"
    awk -F: -v key="$field" -v expected="$expected" '
      $1 == key {
        value = substr($0, index($0, ":") + 1)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
        if (value == expected) found = 1
      }
      END { exit(found ? 0 : 1) }
    ' /out/cosign.version || {
      echo "::error::Cosign $field mismatch; expected $expected" >&2
      exit 1
    }
  }

  expected_build_date="$(date -u -d "@$source_date_epoch" +'%Y-%m-%dT%H:%M:%SZ')"
  assert_version_field GitVersion "v$COSIGN_VERSION"
  assert_version_field GitCommit "$commit"
  assert_version_field GitTreeState dirty
  assert_version_field BuildDate "$expected_build_date"
}

build_gh
build_cosign
