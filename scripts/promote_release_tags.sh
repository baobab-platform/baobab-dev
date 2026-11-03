#!/usr/bin/env bash
# R5: registry tag moves are not transactional. Use two-phase promotion,
# immutable version-tag preflight, and compensated alias updates on failure.
set -Eeuo pipefail
: "${RELEASE_TAG:?stable tag required}"
: "${IMAGE:?image required}"
: "${INFO_DIR:?candidate records required}"
: "${PROMOTION_EVIDENCE_DIR:?evidence directory required}"
[[ "$RELEASE_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "::error::not stable semver"; exit 2; }
[[ "$IMAGE" == "ghcr.io/baobab-platform/baobab-dev" ]] || { echo "::error::wrong registry"; exit 2; }
command -v jq >/dev/null && command -v crane >/dev/null || { echo "::error::missing jq/crane"; exit 2; }
mkdir -p "$PROMOTION_EVIDENCE_DIR"
journal="$PROMOTION_EVIDENCE_DIR/promotion.tsv"
printf 'phase\ttag\tdigest\tresult\n' > "$journal"
version="${RELEASE_TAG#v}"
major="${version%%.*}"
major_minor="${version%.*}"
targets=(final frontend frontend-e2e infra)
declare -A expected prior_alias
version_tags=()
alias_tags=()
changed_aliases=()
mutation_started=0

fail() { echo "::error::DEV-10 R5 promotion: $*" >&2; return 1; }
read_tag_digest() {
  local output
  if output=$(crane digest "$IMAGE:$1" 2>&1); then
    [[ "$output" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "bad resolved digest $1"
    printf '%s' "$output"
  elif grep -Eqi '(manifest[_ ]unknown|manifest not found|404|not_found)' <<<"$output"; then
    printf ''
  else
    fail "cannot establish tag state $1: $output"
  fi
}
rollback() {
  local rc=$?
  trap - EXIT
  if ((rc != 0 && mutation_started != 0)); then
    echo "::error::PARTIAL GHCR PROMOTION: NO GitHub Release; audit $journal" >&2
    for ((i=${#changed_aliases[@]}-1; i>=0; i--)); do
      local tag="${changed_aliases[i]}" old="${prior_alias[${changed_aliases[i]}]}"
      if [[ -z "$old" ]]; then
        printf 'rollback\t%s\t-\tMANUAL_RECOVERY_NEW_ALIAS\n' "$tag" >> "$journal"
      elif crane tag "$IMAGE@$old" "$tag" && [[ "$(crane digest "$IMAGE:$tag")" == "$old" ]]; then
        printf 'rollback\t%s\t%s\tRESTORED\n' "$tag" "$old" >> "$journal"
      else
        printf 'rollback\t%s\t%s\tFAILED_MANUAL_RECOVERY\n' "$tag" "$old" >> "$journal"
        echo "::error::Alias restoration failed: $tag" >&2
      fi
    done
    echo "::error::New version tags can survive failure; inspect GHCR before retrying." >&2
  fi
  exit "$rc"
}
trap rollback EXIT

[[ -d "$INFO_DIR" ]] || fail "candidate directory missing"
count=$(find "$INFO_DIR" -maxdepth 1 -type f -name '*.json' | wc -l)
[[ "$count" -eq 4 ]] || fail "expected four candidate records"
for target in "${targets[@]}"; do
  record="$INFO_DIR/$target.json"
  [[ -f "$record" ]] || fail "missing candidate $target"
  suffix=""
  [[ "$target" == final ]] || suffix="-$target"
  tag="$version$suffix"
  digest=$(jq -er '.digest' "$record")
  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "invalid digest"
  [[ "$(jq -er '.target' "$record")" == "$target" ]] || fail "wrong target"
  [[ "$(jq -er '.tag' "$record")" == "$IMAGE:$tag" ]] || fail "wrong image tag"
  expected["$tag"]="$digest"
  version_tags+=("$tag")
  for prefix in "$major_minor" "$major" latest; do
    alias_tag="$prefix$suffix"
    alias_tags+=("$alias_tag")
    expected["$alias_tag"]="$digest"
  done
done
# Read all existing tag pointers before any mutation. Existing stable
# version tags can NEVER be rebound to different release content.
for tag in "${version_tags[@]}"; do
  old=$(read_tag_digest "$tag")
  [[ -z "$old" || "$old" == "${expected[$tag]}" ]] || fail "immutable version tag drift: $tag"
  printf 'preflight\t%s\t%s\tOK\n' "$tag" "${expected[$tag]}" >> "$journal"
done
for tag in "${alias_tags[@]}"; do
  prior_alias["$tag"]=$(read_tag_digest "$tag")
  printf 'snapshot\t%s\t%s\tOK\n' "$tag" "${prior_alias[$tag]:--}" >> "$journal"
done
# Phase A: four independent immutable stable tag contracts (still non-atomic).
for tag in "${version_tags[@]}"; do
  old=$(read_tag_digest "$tag")
  if [[ "$old" != "${expected[$tag]}" ]]; then
    mutation_started=1
    crane tag "$IMAGE@${expected[$tag]}" "$tag"
  fi
  [[ "$(read_tag_digest "$tag")" == "${expected[$tag]}" ]] || fail "version readback: $tag"
  printf 'version\t%s\t%s\tVERIFIED\n' "$tag" "${expected[$tag]}" >> "$journal"
done
for tag in "${version_tags[@]}"; do
  [[ "$(read_tag_digest "$tag")" == "${expected[$tag]}" ]] || fail "version group drift: $tag"
done
# Phase B: move aliases only once every stable version tag verifies. If a
# later update fails, restore existing aliases; never delete shared manifests.
for tag in "${alias_tags[@]}"; do
  old=$(read_tag_digest "$tag")
  [[ "$old" == "${prior_alias[$tag]}" ]] || fail "concurrent alias change: $tag"
  if [[ "$old" != "${expected[$tag]}" ]]; then
    changed_aliases+=("$tag")
    mutation_started=1
    crane tag "$IMAGE@${expected[$tag]}" "$tag"
  fi
  [[ "$(read_tag_digest "$tag")" == "${expected[$tag]}" ]] || fail "alias readback: $tag"
  printf 'alias\t%s\t%s\tVERIFIED\n' "$tag" "${expected[$tag]}" >> "$journal"
done
for tag in "${version_tags[@]}" "${alias_tags[@]}"; do
  [[ "$(read_tag_digest "$tag")" == "${expected[$tag]}" ]] || fail "final drift: $tag"
done
printf 'result\t%s\t-\tPROMOTED_FOUR_TARGETS\n' "$RELEASE_TAG" >> "$journal"
echo "::notice::R5 four profiles/aliases verified; journal: $journal"
