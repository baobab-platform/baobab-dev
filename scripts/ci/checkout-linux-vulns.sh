#!/usr/bin/env bash
# Fetch one immutable upstream vulnerability-tracker commit and only CVE year trees.
set -euo pipefail
sha="${1:?immutable upstream commit required}"
inventory="${2:?CVE inventory TSV required}"
destination="${3:?checkout destination required}"
[[ "$sha" =~ ^[a-f0-9]{40}$ ]] || { echo "Invalid upstream tracker SHA" >&2; exit 2; }
test -s "$inventory"
repo_url=https://kernel.googlesource.com/pub/scm/linux/security/vulns
mkdir -p "$destination"
[[ -z "$(ls -A -- "$destination")" ]] || {
  echo "Upstream checkout destination must be empty" >&2
  exit 2
}
git -C "$destination" init -q
git -C "$destination" remote add origin "$repo_url"
for attempt in 1 2 3; do
  if timeout 180 git -C "$destination" -c protocol.version=2 fetch --filter=blob:none --no-tags --depth=1 origin "$sha"; then
    break
  fi
  if (( attempt == 3 )); then
    echo "::error::Immutable upstream Linux CVE fetch failed after 3 attempts" >&2
    exit 1
  fi
  sleep "$((2 ** attempt))"
done
git -C "$destination" sparse-checkout init --cone
mapfile -t years < <(tail -n +2 "$inventory" | cut -f1 \
  | sed -nE 's/^CVE-([0-9]{4})-[0-9]{4,}$/\1/p' | sort -u)
(("${#years[@]}" > 0)) || { echo "No CVE publication years in inventory" >&2; exit 2; }
paths=()
for year in "${years[@]}"; do paths+=("cve/published/$year"); done
git -C "$destination" sparse-checkout set "${paths[@]}"
git -C "$destination" checkout --detach --quiet FETCH_HEAD
[[ "$(git -C "$destination" rev-parse HEAD)" == "$sha" ]] || {
  echo "Fetched upstream tracker commit mismatch" >&2
  exit 1
}
while IFS=$'\t' read -r cve _; do
  [[ "$cve" =~ ^CVE-[0-9]{4}-[0-9]{4,}$ ]] || continue
  test -s "$destination/cve/published/${cve:4:4}/$cve.json" || {
    echo "::error::Missing immutable upstream CNA record: $cve" >&2
    exit 1
  }
done < "$inventory"
echo "UPSTREAM_ROOT=$destination" >> "$GITHUB_ENV"
echo "Verified upstream tracker commit: $sha"
