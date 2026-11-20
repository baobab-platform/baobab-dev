#!/usr/bin/env bash
# Capture the installed linux-libc-dev package from the immutable published image.
set -euo pipefail
: "${EXPECTED_ARCHITECTURE:?expected image architecture is required}"
: "${EXPECTED_LINUX_LIBC_DEV_VERSION:?expected linux-libc-dev version is required}"
output="${1:-/evidence}"
mkdir -p "$output"
package_record="$(dpkg-query -W -f='${Status}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n' linux-libc-dev)"
IFS=$'\t' read -r package_status package_version package_arch source_package source_version <<< "$package_record"
[[ "$package_status" == "install ok installed" ]] || { echo "linux-libc-dev is not installed: $package_status" >&2; exit 2; }
[[ "$package_version" == "$EXPECTED_LINUX_LIBC_DEV_VERSION" && "$source_version" == "$EXPECTED_LINUX_LIBC_DEV_VERSION" && "$source_package" == "linux" && "$package_arch" == "$EXPECTED_ARCHITECTURE" ]] || {
  printf 'Unexpected linux-libc-dev identity: status=%s version=%s arch=%s source=%s source_version=%s\n' "$package_status" "$package_version" "$package_arch" "$source_package" "$source_version" >&2
  exit 2
}
{
  printf 'status\tversion\tarchitecture\tsource_package\tsource_version\n'
  printf '%s\n' "$package_record"
} > "$output/linux-libc-dev.package.tsv"
{
  printf 'path\tkind\tsha256\tlink_target\n'
  while IFS= read -r package_path; do
    [[ -n "$package_path" ]] || continue
    if [[ -L "$package_path" ]]; then
      printf '%s\tsymlink\t\t%s\n' "$package_path" "$(readlink -- "$package_path")"
    elif [[ -f "$package_path" ]]; then
      printf '%s\tfile\t%s\t\n' "$package_path" "$(sha256sum -- "$package_path" | cut -d ' ' -f 1)"
    elif [[ -d "$package_path" ]]; then
      printf '%s\tdirectory\t\t\n' "$package_path"
    else
      printf '%s\tmissing\t\t\n' "$package_path"
    fi
  done < <(dpkg-query -L linux-libc-dev | LC_ALL=C sort -u)
} > "$output/linux-libc-dev.manifest.tsv"
echo "Captured linux-libc-dev $package_version ($package_arch) payload paths: $(($(wc -l < "$output/linux-libc-dev.manifest.tsv") - 1))"
