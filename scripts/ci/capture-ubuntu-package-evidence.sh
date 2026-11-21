#!/usr/bin/env bash
# Capture the historical Ubuntu package from both native runner architectures.
set -euo pipefail
version="${1:?exact linux-libc-dev version required}"
architecture="${2:?Ubuntu binary architecture required}"
evidence="${3:?evidence directory required}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+\.[0-9]+$ ]]
[[ "$architecture" == amd64 || "$architecture" == arm64 ]]
# The OCI index verified in both original architecture-capture artifacts.
UBUNTU_IMAGE_REF=ubuntu@sha256:d66b366dac61b575bee2aef07e9c26e8070096fbe84a3d4d3eb0da069b5d76db
mkdir -p "$evidence"
printf '%s\n' "$UBUNTU_IMAGE_REF" > "$evidence/ubuntu-base-image.txt"
docker run --rm -i --platform "linux/$architecture" \
  --env UBUNTU_KERNEL_RELEASE="$version" --env TARGET_ARCH="$architecture" \
  --volume "$evidence:/evidence" "$UBUNTU_IMAGE_REF" bash -s <<'BASH'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -qq -y --no-install-recommends "linux-libc-dev=$UBUNTU_KERNEL_RELEASE" >/dev/null
test "$(dpkg-query -W -f='${Version}' linux-libc-dev)" = "$UBUNTU_KERNEL_RELEASE"
test "$(dpkg-query -W -f='${Architecture}' linux-libc-dev)" = "$TARGET_ARCH"
dpkg-query -L linux-libc-dev > /evidence/installed-paths.txt
dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Status}\t${source:Package}\t${source:Version}\n' \
  linux-libc-dev > /evidence/installed-package.txt
apt-cache show "linux-libc-dev=$UBUNTU_KERNEL_RELEASE" > /evidence/apt-package-metadata.txt
apt-cache policy linux-libc-dev > /evidence/apt-policy.txt
apt-cache madison linux-libc-dev > /evidence/apt-madison.txt
mkdir -p /tmp/apt-package-download
chmod 0777 /tmp/apt-package-download
cd /tmp/apt-package-download
apt-get download "linux-libc-dev=$UBUNTU_KERNEL_RELEASE"
mapfile -t packages < <(find . -maxdepth 1 -type f -name "linux-libc-dev_*_$TARGET_ARCH.deb")
(( ${#packages[@]} == 1 ))
sha256sum "$(basename "${packages[0]}")" > /evidence/apt-package-deb-sha256.txt
cp "${packages[0]}" /evidence/
find /var/lib/apt/lists -type f -name '*_Packages*' -print0 | sort -z | \
  xargs -0 -r sha256sum > /evidence/apt-package-index-sha256.txt
find /var/lib/apt/lists -type f -name '*InRelease' -print0 | sort -z | \
  xargs -0 -r sha256sum > /evidence/apt-inrelease-sha256.txt
while IFS= read -r package_path; do
  if [[ -L "$package_path" ]]; then
    printf 'symlink\t%s\t%s\n' "$package_path" "$(readlink -- "$package_path")"
  elif [[ -d "$package_path" ]]; then
    printf 'dir\t%s\t\n' "$package_path"
  elif [[ -f "$package_path" ]]; then
    printf 'file\t%s\t%s\n' "$package_path" "$(sha256sum -- "$package_path" | cut -d ' ' -f1)"
  else
    printf 'Missing installed package path: %s\n' "$package_path" >&2
    exit 3
  fi
done < /evidence/installed-paths.txt | LC_ALL=C sort -t $'\t' -k2,2 > /evidence/installed-content-manifest.tsv
test -s /evidence/installed-content-manifest.tsv
test -s /evidence/apt-package-index-sha256.txt
test -s /evidence/apt-inrelease-sha256.txt
BASH
