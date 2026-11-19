#!/usr/bin/env bash
# Read back the exact built image on its native runner.
set -euo pipefail
image="${1:?image required}"
target="${2:?Dockerfile target required}"
platform="${3:?platform required}"
evidence="${4:?evidence directory required}"
source_sha="${GITHUB_SHA:?immutable checkout SHA required}"
case "$target" in
    final) profile=full ;;
    frontend|frontend-e2e|infra) profile="$target" ;;
    *) echo "Unsupported image target: $target" >&2; exit 2 ;;
esac
case "$platform:$(uname -m)" in
    linux/amd64:x86_64|linux/arm64:aarch64) ;;
    *) echo "Native $platform runner required" >&2; exit 2 ;;
esac

mkdir -p "$evidence"
inspect=$(docker image inspect "$image")
image_id=$(jq -er --arg source "$source_sha" --arg platform "$platform" '
    .[0] | select(.Config.Labels["org.opencontainers.image.revision"] == $source
        and "\(.Os)/\(.Architecture)" == $platform) | .Id
' <<< "$inspect")
[[ "$image_id" =~ ^sha256:[a-f0-9]{64}$ ]]
if [[ -n "${EXPECTED_CONFIG_DIGEST:-}" && "$image_id" != "$EXPECTED_CONFIG_DIGEST" ]]; then
    echo "Local runtime image differs from the scanned image" >&2
    exit 1
fi
lock_sha=$(sha256sum config/versions.lock | cut -d ' ' -f1)
# shellcheck disable=SC1091
. config/versions.lock
base_digest="sha256:${UBUNTU_BASE_SHA256:?locked Ubuntu digest required}"
jq -e --arg expected "$base_digest" '.[0].Config.Labels["org.opencontainers.image.base.digest"] == $expected' \
    <<< "$inspect" >/dev/null
container=$(docker create --network none --platform "$platform" "$image_id")
trap 'docker rm -f "$container" >/dev/null' EXIT
docker start "$container" >/dev/null

docker exec -i "$container" bash -s -- "$profile" "$lock_sha" <<'SH' | tee "$evidence/runtime.log"
set -euo pipefail
test "$(id -u)" -ne 0
test "$BAOBAB_BUILD_PROFILE" = "$1"
lock="${BAOBAB_CONFIG_DIR}/versions.lock"
printf '%s  %s\n' "$2" "$lock" | sha256sum --check --strict
. "$lock"
arch="$(dpkg --print-architecture)"
verify_package() {
    local actual
    actual=$(dpkg-query -W -f='${Version}' "$1")
    printf '%s %s\n' "$1" "$actual"
    test "$actual" = "$2"
}
verify_package linux-libc-dev "$LINUX_LIBC_DEV_APT_VERSION"
if [[ "$1" != infra ]]; then
    verify_package nodejs "${NODE_VERSION}-1nodesource1"
    node --version
fi
if [[ "$1" == full || "$1" == infra ]]; then
    verify_package docker-ce-cli "$DOCKER_APT_VERSION"
fi
if [[ "$1" == full ]]; then
    java_version="JAVA_APT_VERSION_${arch^^}"
    verify_package "temurin-${JAVA_MAJOR}-jdk" "${!java_version}"
    verify_package "postgresql-client-${POSTGRES_MAJOR}" "$POSTGRES_APT_VERSION"
    test "$(python3 --version)" = "Python $PYTHON_VERSION"
    maven=$(mvn --version)
    printf '%s\n' "$maven"
    grep -Fq "Apache Maven $MAVEN_VERSION " <<< "$maven"
    scratch=$(mktemp -d)
    trap 'rm -rf "$scratch"' EXIT
    printf 'public class Probe { public static void main(String[] args) {} }\n' > "$scratch/Probe.java"
    javac -d "$scratch" "$scratch/Probe.java"
    java -classpath "$scratch" Probe
fi
if [[ "$1" == infra ]]; then
    aws_version=$(aws --version)
    printf '%s\n' "$aws_version"
    test "${aws_version%% *}" = "aws-cli/$AWS_CLI_VERSION"
fi
baobab-verify
if [[ "$1" == frontend-e2e ]]; then
    playwright install --list
fi
SH

docker exec "$container" dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\n' |
    LC_ALL=C sort > "$evidence/apt-packages.tsv"

deadline=$((SECONDS + 75))
while :; do
    health=$(docker inspect --format '{{.State.Status}}/{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$container")
    case "$health" in
        running/healthy) break ;;
        running/starting)
            if (( SECONDS >= deadline )); then
                echo "Image failed to reach healthy state" >&2
                exit 1
            fi
            sleep 3 ;;
        *) echo "Unexpected image health: $health" >&2; exit 1 ;;
    esac
done

if [[ "$target" != infra ]]; then
    bash scripts/qualify-pnpm-provisioning.sh "$image_id" "$PNPM_VERSION" | tee "$evidence/pnpm.log"
fi
jq -n --arg reference "$image" --arg config "$image_id" --arg source "$source_sha" \
    --arg platform "$platform" --arg profile "$profile" --arg lock "$lock_sha" \
    --arg archive "${SCAN_ARCHIVE_SHA256:-}" --arg base "$base_digest" \
    --arg apt "$(sha256sum "$evidence/apt-packages.tsv" | cut -d ' ' -f1)" '
    {schema: "baobab.dev10.native-image.v1", image_reference: $reference, image_config_digest: $config,
     source_sha: $source, platform: $platform, profile: $profile, lock_sha256: $lock, ubuntu_base: $base,
     scan_archive_sha256: (if $archive == "" then null else $archive end), apt_inventory_sha256: $apt,
     health: "healthy", runtime: "passed"}
' > "$evidence/native-image.json"
