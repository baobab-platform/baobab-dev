"""Static contract checks preventing toolchain manifest/lock/image drift."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


def read(relative):
    return (ROOT / relative).read_text(encoding="utf-8")


class ToolchainVersionPinTests(unittest.TestCase):
    def test_yarn_is_exact_in_manifest_lock_image_and_verifier(self):
        manifest = read("config/versions.yaml")
        lock = read("config/versions.lock")
        resolver = read("config/resolve.sh")
        dockerfile = read(".devcontainer/docker/Dockerfile")
        verifier = read("scripts/verify.sh")

        self.assertRegex(
            manifest,
            r'(?m)^  yarn:\n    version: "4\.18\.1"\n    source: "corepack"$',
        )
        self.assertIn("export YARN_VERSION=4.18.1", lock)
        self.assertIn("YARN_VERSION=$(yaml '.package_managers.yarn.version')", resolver)
        self.assertIn("export YARN_VERSION=${YARN_VERSION}", resolver)
        self.assertIn('corepack prepare "yarn@${YARN_VERSION}" --activate', dockerfile)
        self.assertNotIn("corepack prepare yarn@stable", dockerfile)
        self.assertIn('check_exact_version "Yarn" yarn "${YARN_VERSION}"', verifier)

    def test_security_rebuild_versions_match_manifest_and_lock(self):
        manifest = read("config/versions.yaml")
        lock = read("config/versions.lock")
        rebuild = read("scripts/build-security-clis.sh")
        for key, version in (("task", "3.54.0"), ("yq", "4.54.1")):
            section = manifest.split(f"  {key}:", 1)[1]
            section = re.split(r"(?m)^  [A-Za-z0-9_-]+:", section, maxsplit=1)[0]
            self.assertIn(f'    version: "{version}"', section)
            self.assertRegex(lock, rf"(?m)^export {key.upper()}_VERSION={re.escape(version)}$")
        self.assertIn('[[ "$TASK_VERSION" == 3.54.0 && "$YQ_VERSION" == 4.54.1 ]]', rebuild)

    def test_upstream_security_cli_rebuilds_embed_locked_release_metadata(self):
        lock = read("config/versions.lock")
        rebuild = read("scripts/build-upstream-security-clis.sh")
        dockerfile = read(".devcontainer/docker/Dockerfile")

        self.assertIn("export GH_VERSION=2.102.1", lock)
        self.assertIn("export COSIGN_VERSION=3.1.4", lock)
        self.assertIn(". /build/versions.lock", rebuild)
        self.assertIn('git -C "$dest" fetch --depth 1 origin "refs/tags/v$version"', rebuild)
        self.assertIn("go run script/build.go bin/gh", rebuild)
        self.assertIn("mkdir -p bin", rebuild)
        self.assertIn('"GH_VERSION=$GH_VERSION"', rebuild)
        self.assertIn('"SOURCE_DATE_EPOCH=$source_date_epoch"', rebuild)
        self.assertIn("GOFLAGS=-buildvcs=false make", rebuild)
        self.assertIn('"GIT_VERSION=v$COSIGN_VERSION"', rebuild)
        self.assertIn('"SOURCE_DATE_EPOCH=$source_date_epoch"', rebuild)
        self.assertIn("cosign", rebuild)
        self.assertIn('assert_version_field GitVersion "v$COSIGN_VERSION"', rebuild)
        self.assertIn('assert_version_field GitCommit "$commit"', rebuild)
        self.assertIn("assert_version_field GitTreeState dirty", rebuild)
        self.assertIn('assert_version_field BuildDate "$expected_build_date"', rebuild)
        self.assertIn('grep -F "gh version $GH_VERSION"', rebuild)
        self.assertNotIn('grep -F "v$COSIGN_VERSION" /out/cosign.version', rebuild)
        self.assertIn("apt-get install -y --no-install-recommends ca-certificates curl tar git make", dockerfile)

    def test_flutter_runtime_caches_are_writable_without_full_sdk_chown(self):
        dockerfile = read(".devcontainer/docker/Dockerfile")
        self.assertIn(
            "COPY --chown=1000:1000 --from=flutter-sdk /opt/flutter-tmp /opt/flutter",
            dockerfile,
        )
        flutter_preload = dockerfile.split(
            "RUN git config --system --add safe.directory /opt/flutter", 1
        )[1].split("# 6. PostgreSQL", 1)[0]
        self.assertIn("mkdir -p /opt/flutter/bin/cache /opt/flutter/.pub-cache", flutter_preload)
        self.assertIn(
            "chown -R 1000:1000 /opt/flutter/bin/cache /opt/flutter/.pub-cache",
            flutter_preload,
        )
        self.assertNotIn("RUN chown -R vscode:vscode /opt/flutter", dockerfile)
        # The build-time verifier runs as vscode and exercises flutter/dart
        # version commands, which update the engine stamp in bin/cache.
        self.assertIn("RUN baobab-verify", dockerfile)

    def test_locked_runtime_and_package_managers_are_checked_exactly(self):
        lock = read("config/versions.lock")
        verifier = read("scripts/verify.sh")
        expected = {
            "NODE_VERSION": "26.13.1",
            "NPM_VERSION": "12.2.1",
            "PNPM_VERSION": "12.21.0",
            "COREPACK_VERSION": "0.36.0",
            "YARN_VERSION": "4.18.1",
            "TASK_VERSION": "3.54.0",
            "YQ_VERSION": "4.54.1",
            "GH_VERSION": "2.102.1",
            "COSIGN_VERSION": "3.1.4",
            "PLAYWRIGHT_VERSION": "1.65.0",
        }
        labels = {
            "NODE_VERSION": "Node.js",
            "NPM_VERSION": "npm",
            "PNPM_VERSION": "Image pnpm",
            "COREPACK_VERSION": "Corepack",
            "YARN_VERSION": "Yarn",
            "TASK_VERSION": "Task",
            "YQ_VERSION": "yq",
            "GH_VERSION": "GitHub CLI",
            "COSIGN_VERSION": "Cosign",
            "PLAYWRIGHT_VERSION": "Playwright",
        }
        for name, version in expected.items():
            with self.subTest(name=name):
                self.assertRegex(lock, rf"(?m)^export {name}={re.escape(version)}$")
                self.assertIn(f'check_exact_version "{labels[name]}"', verifier)

        self.assertIn("check_project_pnpm", verifier)
        self.assertIn("offline Corepack cache unavailable", verifier)
        self.assertIn(
            """if [[ ! -f package.json || ! -f pnpm-lock.yaml ]]; then
        return 0
    fi""",
            verifier,
        )
        helper = read("scripts/project-pnpm.sh")
        self.assertIn("COREPACK_ENABLE_NETWORK=1", helper)
        self.assertIn("COREPACK_ENABLE_NETWORK=0", helper)
        self.assertIn("COREPACK_ENV_FILE=0", helper)
        self.assertIn("COREPACK_ENABLE_PROJECT_SPEC=1", helper)
        self.assertIn("COREPACK_ENABLE_STRICT=1", helper)
        self.assertIn("COREPACK_ENABLE_AUTO_PIN=0", helper)
        self.assertIn("env -u COREPACK_INTEGRITY_KEYS", helper)
        self.assertIn("COREPACK_ON_UNVERIFIED_DOWNLOAD=error", helper)
        dockerfile = read(".devcontainer/docker/Dockerfile")
        self.assertIn(
            "COPY --chmod=0755 scripts/project-pnpm.sh /usr/local/bin/baobab-project-pnpm",
            dockerfile,
        )


    def test_docs_workflow_uses_locked_yq_and_uv_versions(self):
        lock = read("config/versions.lock")
        pyproject = read("pyproject.toml")
        pages = read(".github/workflows/pages.yml")

        uv_version = re.search(r"(?m)^export UV_VERSION=([0-9.]+)$", lock)
        self.assertIsNotNone(uv_version)
        self.assertIn(
            f'required-version = "=={uv_version.group(1)}"',
            pyproject,
        )
        self.assertIn("Install locked yq", pages)
        self.assertIn("source config/versions.lock", pages)
        self.assertIn("YQ_ASSET_AMD64", pages)
        self.assertIn("YQ_SHA256_AMD64", pages)
        self.assertIn("YQ_ASSET_ARM64", pages)
        self.assertIn("YQ_SHA256_ARM64", pages)
        self.assertIn("sha256sum -c -", pages)
        self.assertIn('echo "${install_dir}" >> "${GITHUB_PATH}"', pages)


if __name__ == "__main__":
    unittest.main()
