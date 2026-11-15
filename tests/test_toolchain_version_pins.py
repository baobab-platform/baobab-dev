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
            "PNPM_VERSION": "pnpm",
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


if __name__ == "__main__":
    unittest.main()
