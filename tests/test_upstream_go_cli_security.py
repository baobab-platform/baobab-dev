"""Regression tests: vulnerable gh/cosign release assets must not re-enter images."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class UpstreamGoCliSecurityTests(unittest.TestCase):
    def test_pinned_source_and_fixed_module(self):
        script = (ROOT / "scripts/build-upstream-security-clis.sh").read_text()
        self.assertIn("89d7dcec017194af1d6f8853176b2dae9c1da762", script)
        self.assertIn("0e48502cf5ef34e2e60bbd3617aa19945712f705", script)
        self.assertIn("go get golang.org/x/net@v0.62.0", script)
        self.assertIn("go mod verify", script)
        self.assertIn("go version -m", script)
        self.assertIn("git -C \"$dest\" rev-parse HEAD", script)

    def test_image_uses_rebuilt_binaries(self):
        dockerfile = (ROOT / ".devcontainer/docker/Dockerfile").read_text()
        self.assertIn("RUN bash /build/build-upstream-security-clis.sh", dockerfile)
        self.assertIn("COPY --from=patched-go-clis /out/ /opt/cli-tools/bin/", dockerfile)
        self.assertNotIn('fetch_verify "https://github.com/cli/cli/releases/', dockerfile)
        self.assertNotIn('fetch_verify "https://github.com/sigstore/cosign/releases/', dockerfile)


if __name__ == "__main__":
    unittest.main()
