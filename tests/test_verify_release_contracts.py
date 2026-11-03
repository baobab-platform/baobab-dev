"""Positive/negative release-contract parsing for DEV-10 R5."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from verify_release_contracts import ContractError, IMAGE, TARGETS, parse_contracts  # noqa: E402

VERSION = "1.5.0"
TAG = "v" + VERSION


def body(targets=TARGETS, version=VERSION):
    chunks = ["### Container Pull Directives"]
    for index, t in enumerate(targets):
        suffix = "" if t == "final" else "-" + t
        chunks.append(
            f"**{t}:**\n\x60\x60\x60bash\ndocker pull {IMAGE}:{version}{suffix}\n"
            f"\x60\x60\x60\n\nVerify (digest \x60sha256:{index + 1:064x}\x60):\n\x60\x60\x60bash\n"
            f"cosign verify {IMAGE}@sha256:{index + 1:064x}\n\x60\x60\x60"
        )
    return "\n".join(chunks)


class ContractTest(unittest.TestCase):
    def test_exact_four(self):
        result = parse_contracts(body(), TAG)
        self.assertEqual([x[0] for x in result], list(TARGETS))

    def test_missing_profile(self):
        with self.assertRaises(ContractError):
            parse_contracts(body(TARGETS[:-1]), TAG)

    def test_duplicate_profile(self):
        with self.assertRaises(ContractError):
            parse_contracts(body(("final", "frontend", "frontend", "infra")), TAG)

    def test_wrong_version_tag(self):
        with self.assertRaises(ContractError):
            parse_contracts(body().replace(f":{VERSION}-infra", ":1.4.0-infra"), TAG)

    def test_foreign_registry(self):
        with self.assertRaises(ContractError):
            parse_contracts(body().replace("ghcr.io/baobab-platform", "ghcr.io/evil"), TAG)

    def test_invalid_digest(self):
        with self.assertRaises(ContractError):
            parse_contracts(body().replace("sha256:" + ("1" * 0) + f"{1:064x}", "sha256:BAD", 1), TAG)

    def test_exact_v150_rc_series_pass_and_bad_prereleases_denied(self):
        for rc in ("1.5.0-rc.1", "1.5.0-rc.2", "1.5.0-rc.10"):
            with self.subTest(rc=rc):
                result = parse_contracts(body(version=rc), "v" + rc)
                self.assertEqual([x[0] for x in result], list(TARGETS))
                self.assertTrue(all(":" + rc in x[1] for x in result))
        for rc in ("v1.5.0-rc.0", "v1.5.0-rc.01", "v1.5.1-rc.1",
                   "v1.5.0-rc.foo", "v1.5.0-rc.1-extra"):
            with self.subTest(rc=rc), self.assertRaises(ContractError):
                parse_contracts(body(version=rc.lstrip("v")), rc)
        # Correct signed release type cannot legitimise GA pull references
        # in a prerelease's own versioned release body.
        with self.assertRaises(ContractError):
            parse_contracts(body(), "v1.5.0-rc.1")

    def test_duplicate_pull_denied(self):
        with self.assertRaises(ContractError):
            parse_contracts(body().replace(
                f"docker pull {IMAGE}:{VERSION}\n",
                f"docker pull {IMAGE}:{VERSION}\ndocker pull {IMAGE}:{VERSION}\n", 1), TAG)


if __name__ == "__main__":
    unittest.main()
