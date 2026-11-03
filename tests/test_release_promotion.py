"""R5 promotion negative tests exercise registry logic without publishing images."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/promote_release_tags.sh"
IMAGE = "ghcr.io/baobab-platform/baobab-dev"
TARGETS = ("final", "frontend", "frontend-e2e", "infra")
DIGESTS = {"final": "a" * 64, "frontend": "b" * 64,
           "frontend-e2e": "c" * 64, "infra": "d" * 64}

# A throwaway CLI implementation. The only state modified is a temp JSON file.
FAKE_CRANE = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
store = pathlib.Path(os.environ["MOCK_CRANE_STATE"])
state = json.loads(store.read_text())
command = sys.argv[1]
if command == "digest":
    name = sys.argv[2].rsplit(":", 1)[-1]
    if name not in state:
        print("MANIFEST_UNKNOWN", file=sys.stderr)
        sys.exit(1)
    print(state[name])
elif command == "tag":
    ref, name = sys.argv[2:4]
    if name == os.environ.get("MOCK_FAIL_ONCE"):
        fail_flag = store.parent / "failed-once"
        if not fail_flag.exists():
            fail_flag.write_text(name)
            print("simulated GHCR tag write rejection", file=sys.stderr)
            sys.exit(23)
    state[name] = ref.rsplit("@", 1)[-1]
    store.write_text(json.dumps(state, sort_keys=True))
else:
    sys.exit(43)
'''


@unittest.skipUnless(shutil.which("jq") and shutil.which("bash"),
                     "requires ordinary GitHub-hosted runner jq and bash")
class PromotionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        crane = self.bin / "crane"
        crane.write_text(FAKE_CRANE)
        crane.chmod(0o755)
        self.info = self.root / "candidates"
        self.info.mkdir()
        self.state_path = self.root / "state.json"
        self.previous = "sha256:" + "e" * 64
        self.state = {}
        for target in TARGETS:
            suffix = "" if target == "final" else "-" + target
            record = {"target": target, "tag": IMAGE + ":1.5.0" + suffix,
                      "digest": "sha256:" + DIGESTS[target]}
            (self.info / (target + ".json")).write_text(json.dumps(record))
            for prefix in ("1", "latest"):
                self.state[prefix + suffix] = self.previous
        self.state_path.write_text(json.dumps(self.state))
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                        MOCK_CRANE_STATE=str(self.state_path), RELEASE_TAG="v1.5.0",
                        IMAGE=IMAGE, INFO_DIR=str(self.info),
                        PROMOTION_EVIDENCE_DIR=str(self.root / "evidence"))

    def run_promotion(self, **updates):
        return subprocess.run(["bash", str(SCRIPT)], env=dict(self.env, **updates),
                              capture_output=True, text=True, timeout=15)

    def change_test_release(self, version: str):
        # Test future full-alias behaviour entirely against mock CLI state.
        for target in TARGETS:
            record = self.info / (target + ".json")
            obj = json.loads(record.read_text())
            suffix = "" if target == "final" else "-" + target
            obj["tag"] = IMAGE + ":" + version.removeprefix("v") + suffix
            record.write_text(json.dumps(obj))
        self.env["RELEASE_TAG"] = version

    def test_bash_syntax(self):
        result = subprocess.run(["bash", "-n", str(SCRIPT)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_v150_promotion_only_explicit_version_tags_and_idempotent_rerun(self):
        for _ in range(2):
            result = self.run_promotion()
            self.assertEqual(result.returncode, 0, result.stderr)
        state = json.loads(self.state_path.read_text())
        for target in TARGETS:
            suffix = "" if target == "final" else "-" + target
            self.assertEqual(state["1.5.0" + suffix],
                             "sha256:" + DIGESTS[target])
            self.assertNotIn("1.5" + suffix, state)
            self.assertEqual(state["1" + suffix], self.previous)
            self.assertEqual(state["latest" + suffix], self.previous)
        journal = (self.root / "evidence/promotion.tsv").read_text()
        self.assertIn("PROMOTED_FOUR_PINNED_DEV_VERSIONS_NO_ALIASES", journal)
        self.assertNotIn("\talias\t", journal)

    def test_future_versions_preserve_normal_alias_promotion(self):
        self.change_test_release("v1.6.0")
        result = self.run_promotion()
        self.assertEqual(result.returncode, 0, result.stderr)
        state = json.loads(self.state_path.read_text())
        for target in TARGETS:
            suffix = "" if target == "final" else "-" + target
            for tag in ("1.6.0", "1.6", "1", "latest"):
                self.assertEqual(state[tag + suffix], "sha256:" + DIGESTS[target])
        self.assertIn("PROMOTED_FOUR_TARGETS",
                      (self.root / "evidence/promotion.tsv").read_text())

    def test_immutable_version_tag_rebind_is_blocked(self):
        self.state["1.5.0"] = self.previous
        self.state_path.write_text(json.dumps(self.state))
        result = self.run_promotion()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("immutable version tag", result.stderr)
        self.assertEqual(json.loads(self.state_path.read_text()), self.state)

    def test_late_alias_failure_restores_existing_moving_aliases(self):
        self.change_test_release("v1.6.0")
        result = self.run_promotion(MOCK_FAIL_ONCE="latest-frontend")
        self.assertNotEqual(result.returncode, 0)
        after = json.loads(self.state_path.read_text())
        self.assertEqual(after["1"], self.previous)
        self.assertEqual(after["latest"], self.previous)
        self.assertEqual(after["1-frontend"], self.previous)
        journal = (self.root / "evidence/promotion.tsv").read_text()
        self.assertIn("RESTORED", journal)
        self.assertIn("MANUAL_RECOVERY_NEW_ALIAS", journal)
        self.assertIn("PARTIAL GHCR PROMOTION", result.stderr)

    def test_invalid_candidate_ref_or_prerelease_is_blocked(self):
        broken = self.info / "infra.json"
        obj = json.loads(broken.read_text())
        obj["tag"] = "ghcr.io/attacker/image:1.5.0-infra"
        broken.write_text(json.dumps(obj))
        self.assertNotEqual(self.run_promotion().returncode, 0)
        self.assertNotEqual(self.run_promotion(RELEASE_TAG="v1.5.0-rc.1").returncode, 0)


if __name__ == "__main__":
    unittest.main()
