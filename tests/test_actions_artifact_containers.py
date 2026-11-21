"""Negative regression coverage for GitHub Actions artifact-container boundaries."""
import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/verify_actions_artifact_containers.py"
spec = importlib.util.spec_from_file_location("actions_artifacts", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

SHA = "a" * 40
RUN = 12345

def item(name, run=RUN, sha=SHA, expired=False):
    return {"id": len(name) + 1, "name": name, "expired": expired,
            "workflow_run": {"id": run, "head_sha": sha}}

class ActionsArtifactTests(unittest.TestCase):
    def rc(self):
        return {"artifacts": [item(name) for name in sorted(mod.RC_NAMES)]}

    def test_rc_complete(self):
        self.assertEqual(set(mod.validate(self.rc(), "rc", RUN, SHA)), mod.RC_NAMES)

    def test_paginated_rc(self):
        entries = self.rc()["artifacts"]
        self.assertEqual(len(mod.validate([{"artifacts": entries[:2]}, {"artifacts": entries[2:]}],
                                          "rc", RUN, SHA)), 4)

    def test_ga_complete(self):
        self.assertEqual(mod.validate({"artifacts": [item("ga-reused-candidates")]},
                                      "ga", RUN, SHA), ["ga-reused-candidates"])

    def test_missing(self):
        payload = self.rc()
        payload["artifacts"].pop()
        with self.assertRaises(ValueError):
            mod.validate(payload, "rc", RUN, SHA)

    def test_duplicate(self):
        payload = self.rc()
        payload["artifacts"].append(payload["artifacts"][0].copy())
        with self.assertRaises(ValueError):
            mod.validate(payload, "rc", RUN, SHA)

    def test_unknown_target(self):
        payload = self.rc()
        payload["artifacts"].append(item("published-info-unknown"))
        with self.assertRaises(ValueError):
            mod.validate(payload, "rc", RUN, SHA)

    def test_wrong_producer(self):
        payload = self.rc()
        payload["artifacts"][0]["workflow_run"]["id"] = RUN + 1
        with self.assertRaises(ValueError):
            mod.validate(payload, "rc", RUN, SHA)

    def test_wrong_sha(self):
        payload = self.rc()
        payload["artifacts"][0]["workflow_run"]["head_sha"] = "b" * 40
        with self.assertRaises(ValueError):
            mod.validate(payload, "rc", RUN, SHA)

    def test_expired(self):
        payload = self.rc()
        payload["artifacts"][0]["expired"] = True
        with self.assertRaises(ValueError):
            mod.validate(payload, "rc", RUN, SHA)

if __name__ == "__main__":
    unittest.main()
