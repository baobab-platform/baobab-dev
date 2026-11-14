"""DEV-10 producer/consumer artifact contract regression tests."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/verify_release_artifact_contract.py"
spec = importlib.util.spec_from_file_location("artifact_contract", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class ArtifactContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.tag = "v1.5.2-rc.2"
        for index, target in enumerate(module.TARGETS):
            suffix = "" if target == "final" else "-" + target
            record = {"target": target, "tag": module.BASE + self.tag[1:] + suffix,
                      "digest": "sha256:" + format(index + 1, "064x")}
            (self.directory / (target + ".json")).write_text(json.dumps(record))

    def edit(self, target, change):
        path = self.directory / (target + ".json")
        item = json.loads(path.read_text())
        item.update(change)
        path.write_text(json.dumps(item))

    def test_valid_rc_records(self):
        self.assertEqual(len(module.validate(self.directory, self.tag, "rc")), 4)

    def test_missing_target(self):
        (self.directory / "infra.json").unlink()
        with self.assertRaises(ValueError):
            module.validate(self.directory, self.tag, "rc")

    def test_unexpected_file(self):
        (self.directory / "extra.json").write_text("{}")
        with self.assertRaises(ValueError):
            module.validate(self.directory, self.tag, "rc")

    def test_wrong_tag(self):
        self.edit("final", {"tag": module.BASE + "1.5.1-rc.2"})
        with self.assertRaises(ValueError):
            module.validate(self.directory, self.tag, "rc")

    def test_wrong_target(self):
        self.edit("final", {"target": "infra"})
        with self.assertRaises(ValueError):
            module.validate(self.directory, self.tag, "rc")

    def test_digest_must_be_exact_sha256(self):
        self.edit("final", {"digest": "sha256:deadbeef"})
        with self.assertRaises(ValueError):
            module.validate(self.directory, self.tag, "rc")

    def test_extra_schema_field(self):
        self.edit("final", {"source_sha": "unexpected"})
        with self.assertRaises(ValueError):
            module.validate(self.directory, self.tag, "rc")

    def test_duplicate_json_key(self):
        (self.directory / "final.json").write_text('{"target":"final","target":"infra","tag":"x","digest":"x"}')
        with self.assertRaises(ValueError):
            module.validate(self.directory, self.tag, "rc")

    def test_rc_channel_rejects_stable(self):
        with self.assertRaises(ValueError):
            module.validate(self.directory, "v1.5.2", "rc")

    def test_ga_channel_rejects_rc(self):
        with self.assertRaises(ValueError):
            module.validate(self.directory, self.tag, "ga")

    def test_symlink_rejected(self):
        (self.directory / "infra.json").unlink()
        (self.directory / "infra.json").symlink_to(self.directory / "final.json")
        with self.assertRaises(ValueError):
            module.validate(self.directory, self.tag, "rc")

if __name__ == "__main__":
    unittest.main()
