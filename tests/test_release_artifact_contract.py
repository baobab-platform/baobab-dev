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

    def make_ga(self, signer_tag="v1.5.2-rc.2", signer_run_id=123):
        ga_tag = "v1.5.2"
        for target in module.TARGETS:
            path = self.directory / (target + ".json")
            record = json.loads(path.read_text())
            suffix = "" if target == "final" else "-" + target
            record.update(tag=module.BASE + ga_tag[1:] + suffix,
                          signer_tag=signer_tag, signer_run_id=signer_run_id)
            path.write_text(json.dumps(record))
        return ga_tag

    def edit(self, target, change):
        path = self.directory / (target + ".json")
        item = json.loads(path.read_text())
        item.update(change)
        path.write_text(json.dumps(item))

    def test_valid_rc_records(self):
        self.assertEqual(len(module.validate(self.directory, self.tag, "rc")), 4)

    def test_valid_ga_records_bind_one_qualified_rc_run(self):
        ga_tag = self.make_ga()
        self.assertEqual(len(module.validate(self.directory, ga_tag, "ga")), 4)

    def test_ga_rejects_wrong_version_or_malformed_signer(self):
        for signer in ("v1.5.1-rc.2", "v1.5.2-rc.0", "v1.5.2-rc.02", "v1.5.2"):
            with self.subTest(signer=signer):
                self.make_ga(signer_tag=signer)
                with self.assertRaises(ValueError):
                    module.validate(self.directory, "v1.5.2", "ga")

    def test_ga_rejects_invalid_or_inconsistent_run_id(self):
        self.make_ga(signer_run_id=True)
        with self.assertRaises(ValueError):
            module.validate(self.directory, "v1.5.2", "ga")
        self.make_ga()
        self.edit("infra", {"signer_run_id": 124})
        with self.assertRaises(ValueError):
            module.validate(self.directory, "v1.5.2", "ga")

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
