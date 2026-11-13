"""GA release uses exact qualified RC digests and refuses changed records."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
spec=importlib.util.spec_from_file_location("prepare_ga_reuse",ROOT/"scripts/prepare_ga_reuse.py")
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class GAReuseTests(unittest.TestCase):
    def test_reuse_and_refusals(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);rc=root/"rc";out=root/"ga";rc.mkdir()
            for t in m.TARGETS:
                suffix="" if t=="final" else "-"+t
                (rc/(t+".json")).write_text(json.dumps({"target":t,
                    "tag":"ghcr.io/baobab-platform/baobab-dev:2.0.0-rc.1"+suffix,
                    "digest":"sha256:"+"a"*64}))
            run={"status":"completed","conclusion":"success","event":"push",
                 "path":".github/workflows/publish.yml@refs/tags/v2.0.0-rc.1",
                 "head_sha":"b"*40,"head_branch":"v2.0.0-rc.1",
                 "html_url":"https://github.com/example/actions/runs/123","id":123}
            result=m.prepare(run,rc,"v2.0.0","b"*40,out)
            self.assertEqual(result["result"],"EXACT_DIGEST_CONTINUITY_VERIFIED")
            self.assertEqual(json.loads((out/"infra.json").read_text())["digest"],"sha256:"+"a"*64)
            for field,value in (("conclusion","failure"),("head_sha","c"*40),
                                ("event","workflow_dispatch"),("path","wrong.yml")):
                with self.subTest(field=field),self.assertRaises(m.ContinuityError):
                    m.prepare({**run,field:value},rc,"v2.0.0","b"*40,root/"bad")
            with self.assertRaises(m.ContinuityError):
                m.prepare(run,rc,"v2.0.1","b"*40,root/"bad")


if __name__=="__main__":
    unittest.main()
