"""Connected RC workflow metadata + four artifact records, without network writes."""
import importlib.util
from pathlib import Path
import tempfile
import json
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("verify_rc_ga_workflow",ROOT/"scripts/verify_rc_ga_workflow.py")
import sys
sys.path.insert(0,str(ROOT/"scripts"))
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)


class ConnectedContinuityTests(unittest.TestCase):
    def test_trusted_success_and_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc=Path(tmp)/"rc";ga=Path(tmp)/"ga";rc.mkdir();ga.mkdir()
            for t in mod.TARGETS:
                suffix="" if t=="final" else "-"+t
                for d,tag in ((rc,"v2.0.0-rc.1"),(ga,"v2.0.0")):
                    (d/(t+".json")).write_text(json.dumps({"target":t,"tag":"ghcr.io/baobab-platform/baobab-dev:"+tag[1:]+suffix,"digest":"sha256:"+"a"*64}))
            run={"status":"completed","conclusion":"success","event":"push","path":".github/workflows/publish.yml@refs/tags/v2.0.0-rc.1","head_branch":"v2.0.0-rc.1","head_sha":"b"*40,"id":123,"html_url":"https://github.com/baobab-platform/baobab-dev/actions/runs/123"}
            self.assertEqual(mod.verify(run,rc,ga,"v2.0.0","b"*40)["result"],"EXACT_DIGEST_CONTINUITY_VERIFIED")
            for field,value in (("conclusion","failure"),("event","workflow_dispatch"),("path","other.yml"),("head_sha","c"*40)):
                bad=dict(run,**{field:value})
                with self.subTest(field=field),self.assertRaises(mod.ContinuityError):
                    mod.verify(bad,rc,ga,"v2.0.0","b"*40)
            (ga/"infra.json").unlink()
            with self.assertRaises(mod.ContinuityError):
                mod.verify(run,rc,ga,"v2.0.0","b"*40)


if __name__=="__main__":
    unittest.main()
