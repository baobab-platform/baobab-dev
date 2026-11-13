"""DEV-10 PROM-02 exact RC-to-GA identity tests."""
import importlib.util
from pathlib import Path
from copy import deepcopy
import unittest

p = Path(__file__).resolve().parents[1] / "scripts/verify_rc_ga_continuity.py"
spec = importlib.util.spec_from_file_location("continuity", p)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
targets = ("final", "frontend", "frontend-e2e", "infra")


class ContinuityTests(unittest.TestCase):
    def setUp(self):
        self.rc = dict(release_tag="v2.0.0-rc.3", source_sha="a"*40,
                       qualified=True, qualification_ref="qualification/123",
                       run_id=123, images={t:"sha256:"+str(i+1)*64 for i,t in enumerate(targets)})
        self.ga = dict(release_tag="v2.0.0", source_sha="a"*40,
                       images=deepcopy(self.rc["images"]))

    def test_identical_qualified_images(self):
        self.assertEqual(m.qualify(self.rc,self.ga)["result"],"EXACT_DIGEST_CONTINUITY_VERIFIED")

    def test_negative_cases(self):
        for field, value in (("qualified",False),("qualification_ref",""),("run_id",None),
                             ("source_sha","b"*40),("release_tag","v2.0.1-rc.1")):
            with self.subTest(field=field):
                rc=deepcopy(self.rc);rc[field]=value
                with self.assertRaises(m.ContinuityError):m.qualify(rc,self.ga)
        for target in targets:
            ga=deepcopy(self.ga);ga["images"][target]="sha256:"+"f"*64
            with self.subTest(target=target),self.assertRaises(m.ContinuityError):
                m.qualify(self.rc,ga)
        ga=deepcopy(self.ga);del ga["images"]["infra"]
        with self.assertRaises(m.ContinuityError):m.qualify(self.rc,ga)


if __name__=="__main__":
    unittest.main()
