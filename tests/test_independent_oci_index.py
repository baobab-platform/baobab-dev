"""Independent OCI index verification negative regression tests."""
import importlib.util
import unittest
from pathlib import Path
p=Path(__file__).resolve().parents[1]/"scripts/verify_independent_oci_index.py"
spec=importlib.util.spec_from_file_location("oci_index",p)
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
def index():
    return {"mediaType":"application/vnd.oci.image.index.v1+json",
            "manifests":[{"digest":"sha256:"+"a"*64,
                          "platform":{"os":"linux","architecture":arch}}
                         for arch in ("amd64","arm64")]}
class OCIIndexTests(unittest.TestCase):
    def test_two_architectures(self):
        self.assertTrue(mod.validate(index()))
    def test_missing_arm(self):
        v=index();v["manifests"].pop()
        with self.assertRaises(ValueError):mod.validate(v)
    def test_duplicate(self):
        v=index();v["manifests"].append(v["manifests"][0])
        with self.assertRaises(ValueError):mod.validate(v)
    def test_wrong_digest(self):
        v=index();v["manifests"][0]["digest"]="sha256:abc"
        with self.assertRaises(ValueError):mod.validate(v)
    def test_wrong_platform(self):
        v=index();v["manifests"][1]["platform"]["architecture"]="ppc64le"
        with self.assertRaises(ValueError):mod.validate(v)
    def test_unknown_attestation_allowed(self):
        v=index();v["manifests"].append({"platform":{"os":"unknown","architecture":"unknown"}})
        self.assertTrue(mod.validate(v))
if __name__=="__main__":
    unittest.main()
