"""DEV-10 immutable remote tag identity regression tests."""
import importlib.util
import unittest
from pathlib import Path
SCRIPT=Path(__file__).resolve().parents[1]/"scripts/verify_remote_release_tag.py"
spec=importlib.util.spec_from_file_location("remote_tag",SCRIPT)
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
SHA="a"*40
TAG="v1.5.2-rc.2"
REF="refs/tags/"+TAG

class RemoteTagTests(unittest.TestCase):
    def test_lightweight(self):
        self.assertEqual(mod.assert_tag_identity(TAG,SHA,f"{SHA}\t{REF}\n"),SHA)
    def test_annotated(self):
        advertised = f"{'b'*40}\t{REF}\n{SHA}\t{REF}^{{}}\n"
        self.assertEqual(mod.resolved_tag_identity(TAG, advertised), SHA)
        self.assertEqual(mod.assert_tag_identity(TAG, SHA, advertised), SHA)
    def test_moved_tag_refused(self):
        with self.assertRaises(ValueError):
            mod.assert_tag_identity(TAG,SHA,f"{'b'*40}\t{REF}\n")
    def test_missing_tag_refused(self):
        with self.assertRaises(ValueError):
            mod.assert_tag_identity(TAG,SHA,"")
    def test_duplicate_ref_refused(self):
        with self.assertRaises(ValueError):
            mod.assert_tag_identity(TAG,SHA,f"{SHA}\t{REF}\n{SHA}\t{REF}\n")
    def test_unexpected_ref_refused(self):
        with self.assertRaises(ValueError):
            mod.assert_tag_identity(TAG,SHA,f"{SHA}\t{REF}\n{SHA}\trefs/tags/other\n")
    def test_malformed_sha_refused(self):
        with self.assertRaises(ValueError):
            mod.assert_tag_identity(TAG,SHA,f"not-a-sha\t{REF}\n")
if __name__=="__main__":
    unittest.main()
