"""Negative tests for digest-bound, time-limited DEV-10 security exceptions."""
import datetime as dt
import importlib.util
import unittest
from pathlib import Path
p=Path(__file__).resolve().parents[1]/"scripts/verify_digest_security_decision.py"
spec=importlib.util.spec_from_file_location("security_decision",p)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
NOW=dt.datetime(2026,11,14,tzinfo=dt.timezone.utc)
DIGEST="sha256:"+"a"*64
PKG={"name":"openssl","version":"1.2.3","type":"os"}
REPORT={"Results":[{"Packages":[{"Name":"openssl","Version":"1.2.3"}],"Vulnerabilities":[{"Severity":"HIGH","VulnerabilityID":"CVE-2026-12345","PkgName":"openssl","InstalledVersion":"1.2.3"}]}]}
def decision():
    return {"schema_version":1,"release_tag":"v1.5.2-rc.1","target":"final","digest":DIGEST,
            "package_inventory":[dict(PKG)],"inventory_sha256":m.inventory_hash([PKG]),
            "exceptions":[{"cve":"CVE-2026-12345","package":"openssl",
                           "installed_version":"1.2.3","justification":"Reviewed temporary mitigation"}],
            "approver":"security-reviewer","approved_at":"2026-11-13T00:00:00Z",
            "expires_at":"2026-11-20T00:00:00Z","evidence_url":"https://github.com/baobab-platform/baobab-dev/issues/54"}
def verify(d,report=REPORT,tag="v1.5.2-rc.1",digest=DIGEST):
    return m.validate(d,report,target="final",digest=digest,release_tag=tag,now=NOW)
class SecurityDecisionTests(unittest.TestCase):
    def test_valid(self):self.assertEqual(verify(decision())["status"],"approved-exact-digest")
    def test_clean_no_exception(self):self.assertEqual(verify(None,{"Results":[]})["status"],"no-high-critical-findings")
    def test_missing_decision(self):
        with self.assertRaises(ValueError):verify(None)
    def test_wrong_digest(self):
        with self.assertRaises(ValueError):verify(decision(),digest="sha256:"+"b"*64)
    def test_new_release_not_inherited(self):
        with self.assertRaises(ValueError):verify(decision(),tag="v1.5.2-rc.2")
    def test_expired(self):
        d=decision();d["expires_at"]="2026-11-01T00:00:00Z"
        with self.assertRaises(ValueError):verify(d)
    def test_missing_cve(self):
        d=decision();d["exceptions"]=[]
        with self.assertRaises(ValueError):verify(d)
    def test_inventory_tamper(self):
        d=decision();d["package_inventory"][0]["version"]="9.9.9"
        with self.assertRaises(ValueError):verify(d)
    def test_missing_approver(self):
        d=decision();d["approver"]=""
        with self.assertRaises(ValueError):verify(d)
if __name__=="__main__":unittest.main()
