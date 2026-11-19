"""Release-only exact-digest gate tests; development decisions are never accepted."""
import datetime as dt
import importlib.util
import sys
import unittest
from pathlib import Path
p=Path(__file__).resolve().parents[1]/"scripts/verify_digest_security_decision.py"
sys.path.insert(0, str(p.parent))
spec=importlib.util.spec_from_file_location("security_decision",p)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
NOW=dt.datetime(2026,11,14,tzinfo=dt.timezone.utc)
DIGEST="sha256:"+"a"*64
OTHER_DIGEST="sha256:"+"b"*64
PKG={"name":"openssl","version":"1.2.3","type":"os"}
REPORT={
    "SchemaVersion":2,"ArtifactType":"container_image","Trivy":{"Version":m.TRIVY_VERSION},
    "Metadata":{"RepoDigests":[f"{m.IMAGE_REPOSITORY}@{DIGEST}"],
                "ImageConfig":{"os":"linux","architecture":"amd64"}},
    "Results":[{"Target":"ubuntu:26.04","Type":"ubuntu","Secrets":[],
                "Vulnerabilities":[{"Severity":"HIGH","VulnerabilityID":"CVE-2026-12345",
                                    "PkgName":"openssl","InstalledVersion":"1.2.3"}]}],
}
def decision():
    return {"schema_version":1,"release_tag":"v1.5.2-rc.1","target":"final","digest":DIGEST,
            "package_inventory":[dict(PKG)],"inventory_sha256":m.inventory_hash([PKG]),
            "exceptions":[{"cve":"CVE-2026-12345","package":"openssl",
                           "installed_version":"1.2.3","justification":"Reviewed temporary mitigation"}],
            "approver":"security-reviewer","approved_at":"2026-11-13T00:00:00Z",
            "expires_at":"2026-11-20T00:00:00Z","evidence_url":"https://github.com/baobab-platform/baobab-dev/issues/54"}
def verify(d,report=REPORT,tag="v1.5.2-rc.1",digest=DIGEST,architecture="linux/amd64"):
    return m.validate(d,report,target="final",digest=digest,release_tag=tag,
                      image_repository=m.IMAGE_REPOSITORY,architecture=architecture,now=NOW)
class SecurityDecisionTests(unittest.TestCase):
    def test_legacy_approval_is_not_authority(self):
        with self.assertRaisesRegex(ValueError, "protected custody required"):
            verify(decision())
    def test_clean_no_exception(self):
        report = dict(REPORT)
        report["Results"] = [{"Target":"ubuntu:26.04","Type":"ubuntu","Secrets":[],"Vulnerabilities":[]}]
        self.assertEqual(verify(None,report)["status"],"no-high-critical-findings")
    def test_secret_finding_blocks_release(self):
        report = dict(REPORT)
        report["Results"] = [{"Target":"image","Type":"secret","Secrets":[{"RuleID":"secret"}],"Vulnerabilities":[]}]
        with self.assertRaisesRegex(ValueError,"secret findings block release"):
            verify(None,report)
    def test_report_digest_and_architecture_must_match(self):
        report = dict(REPORT)
        report["Metadata"] = {"RepoDigests":[f"{m.IMAGE_REPOSITORY}@{OTHER_DIGEST}"],
                              "ImageConfig":{"os":"linux","architecture":"amd64"}}
        with self.assertRaisesRegex(ValueError,"exact release child digest"):
            verify(None,report)
        report = dict(REPORT)
        report["Metadata"] = {"RepoDigests":[f"{m.IMAGE_REPOSITORY}@{DIGEST}"],
                              "ImageConfig":{"os":"linux","architecture":"arm64"}}
        with self.assertRaisesRegex(ValueError,"architecture"):
            verify(None,report)
    def test_empty_results_are_not_treated_as_clean(self):
        report = dict(REPORT)
        report["Results"] = []
        with self.assertRaisesRegex(ValueError,"cannot be treated as clean"):
            verify(None,report)
    def test_missing_decision(self):
        with self.assertRaises(ValueError):verify(None)
    def test_wrong_digest(self):
        with self.assertRaises(ValueError):verify(decision(),digest="sha256:"+"b"*64)
    def test_new_release_not_inherited(self):
        with self.assertRaises(ValueError):verify(decision(),tag="v1.5.2-rc.2")
    def test_release_exception_is_denied_even_when_legacy_record_is_complete(self):
        d=decision()
        with self.assertRaisesRegex(ValueError,"legacy free-text release decisions are not authenticated"):
            verify(d)
    def test_invalid_release_tag_is_rejected(self):
        with self.assertRaisesRegex(ValueError,"invalid release target/digest/repository/architecture"):
            verify(None,tag="refs/heads/main")
    def test_invalid_trivy_version_is_rejected(self):
        report = dict(REPORT)
        report["Trivy"] = {"Version":"0.74.0"}
        with self.assertRaisesRegex(ValueError,"scanner version is not qualified"):
            verify(None,report)
if __name__=="__main__":unittest.main()
