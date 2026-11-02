"""Guard the privileged release workflow against dispatch-selected source code."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/publish.yml"


class PublishCheckoutTrustTests(unittest.TestCase):
    def test_every_checkout_uses_immutable_event_sha(self):
        source = WORKFLOW.read_text()
        self.assertEqual(source.count("uses: actions/checkout@"), 4)
        self.assertEqual(source.count("ref: ${{ github.sha }}"), 4)
        self.assertEqual(source.count("persist-credentials: false"), 4)
        self.assertNotIn("checkout_ref", source)
        self.assertNotIn("pull_request.head.ref", source)

    def test_dispatch_cannot_override_the_code_or_publish(self):
        source = WORKFLOW.read_text()
        self.assertNotIn("workflow_dispatch.inputs.tag", source)
        self.assertNotIn("DISPATCH_TAG", source)
        self.assertNotRegex(source, r"\btag:\s*\n\s*description: Existing tag")
        self.assertIn('"$GITHUB_EVENT_NAME" == "workflow_dispatch"', source)
        self.assertIn('"$GITHUB_REF" != "refs/heads/main"', source)
        self.assertIn('"$GITHUB_EVENT_NAME" == "push"', source)
        self.assertIn('"$GITHUB_REF" == refs/tags/*', source)
        self.assertIn('echo "is_release=false"', source)

    def test_cve_gate_is_not_modified(self):
        source = WORKFLOW.read_text()
        self.assertIn("--exit-code 1", source)
        self.assertIn("--ignorefile /dev/null", source)
        self.assertNotRegex(source, r"^\s+--ignore-unfixed\\", re.M)


if __name__ == "__main__":
    unittest.main()
