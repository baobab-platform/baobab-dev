"""Guard the privileged release workflow against dispatch-selected source code."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/publish.yml"


class PublishCheckoutTrustTests(unittest.TestCase):
    def test_every_checkout_uses_immutable_event_sha(self):
        source = WORKFLOW.read_text()
        # Jobs may be added to separate read-only validation and privileged
        # release promotion. Protect EVERY checkout, not a fixed job count.
        matches = list(re.finditer(
            r"(?m)^(?P<indent> +)(?:- )?uses: actions/checkout@(?P<sha>[a-f0-9]{40})(?:[ \t]*#.*)?$",
            source,
        ))
        self.assertGreaterEqual(len(matches), 4)
        self.assertEqual(source.count("uses: actions/checkout@"), len(matches))
        for match in matches:
            with self.subTest(action_sha=match.group("sha"), line=source.count("\n", 0, match.start()) + 1):
                # Checkout metadata must not derive source from caller input.
                block = "\n".join(source[match.end():].splitlines()[:12])
                self.assertRegex(block, r"(?m)^[ \t]+with:[ \t]*$")
                self.assertRegex(block, r"(?m)^[ \t]+ref:[ \t]*\$\{\{[ \t]*github\.sha[ \t]*\}\}[ \t]*$")
                self.assertRegex(block, r"(?m)^[ \t]+persist-credentials:[ \t]*false[ \t]*$")
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
