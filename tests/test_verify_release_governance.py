"""Release preflight requires effective repository protections."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import verify_release_governance as governance


class ReleaseGovernanceTests(unittest.TestCase):
    main = {"name": "main", "protected": True}
    rules = [
        {"type": "pull_request", "parameters": {
            "required_approving_review_count": 1,
            "dismiss_stale_reviews_on_push": True,
            "require_last_push_approval": True,
        }},
        {"type": "required_status_checks", "parameters": {
            "strict_required_status_checks_policy": True,
            "required_status_checks": [{"context": "Foundation / Result"}],
        }},
    ]
    tags = {
        "id": 42, "target": "tag", "enforcement": "active",
        "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
        "rules": [{"type": name} for name in governance.REQUIRED_TAG_RULES],
    }

    def test_effective_rules_allow_preflight_to_continue(self):
        governance.verify_main(self.main, self.rules)
        self.assertEqual(governance.verify_tag_protection([self.tags]), {
            "creation": [42], "deletion": [42], "update": [42],
        })

    def test_creation_and_immutability_can_be_enforced_by_separate_rulesets(self):
        creation = dict(self.tags, rules=[{"type": "creation"}])
        immutability = dict(self.tags, id=57, rules=[{"type": "update"}, {"type": "deletion"}])
        self.assertEqual(governance.verify_tag_protection([creation, immutability]), {
            "creation": [42], "deletion": [57], "update": [57],
        })
        immutability["rules"][0]["type"] = "non_fast_forward"
        with self.assertRaisesRegex(governance.GovernanceError, "missing: update"):
            governance.verify_tag_protection([creation, immutability])

    def test_main_requires_current_head_reviews_and_up_to_date_checks(self):
        for flags in ("dismiss_stale_reviews_on_push", "require_last_push_approval"):
            with self.subTest(flags=flags), self.assertRaises(governance.GovernanceError):
                rules = deepcopy(self.rules)
                rules[0]["parameters"][flags] = False
                governance.verify_main(self.main, rules)
        for branch, rules in ((dict(self.main, protected=False), self.rules), (self.main, self.rules[:1])):
            with self.subTest(branch=branch, rules=rules), self.assertRaises(governance.GovernanceError):
                governance.verify_main(branch, rules)

    def test_mistargeted_or_disabled_release_tag_rules_are_refused(self):
        for include, exclude in ((["refs/tags/refs/tags/v*"], []), (["refs/tags/v*"], ["refs/tags/v1.5.2*"])):
            tags = deepcopy(self.tags)
            tags["conditions"]["ref_name"] = {"include": include, "exclude": exclude}
            with self.subTest(tags=tags), self.assertRaises(governance.GovernanceError):
                governance.verify_tag_protection([tags])
        with self.assertRaises(governance.GovernanceError):
            governance.verify_tag_protection([dict(self.tags, enforcement="evaluate")])


if __name__ == "__main__":
    unittest.main()
