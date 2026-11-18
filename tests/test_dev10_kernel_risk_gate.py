"""Regression tests for the retired legacy DEV-10 risk gate."""
from pathlib import Path
import importlib.util
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "dev10_kernel_risk_gate", ROOT / "scripts/dev10_kernel_risk_gate.py"
)
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)

# Execute supplemental 41-CVE source and binary evidence regression tests in the
# existing Foundation DEV-10 test job (which is present on the PR base branch).
from test_dev10_image_observed_41_sources import Supplemental41SourceEvidenceTests
from test_ubuntu_binary_package_arch import UbuntuBinaryPackageArchitectureTests
from test_reconcile_dev10_image_observed_41_binary_paths import Supplemental41BinaryPathMappingTests


class RetiredDevelopmentRiskGateTests(unittest.TestCase):
    def test_legacy_validator_always_fails_closed(self):
        for args, kwargs in (
            ((), {}),
            (({},), {}),
            (({"Results": []},), {"event": "push", "ref": "refs/heads/main"}),
            ((), {"event": "push", "ref": "refs/tags/v1.5.1"}),
        ):
            with self.subTest(args=args, kwargs=kwargs):
                with self.assertRaisesRegex(mod.RiskGateError, "retired"):
                    mod.validate(*args, **kwargs)

    def test_only_historical_v150_and_v151_tags_are_disclosure_refs(self):
        accepted = ("v1.5.0", "v1.5.0-rc.1", "v1.5.1", "v1.5.1-rc.9")
        rejected = ("v1.5.2", "v1.5.2-rc.1", "v1.5.1-beta.1", "v1.5.0-rc.0", "main")
        for tag in accepted:
            with self.subTest(tag=tag):
                self.assertTrue(mod.is_historical_development_risk_disclosure_ref(tag))
        for tag in rejected:
            with self.subTest(tag=tag):
                self.assertFalse(mod.is_historical_development_risk_disclosure_ref(tag))

    def test_retired_module_exposes_no_inventory_or_approval_evaluator(self):
        self.assertFalse(hasattr(mod, "inventory"))
        self.assertFalse(hasattr(mod, "evaluate"))
        self.assertTrue(callable(mod.validate))
        self.assertIn("refs/tags/v1.5.0", mod.HISTORICAL_DISCLOSURE_IMAGE_REFS)
        self.assertIn("refs/tags/v1.5.1", mod.HISTORICAL_DISCLOSURE_IMAGE_REFS)


if __name__ == "__main__":
    unittest.main()
