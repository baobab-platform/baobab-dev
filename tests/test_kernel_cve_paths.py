"""Fail closed when Linux CVE source paths or package manifests are missing."""
from pathlib import Path
import base64
import importlib.util
import json
import unittest
from unittest.mock import patch

SRC = Path(__file__).resolve().parents[1] / "scripts/audit_kernel_cve_paths.py"
spec = importlib.util.spec_from_file_location("kernel_paths", SRC)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class KernelPathTests(unittest.TestCase):
    def sample(self, paths):
        return base64.b64encode(json.dumps({
            "dataType": "CVE_RECORD", "containers": {"cna": {"affected": [
                {"vendor": "Linux", "product": "Linux", "programFiles": paths}
            ]}}
        }).encode())

    def test_implementation_only_remains_review_required(self):
        with patch.object(module.request, "urlopen") as response:
            response.return_value.__enter__.return_value.read.return_value = self.sample([
                "net/sunrpc/xprtrdma/svc_rdma_sendto.c"])
            result = module.inspect("CVE-2026-89530", "a"*40, {"/usr/include/linux/types.h"})
        self.assertEqual(result["classification"], "KERNEL_IMPLEMENTATION_PATHS_REVIEW_REQUIRED")
        self.assertEqual(result["binary_disposition"], "PENDING_INDEPENDENT_SECURITY_REVIEW")

    def test_any_header_requires_review_even_if_manifest_match_is_absent(self):
        with patch.object(module.request, "urlopen") as response:
            response.return_value.__enter__.return_value.read.return_value = self.sample([
                "include/uapi/linux/example.h", "net/example.c"])
            result = module.inspect("CVE-2026-90162", "a"*40, {"/usr/include/linux/example.h"})
        self.assertEqual(result["classification"], "HEADER_PATH_REVIEW_REQUIRED")
        self.assertEqual(result["matching_shipped_uapi_headers"], ["include/uapi/linux/example.h"])

    def test_missing_upstream_evidence_rejected(self):
        with self.assertRaises(ValueError):
            module.parse_upstream(self.sample([]))

    def test_source_revision_must_be_immutable(self):
        with self.assertRaises(ValueError):
            module.upstream_url("CVE-2026-89530", "master")

    def test_partial_inventories_rejected(self):
        with self.assertRaises(ValueError):
            module.audit([], [], {"/usr/include/linux/example.h"}, "a"*40)


if __name__ == "__main__":
    unittest.main()
