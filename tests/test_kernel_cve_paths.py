"""Fail closed when Linux CVE source paths or package manifests are missing."""
from pathlib import Path
import base64
import importlib.util
import json
import subprocess
import unittest
from tempfile import TemporaryDirectory
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

    def write_cve(self, root, cve, paths):
        path = root / "cve" / "published" / cve[4:8] / (cve + ".json")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(base64.b64decode(self.sample(paths)))
        return root

    def test_implementation_only_remains_review_required(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_cve(root, "CVE-2026-89530", ["net/sunrpc/xprtrdma/svc_rdma_sendto.c"])
            result = module.inspect("CVE-2026-89530", "a"*40,
                                    {"/usr/include/linux/types.h"}, root)
        self.assertEqual(result["classification"], "KERNEL_IMPLEMENTATION_PATHS_REVIEW_REQUIRED")
        self.assertEqual(result["binary_disposition"], "PENDING_INDEPENDENT_SECURITY_REVIEW")

    def test_any_header_requires_review_even_if_manifest_match_is_absent(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_cve(root, "CVE-2026-90162", [
                "include/uapi/linux/example.h", "net/example.c"])
            result = module.inspect("CVE-2026-90162", "a"*40,
                                    {"/usr/include/linux/example.h"}, root)
        self.assertEqual(result["classification"], "HEADER_PATH_REVIEW_REQUIRED")
        self.assertEqual(result["matching_shipped_uapi_headers"], ["include/uapi/linux/example.h"])

    def test_single_immutable_local_git_snapshot_is_used_without_http(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "cve/published/2026/CVE-2026-89530.json"
            path.parent.mkdir(parents=True)
            import base64
            path.write_bytes(base64.b64decode(self.sample(
                ["net/sunrpc/xprtrdma/svc_rdma_sendto.c"]
            )))
            row = module.inspect("CVE-2026-89530", "a"*40,
                                 {"/usr/include/linux/types.h"}, root)
            self.assertEqual(row["classification"], "KERNEL_IMPLEMENTATION_PATHS_REVIEW_REQUIRED")
            self.assertEqual(row["error"], "")

    def test_local_snapshot_accepts_prior_published_years(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            import base64
            for year in ("2022", "2025", "2026"):
                cve = f"CVE-{year}-50240"
                path = root / "cve" / "published" / year / (cve + ".json")
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(base64.b64decode(self.sample(["kernel/example.c"])))
                row = module.inspect(cve, "a"*40, {"/usr/include/linux/types.h"}, root)
                self.assertEqual(row["classification"], "KERNEL_IMPLEMENTATION_PATHS_REVIEW_REQUIRED")

    def test_missing_local_cve_fails_closed_without_http(self):
        with TemporaryDirectory() as tmp:
            row = module.inspect("CVE-2026-89530", "a"*40,
                                 {"/usr/include/linux/types.h"}, Path(tmp))
            self.assertEqual(row["classification"], "UPSTREAM_UNVERIFIED")
            self.assertIn("FileNotFoundError", row["error"])

    def test_audit_records_exact_installed_binary_package_version(self):
        ids = [f"CVE-2026-{i:05d}" for i in range(10000, 10298)]
        trivy = [{"cve": cve, "severity": "HIGH"} for cve in ids]
        vendor = [{"cve": cve, "ubuntu_linux_resolute_status": "pending"} for cve in ids]
        class GitResult:
            returncode = 0
            stdout = "a" * 40 + "\n"
        with (
            patch.object(module.subprocess, "run", return_value=GitResult()),
            patch.object(
                module,
                "inspect",
                side_effect=lambda cve, sha, manifest, source_root: {
                    "cve": cve,
                    "classification": "KERNEL_IMPLEMENTATION_PATHS_REVIEW_REQUIRED",
                },
            ),
        ):
            result = module.audit(
                trivy, vendor, {"/usr/include/linux/types.h"},
                "a" * 40, "7.0.0-43.43", Path("."),
            )
        self.assertEqual(result["package"], "linux-libc-dev=7.0.0-43.43")
        self.assertEqual(len(result["records"]), 298)

    def test_invalid_binary_package_version_is_rejected(self):
        ids = [f"CVE-2026-{i:05d}" for i in range(10000, 10298)]
        trivy = [{"cve": cve, "severity": "HIGH"} for cve in ids]
        vendor = [{"cve": cve, "ubuntu_linux_resolute_status": "pending"} for cve in ids]
        with self.assertRaisesRegex(ValueError, "binary package version"):
            module.audit(trivy, vendor, {"/usr/include/linux/types.h"},
                         "a" * 40, "not-a-version", Path("."))

    def test_git_checkout_revision_mismatch_is_rejected(self):
        with TemporaryDirectory() as tmp:
            ids = [f"CVE-2026-{i:05d}" for i in range(10000, 10298)]
            trivy = [{"cve": cve, "severity": "HIGH"} for cve in ids]
            vendor = [{"cve": cve, "ubuntu_linux_resolute_status": "pending"} for cve in ids]
            class GitResult:
                returncode = 0
                stdout = "b" * 40 + "\n"
            with patch.object(module.subprocess, "run", return_value=GitResult()):
                with self.assertRaisesRegex(ValueError, "revision mismatch"):
                    module.audit(trivy, vendor, {"/usr/include/linux/types.h"},
                                 "a"*40, "7.0.0-43.43", Path(tmp))

    def test_missing_upstream_evidence_rejected(self):
        with self.assertRaises(ValueError):
            module.parse_upstream(self.sample([]))

    def test_upstream_audit_requires_local_checkout_without_network_fallback(self):
        source = Path(module.__file__).read_text(encoding="utf-8")
        self.assertNotIn("urllib.request", source)
        self.assertIn('p.add_argument("--upstream-root", type=Path, required=True', source)

    def test_unsafe_upstream_paths_are_rejected(self):
        for path in ("kernel/a\nb.c", "kernel/a\\\\b.c", "kernel/../escape.c"):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "unsafe source path"):
                module.parse_upstream(self.sample([path]))

    def test_source_revision_must_be_immutable(self):
        with self.assertRaises(ValueError):
            module.upstream_url("CVE-2026-89530", "master")

    def test_partial_inventories_rejected(self):
        with self.assertRaises(ValueError):
            module.audit([], [], {"/usr/include/linux/example.h"}, "a"*40, "7.0.0-43.43", Path("."))


if __name__ == "__main__":
    unittest.main()
