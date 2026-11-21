import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch


PATH = Path(__file__).resolve().parents[1] / "scripts/ci/collect-development-host-evidence.py"
SPEC = importlib.util.spec_from_file_location("development_host_evidence", PATH)
evidence = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evidence)


class DevelopmentHostEvidenceTests(unittest.TestCase):
    def test_selects_actual_deepest_backing_mount(self):
        mounts = evidence.mounts_from_linux(
            "1 0 8:1 / / rw - ext4 /dev/host-root rw\n"
            "2 1 8:2 / /private\\040volume ro,nodev,nosuid - ntfs3 /dev/private-drive ro\n"
            "3 1 8:3 / /var/lib/docker rw - xfs /dev/private-data rw\n"
        )
        self.assertEqual(evidence.mount_at(mounts, "/private volume/workspace"),
                         {"filesystem": "ntfs3", "read_only": True, "nodev": True, "nosuid": True})
        self.assertEqual(evidence.mount_at(mounts, "/private volumetric")["filesystem"], "ext4")
        self.assertEqual(evidence.mount_at(mounts, "/var/lib/docker/volumes/workspace")["filesystem"], "xfs")

    def test_docker_receipts_filter_local_paths_and_identity(self):
        raw = {
            "Image": "sha256:" + "0" * 64,
            "Config": {"Env": ["UNRELATED_SECRET=secret-sentinel"]},
            "HostConfig": {"Privileged": False, "CapAdd": ["SYS_PTRACE"],
                           "SecurityOpt": ["seccomp=unconfined"], "Devices": [{"PathOnHost": "/private-device"}]},
            "Mounts": [{"Type": "bind", "Source": "/private-source", "Destination": "/private-destination", "RW": True}],
        }
        report = evidence.summarize_container(raw, [("/", "ext4", {"rw"})])
        self.assertTrue(report["seccomp_unconfined"])
        self.assertEqual(report["explicit_devices"], 1)
        self.assertEqual(report["mounts"][0]["host_backing"]["filesystem"], "ext4")
        self.assertNotIn("private-", json.dumps(report))
        self.assertNotIn("secret-sentinel", json.dumps(report))
        daemon = evidence.summarize_daemon({"ID": "private-daemon-id", "Plugins": {"Authorization": None},
                                            "SecurityOptions": ["name=seccomp,profile=builtin"],
                                            "DockerRootDir": "/private-engine-data"})
        self.assertEqual(daemon["authorization_plugin_count"], 0)
        self.assertFalse(daemon["rootless"])
        self.assertNotIn("private-", json.dumps(daemon))
        self.assertIsNone(evidence.summarize_daemon({})["authorization_plugin_count"])

    def test_kernel_config_preserves_unknown_options(self):
        with patch.object(evidence, "read_text", return_value=(
                "# CONFIG_ANDROID_BINDER_IPC is not set\nCONFIG_EXT4_FS=y\nCONFIG_NTFS3_FS=m\n")):
            report = evidence.kernel_config("test-kernel")
        self.assertEqual(report["source"], "boot_config")
        self.assertEqual(report["options"]["ANDROID_BINDER_IPC"], "n")
        self.assertEqual(report["options"]["NTFS3_FS"], "m")
        self.assertIsNone(report["options"]["NTFS_FS"])

    def test_kernel_comparison_requires_architecture_as_well_as_release(self):
        host = {"kernel": {"release": "test", "machine": "x86_64"}}
        self.assertTrue(evidence.matches_running_kernel(host, host))
        self.assertFalse(evidence.matches_running_kernel(host, {"kernel": {"release": "test", "machine": "aarch64"}}))
