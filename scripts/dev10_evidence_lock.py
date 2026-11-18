"""Validated, single source of truth for DEV-10 kernel evidence inputs."""
from __future__ import annotations

import csv
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

LOCK_PATH = Path("security/evidence/dev10-kernel-evidence.lock.json")
SHA40 = re.compile(r"^[a-f0-9]{40}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")


@dataclass(frozen=True)
class EvidenceLock:
    package_version: str
    ubuntu_tag: str
    ubuntu_tag_commit: str
    upstream_sha: str
    canonical_osv_repository: str
    canonical_osv_commit: str
    canonical_osv_snapshot_path: str
    inventory_path: str
    inventory_sha256: str
    inventory_count: int
    canonical_path: str
    canonical_sha256: str
    canonical_count: int
    binary_manifest_sha256: str | None
    header_count: int
    binary_manifest_path_count: int
    stable_profile_images: dict[str, dict]
    historical_inventory_path: str
    historical_inventory_sha256: str
    historical_inventory_count: int
    historical_package_version: str
    extension_cves: frozenset[str]
    profile_scan_run_id: int
    profile_scan_package_version: str
    observed_kernel_cves: frozenset[str]
    observed_node_cves: frozenset[str]
    profile_scan_artifacts: tuple[dict, ...]
    evidence_lock_sha256: str

    @classmethod
    def load(cls, root: Path | None = None) -> "EvidenceLock":
        root = root or Path(__file__).resolve().parents[1]
        path = root / LOCK_PATH
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("schema") != "baobab.dev10.kernel-evidence-lock.v1":
            raise ValueError("unsupported DEV-10 evidence lock schema")
        ubuntu, upstream = data["ubuntu_tag"], data["upstream_cna"]
        inventory, canonical, manifest = (
            data["inventory"], data["canonical_status"], data["binary_manifest"]
        )
        canonical_osv = data["canonical_osv"]
        lock = cls(
            package_version=data["package_version"],
            ubuntu_tag=ubuntu["name"], ubuntu_tag_commit=ubuntu["commit"],
            upstream_sha=upstream["sha"],
            canonical_osv_repository=canonical_osv["repository"],
            canonical_osv_commit=canonical_osv["commit"],
            canonical_osv_snapshot_path=canonical_osv["snapshot_path"],
            inventory_path=inventory["path"], inventory_sha256=inventory["sha256"],
            inventory_count=inventory["count"],
            canonical_path=canonical["path"], canonical_sha256=canonical["sha256"],
            canonical_count=canonical["count"],
            binary_manifest_sha256=manifest["sha256"],
            header_count=manifest["header_count"],
            binary_manifest_path_count=manifest["path_count"],
            stable_profile_images=data.get("stable_profile_images", {}),
            historical_inventory_path=data["historical_295_inventory"]["path"],
            historical_inventory_sha256=data["historical_295_inventory"]["sha256"],
            historical_inventory_count=data["historical_295_inventory"]["count"],
            historical_package_version=data["historical_295_inventory"]["package_version"],
            extension_cves=frozenset(),
            profile_scan_run_id=data["profile_scan_run"]["run_id"],
            profile_scan_package_version=data["profile_scan_run"]["package_version"],
            observed_kernel_cves=frozenset(data["profile_scan_run"]["observed_kernel_cves"]),
            observed_node_cves=frozenset(data["profile_scan_run"]["observed_node_cves"]),
            profile_scan_artifacts=tuple(data["profile_scan_run"]["artifacts"]),
            evidence_lock_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        )
        if (not SHA40.fullmatch(lock.ubuntu_tag_commit)
                or not SHA40.fullmatch(lock.upstream_sha)
                or not SHA40.fullmatch(lock.canonical_osv_commit)):
            raise ValueError("DEV-10 evidence lock contains an invalid source commit")
        for digest in (lock.inventory_sha256, lock.canonical_sha256):
            if not SHA256.fullmatch(digest):
                raise ValueError("DEV-10 evidence lock contains an invalid input digest")
        if (lock.binary_manifest_sha256 is None
                or not SHA256.fullmatch(lock.binary_manifest_sha256)
                or lock.header_count < 1 or lock.binary_manifest_path_count < lock.header_count):
            raise ValueError("DEV-10 evidence lock contains an invalid binary manifest digest or counts")
        for rel, expected, count, label in (
            (lock.inventory_path, lock.inventory_sha256, lock.inventory_count, "CVE inventory"),
            (lock.canonical_path, lock.canonical_sha256, lock.canonical_count, "Canonical status input"),
        ):
            raw = (root / rel).read_bytes()
            if hashlib.sha256(raw).hexdigest() != expected:
                raise ValueError(f"{label} digest differs from reviewed evidence lock")
            lines = raw.decode("utf-8").splitlines()
            if len(lines) - 1 != count:
                raise ValueError(f"{label} row count differs from reviewed evidence lock")
        if lock.inventory_count != lock.canonical_count:
            raise ValueError("CVE inventory and Canonical status counts differ")
        historical = root / lock.historical_inventory_path
        historical_raw = historical.read_bytes()
        if hashlib.sha256(historical_raw).hexdigest() != lock.historical_inventory_sha256:
            raise ValueError("historical 295-CVE inventory digest differs from evidence lock")
        historical_rows = list(csv.DictReader(
            historical_raw.decode("utf-8").splitlines(), delimiter="\t"
        ))
        current_rows = list(csv.DictReader(
            (root / lock.inventory_path).read_text(encoding="utf-8").splitlines(),
            delimiter="\\t",
        ))
        historical_ids = {row.get("cve") for row in historical_rows}
        current_ids = {row.get("cve") for row in current_rows}
        extension_ids = current_ids - historical_ids
        if (len(historical_rows) != lock.historical_inventory_count
                or len(historical_ids) != lock.historical_inventory_count
                or lock.historical_inventory_count != 295
                or lock.historical_package_version != "7.0.0-42.42"
                or len(extension_ids) != lock.inventory_count - lock.historical_inventory_count
                or not historical_ids.issubset(current_ids)):
            raise ValueError("historical 295-CVE inventory is not an exact subset of the expanded inventory")
        object.__setattr__(lock, "extension_cves", frozenset(extension_ids))
        if (lock.profile_scan_package_version != lock.package_version
                or len(lock.observed_kernel_cves) != 11
                or not lock.observed_kernel_cves.issubset(current_ids)
                or lock.observed_node_cves != {"CVE-2026-112366"}
                or not isinstance(lock.profile_scan_run_id, int)
                or len(lock.profile_scan_artifacts) != 8):
            raise ValueError("43.43 profile scan provenance differs from the reviewed 11-kernel/one-node set")
        scan = data.get("profile_scan_run", {})
        artifacts = scan.get("artifacts", [])
        expected_pairs = {
            (profile, architecture)
            for profile in ("final", "frontend", "frontend-e2e", "infra")
            for architecture in ("linux/amd64", "linux/arm64")
        }
        observed_pairs = {(item.get("profile"), item.get("architecture")) for item in artifacts}
        if len(artifacts) != 8 or observed_pairs != expected_pairs:
            raise ValueError("historical profile scan evidence must cover all four profiles and both architectures")
        if any(not isinstance(item.get("artifact_id"), int)
               or not SHA256.fullmatch(item.get("artifact_sha256", ""))
               for item in artifacts):
            raise ValueError("historical profile scan artifact provenance is incomplete")
        foundation = scan.get("foundation_scan", {})
        if (not isinstance(foundation.get("artifact_id"), int)
                or not SHA256.fullmatch(foundation.get("artifact_sha256", ""))):
            raise ValueError("historical Foundation scan artifact provenance is incomplete")
        stable = data.get("stable_base_image", {})
        if (stable.get("image_tag") != "ghcr.io/baobab-platform/baobab-dev:1.5.1"
                or not re.fullmatch(r"sha256:[a-f0-9]{64}", stable.get("index_digest", ""))
                or not SHA40.fullmatch(stable.get("source_sha", ""))
                or stable.get("release_tag") != "v1.5.1"
                or stable.get("signer_tag") != "v1.5.1-rc.2"):
            raise ValueError("historical GHCR base image digest or signer identity is not locked")
        expected_profiles = {"final", "frontend", "frontend-e2e", "infra"}
        if set(lock.stable_profile_images) != expected_profiles:
            raise ValueError("historical GHCR image lock must cover all four profiles")
        for profile, image in lock.stable_profile_images.items():
            expected_tag = (
                "ghcr.io/baobab-platform/baobab-dev:1.5.1"
                if profile == "final"
                else f"ghcr.io/baobab-platform/baobab-dev:1.5.1-{profile}"
            )
            if (image.get("image_tag") != expected_tag
                    or not re.fullmatch(r"sha256:[a-f0-9]{64}", image.get("index_digest", ""))
                    or image.get("release_tag") != "v1.5.1"
                    or image.get("signer_tag") != "v1.5.1-rc.2"
                    or image.get("source_sha") != stable.get("source_sha")
                    or not isinstance(image.get("ga_reuse_run_id"), int)
                    or not isinstance(image.get("signer_run_id"), int)):
                raise ValueError(f"historical GHCR {profile} image digest or provenance identity is not locked")
        final_image = lock.stable_profile_images["final"]
        if (final_image["image_tag"] != stable["image_tag"]
                or final_image["index_digest"] != stable["index_digest"]):
            raise ValueError("final profile GHCR image lock differs from stable base image")
        return lock
