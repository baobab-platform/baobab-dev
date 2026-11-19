"""Validated, single source of truth for DEV-10 kernel evidence inputs."""
from __future__ import annotations

import csv
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

LOCK_PATH = Path("security/evidence/dev10-kernel-evidence.lock.json")
BINARY_LOCK_PATH = LOCK_PATH.with_name("dev10-ubuntu-binary-evidence.lock.json")
SHA40 = re.compile(r"^[a-f0-9]{40}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
CVE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
UBUNTU_BINARY_POCKETS = frozenset({"resolute-updates", "resolute-security"})
DEBIAN_VERSION = re.compile(r"(?:[0-9]+:)?[0-9][A-Za-z0-9.+~\-]*")


@dataclass(frozen=True)
class EvidenceLock:
    package_version: str
    binary_source: dict[str, str]
    binary_artifact_sha256: dict[str, str]
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
    binary_manifest_sha256: str
    header_count: int
    binary_manifest_path_count: int
    stable_profile_images: dict[str, dict]
    stable_image_readback: dict
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
        binary_source = data["binary_source"]
        artifact_lock = json.loads((root / BINARY_LOCK_PATH).read_text(encoding="utf-8"))
        binary_artifacts = artifact_lock["sha256"]
        stable = data.get("stable_base_image", {})
        if binary_source != {
            "binary_package": "linux-libc-dev",
            "binary_version": data["package_version"],
            "architecture": "amd64",
            "source_package": "linux",
            "source_version": data["package_version"],
            "release_pocket": "resolute-updates",
        }:
            raise ValueError("Ubuntu binary-to-source package identity differs from reviewed lock")
        if (artifact_lock.get("schema") != "baobab.dev10.ubuntu-binary-evidence-lock.v1"
                or artifact_lock.get("package") != binary_source["binary_package"]
                or artifact_lock.get("version") != binary_source["binary_version"]
                or not isinstance(binary_artifacts, dict)
                or set(binary_artifacts) != {"amd64", "arm64"}
                or any(not isinstance(value, str) or not SHA256.fullmatch(value)
                       for value in binary_artifacts.values())):
            raise ValueError("Ubuntu binary artifact hashes must cover both native architectures")
        lock = cls(
            package_version=data["package_version"], binary_source=binary_source,
            binary_artifact_sha256=binary_artifacts,
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
            stable_image_readback=stable.get("independent_readback", {}),
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
        reviewed_ids = []
        for rel, expected, count, label in (
            (lock.inventory_path, lock.inventory_sha256, lock.inventory_count, "CVE inventory"),
            (lock.canonical_path, lock.canonical_sha256, lock.canonical_count, "Canonical status input"),
        ):
            raw = (root / rel).read_bytes()
            if hashlib.sha256(raw).hexdigest() != expected:
                raise ValueError(f"{label} digest differs from reviewed evidence lock")
            rows = list(csv.DictReader(raw.decode("utf-8").splitlines(), delimiter="\t"))
            ids = {row.get("cve") for row in rows}
            if (len(rows) != count or len(ids) != count
                    or any(not isinstance(cve, str) or not CVE.fullmatch(cve) for cve in ids)):
                raise ValueError(f"{label} does not contain the reviewed count of unique CVEs")
            reviewed_ids.append(ids)
        current_ids, canonical_ids = reviewed_ids
        if current_ids != canonical_ids:
            raise ValueError("CVE inventory and Canonical status contain different advisories")
        historical = root / lock.historical_inventory_path
        historical_raw = historical.read_bytes()
        if hashlib.sha256(historical_raw).hexdigest() != lock.historical_inventory_sha256:
            raise ValueError("historical 295-CVE inventory digest differs from evidence lock")
        historical_rows = list(csv.DictReader(
            historical_raw.decode("utf-8").splitlines(), delimiter="\t"
        ))
        historical_ids = {row.get("cve") for row in historical_rows}
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
        readback = lock.stable_image_readback
        if not isinstance(readback, dict):
            raise ValueError("historical GHCR independent readback is missing")
        if (readback.get("status") != "STRICT_SIGNED_NATIVE_CONTENT_VERIFIED"
                or readback.get("release_tag") != stable.get("release_tag")
                or readback.get("signer_tag") != stable.get("signer_tag")
                or readback.get("source_sha") != stable.get("source_sha")
                or not isinstance(readback.get("run_id"), int)
                or readback.get("release_qualification") is not False
                or readback.get("image_signature_count") != 5
                or readback.get("signed_slsa_statements") != 2
                or readback.get("signed_spdx_statements") != 2):
            raise ValueError("historical GHCR independent readback is incomplete or over-claims qualification")
        readback_profiles = readback.get("profiles", {})
        if not isinstance(readback_profiles, dict) or set(readback_profiles) != expected_profiles:
            raise ValueError("historical GHCR readback must cover all four profiles")
        for profile, proof in readback_profiles.items():
            image = lock.stable_profile_images[profile]
            if not isinstance(proof, dict):
                raise ValueError(f"historical GHCR {profile} readback is malformed")
            children = proof.get("native_child_digests", {})
            if (proof.get("index_digest") != image.get("index_digest")
                    or not isinstance(proof.get("artifact_id"), int)
                    or not SHA256.fullmatch(proof.get("artifact_sha256", ""))
                    or not isinstance(children, dict)
                    or set(children) != {"linux/amd64", "linux/arm64"}
                    or any(not re.fullmatch(r"sha256:[a-f0-9]{64}", digest)
                           for digest in children.values())):
                raise ValueError(f"historical GHCR {profile} readback is not bound to its locked index and native children")
        final_image = lock.stable_profile_images["final"]
        if (final_image["image_tag"] != stable["image_tag"]
                or final_image["index_digest"] != stable["index_digest"]):
            raise ValueError("final profile GHCR image lock differs from stable base image")
        return lock


def require_binary_provenance(binary_source: dict, lock: EvidenceLock) -> None:
    if not isinstance(binary_source, dict) or binary_source.get(
        "schema"
    ) != "baobab.dev10.ubuntu-binary-source-provenance.v1":
        raise ValueError("missing verified Ubuntu binary/source provenance")
    for key, expected in lock.binary_source.items():
        if binary_source.get(key) != expected:
            raise ValueError("Ubuntu binary/source identity differs from evidence lock: " + key)
    package_digest = lock.binary_artifact_sha256[lock.binary_source["architecture"]]
    if binary_source.get("apt_package_deb_sha256") != package_digest:
        raise ValueError("Ubuntu binary/source digest differs from evidence lock")
    for key in ("apt_package_metadata_sha256", "apt_policy_sha256", "apt_madison_sha256",
                "installed_package_metadata_sha256"):
        value = binary_source.get(key)
        if not isinstance(value, str) or not SHA256.fullmatch(value):
            raise ValueError("invalid Ubuntu binary/source provenance digest: " + key)
    pockets = binary_source.get("apt_exact_version_pockets")
    candidate = binary_source.get("apt_candidate_version")
    indices = binary_source.get("apt_package_index_sha256")
    image = binary_source.get("ubuntu_base_image")
    if (not isinstance(pockets, list) or not pockets
            or any(not isinstance(pocket, str) or pocket not in UBUNTU_BINARY_POCKETS for pocket in pockets)
            or len(set(pockets)) != len(pockets)
            or not isinstance(candidate, str) or not DEBIAN_VERSION.fullmatch(candidate)
            or not isinstance(indices, list) or not indices
            or not isinstance(image, str) or not re.fullmatch(r"ubuntu@sha256:[a-f0-9]{64}", image)):
        raise ValueError("incomplete Ubuntu binary/source provenance")
