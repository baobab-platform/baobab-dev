#!/usr/bin/env python3
"""Compare supplemental Linux CNA affected paths with Ubuntu source and binary payloads.

This is a conservative path/content join. A missing header or implementation
path is never converted into a not-affected or VEX disposition.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def git(repo: Path, *args: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True,
        timeout=60, check=False,
    )
    if result.returncode:
        raise ValueError("Ubuntu source evidence command failed: " + result.stderr.decode(errors="replace")[:200])
    return result.stdout


def candidate_binary_paths(source_path: str, architecture: str) -> tuple[str, ...]:
    if source_path.startswith("include/uapi/"):
        return ("/usr/include/" + source_path[len("include/uapi/"):],)
    if source_path.startswith("include/generated/uapi/"):
        return ("/usr/include/" + source_path[len("include/generated/uapi/"):],)
    arch_map = {
        "amd64": ("x86", "x86_64-linux-gnu"),
        "arm64": ("arm64", "aarch64-linux-gnu"),
    }
    arch, multiarch = arch_map[architecture]
    for prefix in (
        f"arch/{arch}/include/uapi/asm/",
        f"arch/{arch}/include/generated/uapi/asm/",
    ):
        if source_path.startswith(prefix):
            suffix = source_path[len(prefix):]
            return (f"/usr/include/{multiarch}/asm/{suffix}",
                    f"/usr/include/asm/{suffix}")
    return ()


def safe_source_path(value: str) -> bool:
    return bool(value) and not value.startswith("/") and "\\" not in value and all(
        part not in {"", ".", ".."} for part in value.split("/")
    )


def compare(args: argparse.Namespace) -> dict:
    upstream = json.loads(args.upstream_evidence.read_text(encoding="utf-8"))
    amd64 = json.loads(args.amd64_manifest.read_text(encoding="utf-8"))
    arm64 = json.loads(args.arm64_manifest.read_text(encoding="utf-8"))
    if upstream.get("counts", {}).get("records") != 41 or len(upstream.get("records", [])) != 41:
        raise ValueError("upstream source evidence must contain exactly 41 CVEs")
    if git(args.ubuntu_root, "rev-parse", "HEAD").decode().strip() != args.ubuntu_commit:
        raise ValueError("Ubuntu source checkout does not match immutable release-tag commit")
    if args.ubuntu_tag != "Ubuntu-7.0.0-43.43":
        raise ValueError("unexpected Ubuntu kernel source tag")
    manifests = {"amd64": amd64, "arm64": arm64}
    for architecture, evidence in manifests.items():
        if (evidence.get("binary_package") != "linux-libc-dev"
                or evidence.get("binary_version") != "7.0.0-43.43"
                or evidence.get("architecture") != architecture
                or evidence.get("source_package") != "linux"
                or evidence.get("source_version") != "7.0.0-43.43"):
            raise ValueError(architecture + ": binary package provenance does not match the reviewed source package")
    output_records = []
    for record in upstream["records"]:
        cve = record["cve"]
        if (record.get("canonical_linux_libc_dev_binary_version") != "7.0.0-43.43"
                or record.get("canonical_linux_libc_dev_binary_listed_as_affected") is not True):
            raise ValueError(cve + ": Canonical OSV lacks the expected linux-libc-dev binary association")
        path_results = []
        for source_path in record.get("affected_source_paths", []):
            if not safe_source_path(source_path):
                raise ValueError(cve + ": unsafe affected source path")
            exists = subprocess.run(
                ["git", "-C", str(args.ubuntu_root), "cat-file", "-e",
                 f"{args.ubuntu_commit}:{source_path}"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=30, check=False,
            ).returncode == 0
            source_sha256 = None
            if exists:
                source_sha256 = hashlib.sha256(
                    git(args.ubuntu_root, "show", f"{args.ubuntu_commit}:{source_path}")
                ).hexdigest()
            per_arch = {}
            for architecture, evidence in manifests.items():
                entries = {item["path"]: item for item in evidence["package_content_manifest"]}
                candidates = candidate_binary_paths(source_path, architecture)
                matches = [entries[path] for path in candidates if path in entries]
                if not exists:
                    classification = "SOURCE_PATH_NOT_PRESENT_AT_UBUNTU_TAG"
                elif matches:
                    file_matches = [
                        item for item in matches
                        if item["kind"] == "file" and item["value"] == source_sha256
                    ]
                    if file_matches:
                        classification = "EXPORTED_UAPI_FILE_CONTENT_MATCH"
                    elif any(item["kind"] == "symlink" for item in matches):
                        classification = "EXPORTED_UAPI_PATH_PRESENT_AS_SYMLINK"
                    else:
                        classification = "EXPORTED_UAPI_PATH_PRESENT_CONTENT_DIFFERS_OR_IS_GENERATED"
                elif candidates:
                    classification = "UAPI_SOURCE_PATH_NOT_FOUND_IN_BINARY_MANIFEST"
                elif source_path.endswith(".h"):
                    classification = "PRIVATE_OR_NON_EXPORTED_HEADER_NO_DIRECT_BINARY_MAPPING"
                else:
                    classification = "KERNEL_IMPLEMENTATION_SOURCE_NO_DIRECT_BINARY_MAPPING"
                per_arch[architecture] = {
                    "candidate_binary_paths": list(candidates),
                    "matched_binary_paths": [item["path"] for item in matches],
                    "classification": classification,
                }
            path_results.append({
                "upstream_affected_source_path": source_path,
                "ubuntu_source_tag_path_exists": exists,
                "ubuntu_source_tag_file_sha256": source_sha256,
                "binary_reconciliation": per_arch,
                "disposition": "under_investigation",
            })
        output_records.append({
            "cve": cve,
            "canonical_resolute_source_package": record["canonical_resolute_source_package"],
            "canonical_resolute_affected_version": record["canonical_resolute_affected_version"],
            "canonical_linux_libc_dev_binary_version": record["canonical_linux_libc_dev_binary_version"],
            "canonical_linux_libc_dev_binary_listed_as_affected": record["canonical_linux_libc_dev_binary_listed_as_affected"],
            "candidate_fix_commit_ids": record["candidate_fix_commit_ids"],
            "candidate_fix_commit_references": record["candidate_fix_commit_references"],
            "candidate_fix_commit_ancestry": {
                "status": "NOT_ASSESSED_NO_NON_APPLICABLE_DISPOSITION_CONSIDERED",
                "reason": "Canonical OSV lists the exact Resolute source and linux-libc-dev versions as affected. Upstream candidate fix references are not proof of an Ubuntu backport or fix; no not_affected disposition is permitted without exact Ubuntu ancestry or patch-equivalence evidence.",
            },
            "affected_source_paths": path_results,
            "binary_applicability": "under_investigation",
            "vex_disposition": "under_investigation",
        })
    return {
        "schema": "baobab.dev10.image-observed-41-source-binary-path-reconciliation.v1",
        "status": "PATH_JOIN_COMPLETE_FIX_BACKPORT_ANCESTRY_AND_DISPOSITION_REVIEW_REQUIRED",
        "ubuntu_source": {
            "tag": args.ubuntu_tag,
            "commit": args.ubuntu_commit,
        },
        "binary_packages": {
            architecture: {
                "package": evidence["binary_package"],
                "version": evidence["binary_version"],
                "source_package": evidence["source_package"],
                "source_version": evidence["source_version"],
                "package_path_count": evidence["package_path_count"],
                "package_content_manifest_sha256": evidence["package_content_manifest_sha256"],
            }
            for architecture, evidence in manifests.items()
        },
        "counts": {
            "cves": len(output_records),
            "canonical_linux_libc_dev_binary_mappings": sum(
                1 for row in output_records if row["canonical_linux_libc_dev_binary_listed_as_affected"]
            ),
            "affected_source_paths": sum(len(row["affected_source_paths"]) for row in output_records),
            "source_paths_present_at_ubuntu_tag": sum(
                1 for row in output_records for item in row["affected_source_paths"]
                if item["ubuntu_source_tag_path_exists"]
            ),
            "direct_exported_uapi_matches": sum(
                1 for row in output_records for item in row["affected_source_paths"]
                for arch in item["binary_reconciliation"].values()
                if arch["classification"] == "EXPORTED_UAPI_FILE_CONTENT_MATCH"
            ),
        },
        "policy_boundary": {
            "all_41_dispositions": "under_investigation",
            "not_affected": False,
            "vex": False,
            "suppression": False,
            "risk_acceptance": False,
            "release_authorization": False,
        },
        "records": output_records,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream-evidence", type=Path, required=True)
    parser.add_argument("--amd64-manifest", type=Path, required=True)
    parser.add_argument("--arm64-manifest", type=Path, required=True)
    parser.add_argument("--ubuntu-root", type=Path, required=True)
    parser.add_argument("--ubuntu-tag", required=True)
    parser.add_argument("--ubuntu-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = compare(args)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")
        print("Reconciled 41-CVE affected paths against Ubuntu source and both binary manifests:",
              result["counts"])
        print("No non-applicability or VEX disposition was inferred.")
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        print("41-CVE source/binary path reconciliation denied:", error, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
