#!/usr/bin/env python3
"""Verify Ubuntu linux-libc-dev package provenance and exact architecture payload.

This binds an apt-selected .deb to its source package and compares every archive
path/content with the installed package manifest captured in the same container.
It does not make a CVE applicability or VEX decision.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

PACKAGE = "linux-libc-dev"
VERSION = "7.0.0-43.43"
SOURCE = "linux"
SOURCE_VERSION = "7.0.0-43.43"
POCKET = "resolute-updates"
SHA256 = re.compile(r"^[a-f0-9]{64}$")
SOURCE_FIELD = re.compile(r"^([a-z0-9+.-]+)(?:\s+\(([^)]+)\))?$")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(*args: str) -> str:
    result = subprocess.run(args, text=True, capture_output=True, check=False, timeout=90)
    if result.returncode:
        raise ValueError("package evidence command failed: " + result.stderr[:250])
    return result.stdout.strip()


def parse_one_line(path: Path, names: tuple[str, ...]) -> dict[str, str]:
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line]
    if len(lines) != 1:
        raise ValueError(path.name + " must contain exactly one metadata record")
    values = lines[0].split("\t")
    if len(values) != len(names):
        raise ValueError(path.name + " has an unexpected field count")
    return dict(zip(names, values, strict=True))


def apt_records(path: Path) -> list[dict[str, str]]:
    records = []
    for paragraph in re.split(r"\n\s*\n", path.read_text(encoding="utf-8").strip()):
        fields: dict[str, str] = {}
        for line in paragraph.splitlines():
            if line[:1].isspace() or ":" not in line:
                continue
            key, value = line.split(":", 1)
            fields[key] = value.strip()
        if fields:
            records.append(fields)
    return records


def source_identity(value: str) -> tuple[str, str]:
    match = SOURCE_FIELD.fullmatch(value.strip())
    if not match:
        raise ValueError("invalid Source field in Ubuntu package metadata")
    return match.group(1), match.group(2) or VERSION


def archive_manifest(deb: Path) -> list[dict[str, str]]:
    with tempfile.TemporaryDirectory(prefix="dev10-linux-libc-dev-") as temp:
        root = Path(temp) / "root"
        root.mkdir()
        run("dpkg-deb", "-x", str(deb), str(root))
        entries: list[dict[str, str]] = []
        for current, directories, files in os.walk(root, topdown=True, followlinks=False):
            current_path = Path(current)
            for name in list(directories) + files:
                path = current_path / name
                relative = "/" + path.relative_to(root).as_posix()
                mode = path.lstat().st_mode
                if path.is_symlink():
                    entries.append({"kind": "symlink", "path": relative,
                                    "value": os.readlink(path)})
                    if name in directories:
                        directories.remove(name)
                elif path.is_dir():
                    entries.append({"kind": "dir", "path": relative, "value": ""})
                elif path.is_file():
                    entries.append({"kind": "file", "path": relative, "value": digest(path)})
                else:
                    raise ValueError("unsupported special file in binary package: " + relative)
        return sorted(entries, key=lambda item: item["path"])


def installed_manifest(path: Path) -> list[dict[str, str]]:
    rows = []
    with path.open(newline="", encoding="utf-8") as stream:
        for row in csv.reader(stream, delimiter="\t"):
            if len(row) != 3 or row[0] not in {"dir", "file", "symlink"}:
                raise ValueError("installed package content manifest is malformed")
            rows.append({"kind": row[0], "path": row[1], "value": row[2]})
    if not rows or len({row["path"] for row in rows}) != len(rows):
        raise ValueError("installed package content manifest is empty or contains duplicate paths")
    return sorted(rows, key=lambda item: item["path"])


def verify(args: argparse.Namespace) -> dict:
    if args.architecture not in {"amd64", "arm64"}:
        raise ValueError("unsupported target architecture")
    installed = parse_one_line(
        args.installed_package,
        ("binary_package", "binary_version", "architecture", "status",
         "source_package", "source_version"),
    )
    expected = {
        "binary_package": PACKAGE, "binary_version": VERSION,
        "architecture": args.architecture, "source_package": SOURCE,
        "source_version": SOURCE_VERSION,
    }
    for key, value in expected.items():
        if installed[key] != value:
            raise ValueError("installed " + key + " differs from expected Ubuntu package identity")
    if installed["status"] != "install ok installed":
        raise ValueError("linux-libc-dev is not in installed dpkg state")

    matches = []
    for record in apt_records(args.apt_package_metadata):
        if (record.get("Package") == PACKAGE and record.get("Version") == VERSION
                and record.get("Architecture") == args.architecture):
            source = record.get("Source", PACKAGE)
            if source_identity(source) == (SOURCE, SOURCE_VERSION):
                matches.append(record)
    if len(matches) != 1:
        raise ValueError("apt metadata does not identify exactly one expected binary/source package record")

    policy = args.apt_policy.read_text(encoding="utf-8")
    candidate = re.search(r"(?m)^\s*Candidate:\s*(\S+)\s*$", policy)
    if not candidate or candidate.group(1) != VERSION or POCKET not in policy:
        raise ValueError("apt policy does not corroborate the expected candidate and Resolute pocket")
    madison = args.apt_madison.read_text(encoding="utf-8")
    if VERSION not in madison or POCKET not in madison:
        raise ValueError("apt madison does not corroborate the expected version and Resolute pocket")

    deb_hash = digest(args.deb)
    if not SHA256.fullmatch(deb_hash):
        raise ValueError("invalid downloaded .deb digest")
    index_package_hash = matches[0].get("SHA256", "")
    if not SHA256.fullmatch(index_package_hash) or index_package_hash != deb_hash:
        raise ValueError("downloaded .deb SHA-256 does not match the signed apt package index record")
    control = run("dpkg-deb", "-f", str(args.deb), "Package", "Version", "Architecture", "Source").splitlines()
    if len(control) != 4 or control[:3] != [PACKAGE, VERSION, args.architecture]:
        raise ValueError("downloaded .deb control identity differs from expected package/version/architecture")
    if source_identity(control[3]) != (SOURCE, SOURCE_VERSION):
        raise ValueError("downloaded .deb Source field differs from expected Ubuntu source package/version")
    if not args.deb.name.startswith(f"{PACKAGE}_{VERSION}_{args.architecture}."):
        raise ValueError("downloaded .deb filename does not match expected package/version/architecture")

    index_records = []
    for line in args.index_sha256.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        value, name = line.split(maxsplit=1)
        if not SHA256.fullmatch(value):
            raise ValueError("apt index evidence contains an invalid SHA-256")
        index_records.append({"sha256": value, "index_name": Path(name).name})
    if not index_records:
        raise ValueError("no signed apt package index digests were captured")
    release_records = []
    for line in args.release_sha256.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        value, name = line.split(maxsplit=1)
        if not SHA256.fullmatch(value):
            raise ValueError("apt Release evidence contains an invalid SHA-256")
        release_records.append({"sha256": value, "release_name": Path(name).name})
    if not release_records:
        raise ValueError("no apt InRelease metadata digests were captured")

    base_image = args.base_image.read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"ubuntu@sha256:[a-f0-9]{64}", base_image):
        raise ValueError("Ubuntu base image is not pinned by immutable digest")

    package_entries = archive_manifest(args.deb)
    installed_entries = installed_manifest(args.installed_content_manifest)
    if package_entries != installed_entries:
        package_paths = {row["path"] for row in package_entries}
        installed_paths = {row["path"] for row in installed_entries}
        mismatch_count = sum(
            1 for path in package_paths & installed_paths
            if next(row for row in package_entries if row["path"] == path)
            != next(row for row in installed_entries if row["path"] == path)
        )
        raise ValueError(
            "installed package payload differs from downloaded .deb: "
            f"archive_only={len(package_paths - installed_paths)} "
            f"installed_only={len(installed_paths - package_paths)} "
            f"content_or_type_mismatches={mismatch_count}"
        )
    manifest_bytes = json.dumps(package_entries, sort_keys=True, separators=(",", ":")).encode()
    manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
    return {
        "schema": "baobab.dev10.ubuntu-binary-package-architecture-provenance.v1",
        "binary_package": PACKAGE,
        "binary_version": VERSION,
        "architecture": args.architecture,
        "source_package": SOURCE,
        "source_version": SOURCE_VERSION,
        "release_pocket": POCKET,
        "binary_status": installed["status"],
        "apt_candidate_version": candidate.group(1),
        "apt_package_metadata_sha256": digest(args.apt_package_metadata),
        "apt_policy_sha256": digest(args.apt_policy),
        "apt_madison_sha256": digest(args.apt_madison),
        "apt_package_deb_sha256": deb_hash,
        "apt_index_package_sha256": index_package_hash,
        "apt_package_deb_filename": args.deb.name,
        "apt_package_index_sha256": sorted(index_records, key=lambda item: item["index_name"]),
        "apt_inrelease_sha256": sorted(release_records, key=lambda item: item["release_name"]),
        "installed_package_metadata_sha256": digest(args.installed_package),
        "installed_content_manifest_sha256": digest(args.installed_content_manifest),
        "package_content_manifest_sha256": manifest_sha,
        "package_path_count": len(package_entries),
        "package_header_path_count": sum(row["path"].endswith(".h") for row in package_entries),
        "package_content_manifest": package_entries,
        "ubuntu_base_image": base_image,
        "binary_applicability": "under_investigation",
        "vex_disposition": "under_investigation",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--architecture", required=True)
    parser.add_argument("--installed-package", type=Path, required=True)
    parser.add_argument("--installed-content-manifest", type=Path, required=True)
    parser.add_argument("--apt-package-metadata", type=Path, required=True)
    parser.add_argument("--apt-policy", type=Path, required=True)
    parser.add_argument("--apt-madison", type=Path, required=True)
    parser.add_argument("--deb", type=Path, required=True)
    parser.add_argument("--index-sha256", type=Path, required=True)
    parser.add_argument("--release-sha256", type=Path, required=True)
    parser.add_argument("--base-image", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        evidence = verify(args)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")
        print("Verified Ubuntu binary package payload:",
              evidence["binary_package"], evidence["binary_version"],
              evidence["architecture"], evidence["package_path_count"], "paths")
        print("Binary applicability and VEX remain under investigation.")
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        print("Ubuntu architecture package verification denied:", error, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
