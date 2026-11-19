#!/usr/bin/env python3
"""Reproducibly bind the installed Ubuntu binary package to its source package.

This verifies dpkg's installed source fields against the exact apt package
metadata, candidate/pocket, downloaded .deb and apt index digests. It does not
prove that a particular CVE fix was backported or shipped in a header.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dev10_evidence_lock import DEBIAN_VERSION, EvidenceLock, UBUNTU_BINARY_POCKETS

LOCK = EvidenceLock.load()
SHA256 = re.compile(r"^[a-f0-9]{64}$")
SOURCE_FIELD = re.compile(r"^([a-z0-9+.-]+)(?:\s+\(([^)]+)\))?$")
PACKAGE_ORIGIN = re.compile(
    r"https?://(?:archive\.ubuntu\.com|security\.ubuntu\.com|ports\.ubuntu\.com)"
    r"/(?:ubuntu|ubuntu-ports) (resolute-[a-z]+)/main (amd64|arm64) Packages"
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def installed_fields(path: Path) -> dict[str, str]:
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line]
    if len(lines) != 1:
        raise ValueError("installed dpkg package metadata must contain exactly one record")
    values = lines[0].split("\t")
    names = ("binary_package", "binary_version", "architecture", "status",
             "source_package", "source_version")
    if len(values) != len(names):
        raise ValueError("installed dpkg package metadata has an unexpected field count")
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


def source_identity(value: str, binary_version: str) -> tuple[str, str]:
    match = SOURCE_FIELD.fullmatch(value.strip())
    if not match:
        raise ValueError("apt package metadata has an invalid Source field")
    return match.group(1), match.group(2) or binary_version


def authenticated_apt_binary(args: argparse.Namespace, expected: dict, deb_hash: str) -> tuple[str, list[str]]:
    archive = f"{expected['binary_package']}_{expected['binary_version']}_{expected['architecture']}.deb"
    records = apt_records(args.apt_package_metadata)
    matches = set()
    for record in records:
        if (record.get("Package") != expected["binary_package"]
                or record.get("Version") != expected["binary_version"]
                or record.get("Architecture") != expected["architecture"]):
            continue
        source = record.get("Source")
        if not source:
            raise ValueError("apt package metadata is missing its Source field")
        if source_identity(source, expected["binary_version"]) == (
            expected["source_package"], expected["source_version"]
        ):
            filename = record.get("Filename", "")
            matches.add((Path(filename).name, record.get("SHA256", "")))
    if matches != {(archive, deb_hash)}:
        raise ValueError("apt package metadata does not corroborate the locked source package/version")

    policy = args.apt_policy.read_text(encoding="utf-8")
    candidates = re.findall(r"(?m)^\s*Candidate:\s*(\S+)\s*$", policy)
    if len(candidates) != 1 or not DEBIAN_VERSION.fullmatch(candidates[0]):
        raise ValueError("apt candidate version is missing or ambiguous")

    pockets = set()
    for line in args.apt_madison.read_text(encoding="utf-8").splitlines():
        fields = [field.strip() for field in line.split("|", 2)]
        if fields[:2] != [expected["binary_package"], expected["binary_version"]] or len(fields) != 3:
            continue
        if (origin := PACKAGE_ORIGIN.fullmatch(fields[2])) and (
            origin[1] in UBUNTU_BINARY_POCKETS and origin[2] == expected["architecture"]
        ):
            pockets.add(origin[1])
    if not pockets:
        raise ValueError("apt madison does not identify the exact binary in a Canonical Resolute pocket")
    return candidates[0], sorted(pockets)


def verify(args: argparse.Namespace) -> dict:
    expected = LOCK.binary_source
    installed = installed_fields(args.installed_package)
    for key in ("binary_package", "binary_version", "architecture",
                "source_package", "source_version"):
        if installed.get(key) != expected[key]:
            raise ValueError("installed dpkg " + key + " differs from reviewed binary/source lock")
    if installed.get("status") != "install ok installed":
        raise ValueError("linux-libc-dev is not in the installed dpkg state")

    deb_lines = [line for line in args.deb_sha256.read_text(encoding="utf-8").splitlines() if line]
    if len(deb_lines) != 1:
        raise ValueError("downloaded binary package must have exactly one SHA-256 record")
    deb_hash, deb_name = deb_lines[0].split(maxsplit=1)
    deb_filename = Path(deb_name.strip().lstrip("*")).name
    if (deb_hash != LOCK.binary_artifact_sha256[expected["architecture"]]
            or deb_filename != f"{expected['binary_package']}_{expected['binary_version']}_{expected['architecture']}.deb"):
        raise ValueError("downloaded binary package digest/name differs from evidence lock")
    candidate, pockets = authenticated_apt_binary(args, expected, deb_hash)

    index_records = []
    for line in args.index_sha256.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        value, name = line.split(maxsplit=1)
        if not SHA256.fullmatch(value):
            raise ValueError("apt package index contains an invalid SHA-256")
        index_records.append({"sha256": value, "index_name": Path(name).name})
    if not index_records:
        raise ValueError("no apt package index digests were captured")

    base_image = args.base_image.read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"ubuntu@sha256:[a-f0-9]{64}", base_image):
        raise ValueError("Ubuntu audit base image is not pinned by immutable digest")

    return {
        "schema": "baobab.dev10.ubuntu-binary-source-provenance.v1",
        **expected,
        "binary_status": installed["status"],
        "apt_candidate_version": candidate,
        "apt_exact_version_pockets": pockets,
        "apt_package_metadata_sha256": digest(args.apt_package_metadata),
        "apt_policy_sha256": digest(args.apt_policy),
        "apt_madison_sha256": digest(args.apt_madison),
        "apt_package_deb_sha256": deb_hash,
        "apt_package_deb_filename": deb_filename,
        "apt_package_index_sha256": sorted(index_records, key=lambda item: item["index_name"]),
        "installed_package_metadata_sha256": digest(args.installed_package),
        "ubuntu_base_image": base_image,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--installed-package", type=Path, required=True)
    parser.add_argument("--apt-package-metadata", type=Path, required=True)
    parser.add_argument("--apt-policy", type=Path, required=True)
    parser.add_argument("--apt-madison", type=Path, required=True)
    parser.add_argument("--deb-sha256", type=Path, required=True)
    parser.add_argument("--index-sha256", type=Path, required=True)
    parser.add_argument("--base-image", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        evidence = verify(args)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")
        print("Ubuntu binary/source package identity verified:",
              evidence["binary_package"], "=>", evidence["source_package"],
              evidence["source_version"])
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("Ubuntu binary/source package verification denied:", error, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
