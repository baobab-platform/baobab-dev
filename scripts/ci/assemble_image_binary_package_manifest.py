#!/usr/bin/env python3
"""Assemble the installed package manifest captured from one immutable image."""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
from pathlib import Path
import re
import sys

SHA256 = re.compile(r"^[0-9a-f]{64}$")
IMAGE = re.compile(r"^ghcr\.io/baobab-platform/baobab-dev@sha256:[0-9a-f]{64}$")
PROFILES = {"final", "frontend", "frontend-e2e", "infra"}

def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def tsv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream, delimiter="\t"))

def assemble(args: argparse.Namespace) -> dict:
    if args.profile not in PROFILES or args.architecture not in {"amd64", "arm64"}:
        raise ValueError("unsupported image profile or architecture")
    if not IMAGE.fullmatch(args.image_ref):
        raise ValueError("image reference must be an immutable Baobab GHCR digest")
    package_rows = tsv(args.package_metadata)
    if len(package_rows) != 1:
        raise ValueError("installed package metadata must contain exactly one row")
    package = package_rows[0]
    expected = {
        "status": "install ok installed",
        "version": args.expected_version,
        "architecture": args.architecture,
        "source_package": "linux",
        "source_version": args.expected_version,
    }
    for key, value in expected.items():
        if package.get(key) != value:
            raise ValueError("installed package " + key + " differs from the pinned identity")
    entries = []
    for row in tsv(args.manifest):
        path = row.get("path", "")
        if not path.startswith("/") or "\\" in path or any(p in {"", ".", ".."} for p in path.split("/")[1:]):
            raise ValueError("unsafe installed package path")
        raw_kind = row.get("kind")
        if raw_kind == "directory":
            kind, value = "dir", ""
        elif raw_kind == "file":
            kind, value = "file", row.get("sha256", "")
            if not SHA256.fullmatch(value):
                raise ValueError("invalid installed file SHA-256 for " + path)
        elif raw_kind == "symlink":
            kind, value = "symlink", row.get("link_target", "")
            if not value:
                raise ValueError("empty installed symlink target for " + path)
        elif raw_kind == "missing":
            kind, value = "missing", ""
        else:
            raise ValueError("unsupported installed package manifest kind")
        entries.append({"kind": kind, "path": path, "value": value})
    if not entries or len({item["path"] for item in entries}) != len(entries):
        raise ValueError("installed package manifest is empty or has duplicate paths")
    entries.sort(key=lambda item: item["path"])
    manifest_bytes = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    return {
        "schema": "baobab.dev10.ubuntu-binary-package-architecture-provenance.v1",
        "binary_package": "linux-libc-dev",
        "binary_version": package["version"],
        "architecture": args.architecture,
        "source_package": package["source_package"],
        "source_version": package["source_version"],
        "binary_status": package["status"],
        "profile": args.profile,
        "image_ref": args.image_ref,
        "package_path_count": len(entries),
        "package_header_path_count": sum(item["path"].endswith(".h") for item in entries),
        "package_content_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "package_content_manifest_tsv_sha256": sha256(args.manifest),
        "package_metadata_tsv_sha256": sha256(args.package_metadata),
        "package_content_manifest": entries,
        "binary_applicability": "under_investigation",
        "vex_disposition": "under_investigation",
    }

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True)
    parser.add_argument("--architecture", required=True)
    parser.add_argument("--image-ref", required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--package-metadata", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = assemble(args)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("Captured immutable image package manifest:", args.profile, args.architecture, result["package_path_count"])
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("Image package manifest assembly denied:", error, file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
