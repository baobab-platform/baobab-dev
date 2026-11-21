#!/usr/bin/env python3
"""Correlate current scan findings with locked Ubuntu header packages and source paths."""

import argparse
import base64
import csv
import hashlib
import json
import re
from pathlib import Path

from audit_kernel_cve_paths import COMMIT_URL_RE, CVE_RE, GITILES, SHA_RE, parse_upstream_details, read_locked_cna_record
from audit_ubuntu_kernel_fix_history import SOURCE_REPO, run
from reconcile_ubuntu_image_findings import payload_contents
from verify_ubuntu_binary_package_arch import archive_manifest, parse_control_fields, run as package_command
from verify_ubuntu_binary_source import digest

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "linux-libc-dev"
ARCHITECTURES = ("amd64", "arm64")
TARGETS = ("final", "frontend", "frontend-e2e", "infra")


def package_identity(root, arch, version, expected):
    deb = root / arch / f"{PACKAGE}_{version}_{arch}.deb"
    if digest(deb) != expected:
        raise ValueError(f"{arch}: archive differs from config/versions.lock")
    control = parse_control_fields(package_command("dpkg-deb", "-f", str(deb)))
    if (control.get("Package"), control.get("Version"), control.get("Architecture")) != (PACKAGE, version, arch):
        raise ValueError(f"{arch}: archive has unexpected package identity")
    if control.get("Source") not in {"linux", f"linux ({version})"}:
        raise ValueError(f"{arch}: archive has unexpected source identity")
    contents, includes = payload_contents(root, arch, expected, version=version)
    files = {entry["path"]: entry["value"] for entry in archive_manifest(deb)
             if entry["kind"] == "file" and entry["path"].startswith("/usr/include/")}
    return {"sha256": expected, **contents}, files, includes


def header_matches(source_paths, files, includes, arch):
    exported = {}
    linux_arch = "x86" if arch == "amd64" else "arm64"
    for path in source_paths:
        # Linux installs generic and architecture UAPI trees under usr/include.
        # Ubuntu can add a multiarch component before the exported suffix.
        if not path.startswith(("include/uapi/", f"arch/{linux_arch}/include/uapi/")):
            continue
        suffix = "/" + path.split("include/uapi/", 1)[1]
        exported[path] = {p: sha for p, sha in sorted(files.items()) if p.endswith(suffix)}
    basenames = {Path(path).name for path in source_paths if path.endswith(".h")}
    return {
        "exported_path_candidates": exported,
        "headers_with_literal_include_basename_matches": {
            name: sorted(includes[name]) for name in sorted(basenames & includes.keys())
        },
    }


def verify_native_payloads(root, source_sha, lock_digest, version, packages):
    if not SHA_RE.fullmatch(source_sha):
        raise ValueError("native evidence requires an immutable checkout SHA")
    results = {}
    for target in TARGETS:
        for arch in ARCHITECTURES:
            key = f"{target}-{arch}"
            directory = root / f"native-image-{key}"
            metadata = json.loads((directory / "native-image.json").read_text())
            package = directory / "linux-libc-dev.package.tsv"
            manifest = directory / "linux-libc-dev.manifest.tsv"
            hashes = {"package_tsv_sha256": digest(package), "manifest_tsv_sha256": digest(manifest)}
            expected = {"schema": "baobab.dev10.native-image.v1", "source_sha": source_sha,
                        "lock_sha256": lock_digest, "platform": f"linux/{arch}",
                        "profile": "full" if target == "final" else target, "linux_libc_dev": hashes}
            if any(metadata.get(name) != value for name, value in expected.items()):
                raise ValueError(f"{key}: native artifact identity or payload digest mismatch")
            with package.open(newline="") as stream:
                actual = list(csv.DictReader(stream, delimiter="\t"))
            if actual != [{"status": "install ok installed", "version": version, "architecture": arch,
                           "source_package": "linux", "source_version": version}]:
                raise ValueError(f"{key}: unexpected installed package identity")
            headers = {}
            with manifest.open(newline="") as stream:
                for row in csv.DictReader(stream, delimiter="\t"):
                    path = row["path"]
                    if path.startswith("/usr/include/") and row["kind"] != "directory":
                        if row["kind"] != "file" or path in headers:
                            raise ValueError(f"{key}: invalid installed header entry {path}")
                        headers[path] = row["sha256"]
            if headers != packages[arch][1]:
                raise ValueError(f"{key}: installed header path or bytes differ from the locked archive")
            results[key] = {**hashes, "image_config_digest": metadata["image_config_digest"],
                            "matching_header_files": len(headers)}
    return results


def audit(inventory, binary_root, cna, cna_revision, ubuntu, ubuntu_commit, *, native_root=None, source_sha=None):
    if not SHA_RE.fullmatch(cna_revision) or not SHA_RE.fullmatch(ubuntu_commit):
        raise ValueError("immutable Git revisions are required")
    lock = ROOT / "config/versions.lock"
    pins = dict(re.findall(r"^export (LINUX_LIBC_DEV_APT_\w+)=([^\s]+)$", lock.read_text(), re.M))
    version = pins["LINUX_LIBC_DEV_APT_VERSION"]
    if re.fullmatch(r"\d+\.\d+\.\d+-\d+\.\d+", version) is None:
        raise ValueError("unexpected Ubuntu package version format")
    with inventory.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream, delimiter="\t"))
    cves = {row["cve"] for row in rows}
    if not rows or len(rows) != len(cves) or not all(CVE_RE.fullmatch(cve) for cve in cves):
        raise ValueError("inventory must contain unique CVEs")
    for row in rows:
        if ((row["package"], row["installed"], row["ecosystem"]) != (PACKAGE, version, "ubuntu")
                or row["severity"] not in {"HIGH", "CRITICAL"}):
            raise ValueError("inventory CVE differs from the locked Ubuntu package")
    tag = f"Ubuntu-{version}"
    if (run(cna, "remote", "get-url", "origin") != GITILES
            or run(cna, "rev-parse", "HEAD") != cna_revision
            or run(ubuntu, "remote", "get-url", "origin") != SOURCE_REPO
            or run(ubuntu, "rev-parse", f"refs/tags/{tag}^{{commit}}") != ubuntu_commit):
        raise ValueError("source checkout differs from the expected upstream revision")
    packages = {arch: package_identity(binary_root, arch, version, pins[f"LINUX_LIBC_DEV_APT_SHA256_{arch.upper()}"])
                for arch in ARCHITECTURES}
    records = []
    for row in sorted(rows, key=lambda item: item["cve"]):
        raw = read_locked_cna_record(cna, row["cve"], cna_revision)
        if json.loads(raw)["cveMetadata"]["cveId"] != row["cve"]:
            raise ValueError(f"{row['cve']}: CNA record identity mismatch")
        paths, references = parse_upstream_details(base64.b64encode(raw))
        source_tree = run(ubuntu, "ls-tree", "-r", ubuntu_commit, "--", *paths)
        source_blobs = {path: info.split()[2] for info, path in
                        (line.split("\t", 1) for line in source_tree.splitlines())}
        records.append({
            "cve": row["cve"],
            "severity": row["severity"],
            "scanner_fixed_version": row["scanner_fixed_version"],
            "cna_record_sha256": hashlib.sha256(raw).hexdigest(),
            "upstream_fix_candidate_references": [ref for ref in references if COMMIT_URL_RE.search(ref)],
            "ubuntu_source_paths": {path: source_blobs.get(path) for path in paths},
            "architectures": {arch: header_matches(paths, files, includes, arch)
                              for arch, (_, files, includes) in packages.items()},
            "disposition": "under_investigation",
        })
    lock_digest = digest(lock)
    return {
        "schema": "baobab.dev10.kernel-header-applicability.v1",
        "package": PACKAGE,
        "package_version": version,
        "versions_lock_sha256": lock_digest,
        "inventory_sha256": digest(inventory),
        "cna_revision": cna_revision,
        "ubuntu_source_tag": tag,
        "ubuntu_source_commit": ubuntu_commit,
        "native_image_source_sha": source_sha,
        "native_images": (verify_native_payloads(native_root, source_sha, lock_digest, version, packages)
                          if native_root is not None else {}),
        "packages": {arch: summary for arch, (summary, _, _) in packages.items()},
        "disposition_limits": ["Source-path correspondence does not establish fix ancestry or a backport.",
                               "Indirect UAPI, ABI and downstream compilation exposure requires review."],
        "records": records,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("inventory", "binary-root", "cna", "ubuntu", "output"):
        parser.add_argument("--" + option, required=True, type=Path)
    parser.add_argument("--cna-revision", required=True)
    parser.add_argument("--ubuntu-commit", required=True)
    parser.add_argument("--native-root", type=Path)
    parser.add_argument("--source-sha")
    args = parser.parse_args()
    if bool(args.native_root) != bool(args.source_sha):
        parser.error("--native-root and --source-sha must be supplied together")
    result = audit(args.inventory, args.binary_root, args.cna, args.cna_revision, args.ubuntu, args.ubuntu_commit,
                   native_root=args.native_root, source_sha=args.source_sha)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
