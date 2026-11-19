#!/usr/bin/env python3
"""Bind release builds, scanner and native execution to an OCI layout."""

import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile

from verify_digest_security_decision import DIGEST, TARGETS, TRIVY_VERSION, findings

INDEX = "application/vnd.oci.image.index.v1+json"
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
CONFIG = "application/vnd.oci.image.config.v1+json"
SCAN_TAG = "baobab-dev:scan"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def blob(layout, descriptor, *, media_type=None):
    digest = descriptor.get("digest")
    require(isinstance(digest, str) and DIGEST.fullmatch(digest), "invalid OCI blob digest")
    if media_type:
        require(descriptor.get("mediaType") == media_type, "unexpected OCI descriptor media type")
    path = layout / "blobs" / "sha256" / digest[7:]
    require(not any(p.is_symlink() for p in (path, path.parent, path.parent.parent, layout))
            and path.is_file() and descriptor.get("size") == path.stat().st_size,
            "missing, linked or incorrectly sized OCI blob")
    require(sha256(path) == digest[7:], "OCI blob bytes differ from descriptor digest")
    return path


def inspect(layout, target, architecture, source_sha, lock_sha, expected_index):
    require(target in TARGETS and architecture in ("amd64", "arm64")
            and re.fullmatch(r"[0-9a-f]{40}", source_sha) and re.fullmatch(r"[0-9a-f]{64}", lock_sha),
            "invalid release target, architecture, source or lock digest")
    require(not (layout / "index.json").is_symlink(), "linked OCI layout index")
    top = json.loads((layout / "index.json").read_bytes())
    descriptors = top["manifests"]
    require(len(descriptors) == 1, "expected one attested build index")
    index, = descriptors
    require(index.get("digest") == expected_index, "OCI layout index differs from build digest")
    native, attestations = [], []
    for item in json.loads(blob(layout, index, media_type=INDEX).read_bytes())["manifests"]:
        platform = item.get("platform", {})
        if platform.get("os") == "linux" and platform.get("architecture") == architecture:
            native.append(item)
        elif item.get("annotations", {}).get("vnd.docker.reference.type") == "attestation-manifest":
            attestations.append(item)
        else:
            raise ValueError("unexpected entry in single-architecture OCI index")
    require(len(native) == len(attestations) == 1, "build must have one native child and one attestation sibling")
    child, = native
    attestation, = attestations
    require(attestation["annotations"].get("vnd.docker.reference.digest") == child["digest"],
            "attestation sibling refers to a different child")
    predicate = json.loads(blob(layout, attestation, media_type=MANIFEST).read_bytes())
    blob(layout, predicate["config"], media_type=CONFIG)
    types = []
    for item in predicate["layers"]:
        blob(layout, item)
        types.append(item.get("annotations", {}).get("in-toto.io/predicate-type"))
    require(len(types) == 2 and set(types) == {"https://slsa.dev/provenance/v1", "https://spdx.dev/Document"},
            "attested build must carry SLSA v1 provenance and SPDX SBOM")

    manifest = json.loads(blob(layout, child, media_type=MANIFEST).read_bytes())
    config = blob(layout, manifest["config"], media_type=CONFIG)
    details = json.loads(config.read_bytes())
    variables = details["config"].get("Env", [])
    profile = "full" if target == "final" else target
    require(details.get("architecture") == architecture and details.get("os") == "linux"
            and details["config"].get("Labels", {}).get("org.opencontainers.image.revision") == source_sha
            and f"BAOBAB_BUILD_PROFILE={profile}" in variables,
            "OCI config differs from expected source, platform or profile")
    layers = [blob(layout, item) for item in manifest["layers"]]
    require(bool(layers), "release image has no layers")
    return {
        "target": target, "platform": f"linux/{architecture}", "source_sha": source_sha,
        "lock_sha256": lock_sha, "index_digest": index["digest"],
        "child_digest": child["digest"], "config_digest": manifest["config"]["digest"],
    }, config, layers


def docker_archive(archive, layout, config, layers):
    metadata = [{
        "Config": config.relative_to(layout).as_posix(), "RepoTags": [SCAN_TAG],
        "Layers": [layer.relative_to(layout).as_posix() for layer in layers],
    }]
    data = json.dumps(metadata, separators=(",", ":")).encode()
    member = tarfile.TarInfo("manifest.json")
    member.size = len(data)
    with tarfile.open(archive, "x") as output:
        output.addfile(member, io.BytesIO(data))
        for path in dict.fromkeys([config, *layers]):
            output.add(path, arcname=path.relative_to(layout).as_posix(), recursive=False)


def qualified(plan, runtime, scanner, archive, scanner_version):
    expected = {
        "source_sha": plan["source_sha"], "lock_sha256": plan["lock_sha256"],
        "platform": plan["platform"], "image_config_digest": plan["config_digest"],
        "profile": "full" if plan["target"] == "final" else plan["target"],
        "scan_archive_sha256": sha256(archive), "health": "healthy", "runtime": "passed",
    }
    require(all(runtime.get(key) == value for key, value in expected.items()),
            "native runtime receipt differs from the exact built and scanned archive")
    require(scanner_version == TRIVY_VERSION and scanner.get("SchemaVersion") == 2
            and scanner.get("ArtifactType") == "container_image"
            and scanner.get("ArtifactName") == str(archive)
            and scanner["Metadata"].get("ImageID") == plan["config_digest"]
            and scanner["Metadata"]["ImageConfig"].get("architecture") == plan["platform"].split("/")[1]
            and scanner["Metadata"]["ImageConfig"].get("os") == "linux",
            "Trivy did not scan the exact native OCI child")
    require(not findings(scanner), "unfiltered HIGH/CRITICAL findings require release authorization")
    return {"schema": "baobab.dev10.qualified-oci-layout.v1", **plan,
            "archive_sha256": expected["scan_archive_sha256"],
            "security": "unfiltered-clean", "runtime": "passed"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "qualify", "readback"))
    for name in ("layout", "plan", "archive", "runtime", "scan"):
        parser.add_argument("--" + name, type=Path)
    for name in ("target", "architecture", "source", "lock", "index", "scanner-version"):
        parser.add_argument("--" + name)
    args = parser.parse_args()
    try:
        if args.mode == "prepare":
            plan, config, layers = inspect(
                args.layout, args.target, args.architecture, args.source, args.lock, args.index,
            )
            docker_archive(args.archive, args.layout, config, layers)
            args.plan.write_text(json.dumps(plan))
        elif args.mode == "qualify":
            plan = json.loads(args.plan.read_bytes())
            result = qualified(plan, json.loads(args.runtime.read_bytes()), json.loads(args.scan.read_bytes()),
                               args.archive, args.scanner_version)
            (args.layout / "qualification.json").write_text(json.dumps(result, sort_keys=True) + "\n")
        else:
            receipt = json.loads((args.layout / "qualification.json").read_bytes())
            plan, _, _ = inspect(args.layout, args.target, args.architecture, args.source, args.lock,
                                 receipt.get("index_digest"))
            require(receipt.get("schema") == "baobab.dev10.qualified-oci-layout.v1"
                    and receipt.get("security") == "unfiltered-clean" and receipt.get("runtime") == "passed"
                    and all(receipt.get(key) == value for key, value in plan.items()),
                    "published OCI bytes lack a matching build, test and security receipt")
            print(plan["index_digest"])
    except (OSError, TypeError, KeyError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
