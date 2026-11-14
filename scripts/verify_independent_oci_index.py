#!/usr/bin/env python3
"""DEV-10 independently verify an OCI index contains both required architectures.

This validates the registry-returned index, not a producer's claimed platform
list. Signature, SPDX and SLSA attestations are checked separately with Cosign.
"""
import argparse
import json

REQUIRED = {("linux", "amd64"), ("linux", "arm64")}

def validate(payload):
    if not isinstance(payload, dict) or payload.get("mediaType") not in (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    ):
        raise ValueError("expected multi-platform OCI index")
    manifests = payload.get("manifests")
    if not isinstance(manifests, list):
        raise ValueError("missing OCI manifests")
    platforms = set()
    for item in manifests:
        if not isinstance(item, dict):
            raise ValueError("invalid OCI descriptor")
        platform = item.get("platform", {})
        if not isinstance(platform, dict):
            raise ValueError("invalid platform descriptor")
        os, arch = platform.get("os"), platform.get("architecture")
        if os == "unknown" and arch == "unknown":
            continue  # BuildKit attestations are not runnable platforms.
        if not isinstance(os, str) or not isinstance(arch, str):
            raise ValueError("missing platform identity")
        pair = (os, arch)
        if pair in platforms:
            raise ValueError("duplicate runnable platform")
        digest = item.get("digest")
        if not isinstance(digest, str) or len(digest) != 71 or not digest.startswith("sha256:"):
            raise ValueError("invalid platform digest")
        if any(c not in "0123456789abcdef" for c in digest[7:]):
            raise ValueError("invalid platform digest")
        platforms.add(pair)
    if platforms != REQUIRED:
        raise ValueError("OCI platforms differ from required linux/amd64 and linux/arm64: " + repr(platforms))
    return True

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    args = parser.parse_args()
    try:
        with open(args.input, encoding="utf-8") as f:
            validate(json.load(f))
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print("Independent OCI index architecture verification passed")

if __name__ == "__main__":
    main()
