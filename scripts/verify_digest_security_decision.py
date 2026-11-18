#!/usr/bin/env python3
"""Release-only exact-digest security decision gate.

This verifier is deliberately separate from the development-only DEV-10
policy evaluator. No development decision or trust anchor is read here. No
exception is inherited from a prior tag or image. A future release exception
requires its own protected exact-digest custody implementation; until then,
any residual HIGH/CRITICAL finding fails closed.
"""
import argparse
import datetime as dt
import hashlib
import json
import re
from pathlib import Path

DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}\Z")
TARGETS = {"final", "frontend", "frontend-e2e", "infra"}
ARCHITECTURES = {"linux/amd64", "linux/arm64"}
IMAGE_REPOSITORY = "ghcr.io/baobab-platform/baobab-dev"
TRIVY_VERSION = "0.73.0"
RELEASE_TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[1-9][0-9]*)?\Z")

def inventory_hash(packages):
    if not isinstance(packages, list) or not packages:
        raise ValueError("package inventory must be nonempty")
    canonical = []
    for item in packages:
        if not isinstance(item, dict) or set(item) != {"name", "version", "type"}:
            raise ValueError("package inventory requires name/version/type")
        if any(not isinstance(v, str) or not v.strip() for v in item.values()):
            raise ValueError("empty package identity")
        canonical.append(item)
    if len({(p["type"], p["name"], p["version"]) for p in canonical}) != len(canonical):
        raise ValueError("duplicate package")
    return "sha256:" + hashlib.sha256(json.dumps(sorted(canonical, key=lambda x:(x["type"],x["name"],x["version"])),
                                                  sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def findings(report):
    if (not isinstance(report, dict)
            or not isinstance(report.get("Results"), list)
            or not report["Results"]):
        raise ValueError("missing Trivy result inventory; release scan cannot be treated as clean")
    result = set()
    for target in report["Results"]:
        if not isinstance(target, dict):
            raise ValueError("invalid Trivy result target")
        secrets = target.get("Secrets") or []
        if not isinstance(secrets, list):
            raise ValueError("invalid Trivy secret inventory")
        if secrets:
            raise ValueError("secret findings block release publication and promotion")
        vulnerabilities = target.get("Vulnerabilities") or []
        if not isinstance(vulnerabilities, list):
            raise ValueError("invalid Trivy vulnerability inventory")
        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                raise ValueError("invalid Trivy vulnerability")
            if vuln.get("Severity") not in ("HIGH", "CRITICAL"):
                continue
            cve = vuln.get("VulnerabilityID")
            package = vuln.get("PkgName")
            version = vuln.get("InstalledVersion")
            if (not isinstance(cve, str) or not CVE.fullmatch(cve)
                    or not isinstance(package, str) or not package.strip()
                    or not isinstance(version, str) or not version.strip()):
                raise ValueError("unrecognized HIGH/CRITICAL vulnerability identity")
            result.add((cve, package, version))
    return result

def validate(decision, report, *, target, digest, release_tag,
             image_repository=IMAGE_REPOSITORY, architecture="linux/amd64",
             expected_trivy_version=TRIVY_VERSION, now):
    if not isinstance(report, dict):
        raise ValueError("invalid Trivy report")
    if (target not in TARGETS or not isinstance(digest, str) or not DIGEST.fullmatch(digest)
            or not isinstance(release_tag, str) or not RELEASE_TAG.fullmatch(release_tag)
            or image_repository != IMAGE_REPOSITORY
            or architecture not in ARCHITECTURES
            or expected_trivy_version != TRIVY_VERSION):
        raise ValueError("invalid release target/digest/repository/architecture")
    if (report.get("SchemaVersion") != 2
            or report.get("ArtifactType") != "container_image"
            or not isinstance(report.get("Trivy"), dict)
            or report["Trivy"].get("Version") != expected_trivy_version):
        raise ValueError("Trivy report schema, image type or scanner version is not qualified")
    metadata = report.get("Metadata")
    if not isinstance(metadata, dict):
        raise ValueError("Trivy image metadata is missing")
    repo_digests = metadata.get("RepoDigests")
    if (not isinstance(repo_digests, list)
            or f"{image_repository}@{digest}" not in repo_digests):
        raise ValueError("Trivy report does not identify the exact release child digest")
    image_config = metadata.get("ImageConfig")
    if (not isinstance(image_config, dict) or image_config.get("os") != "linux"
            or image_config.get("architecture") != architecture.split("/", 1)[1]):
        raise ValueError("Trivy report architecture differs from the release child digest")
    observed = findings(report)
    if not observed:
        return {"status": "no-high-critical-findings", "digest": digest}
    if not isinstance(decision, dict) or set(decision) != {
        "schema_version", "release_tag", "target", "digest", "package_inventory",
        "inventory_sha256", "exceptions", "approver", "approved_at", "expires_at",
        "evidence_url"}:
        raise ValueError("exact-digest security decision required")
    raise ValueError("legacy free-text release decisions are not authenticated; protected custody required")

def main():
    p=argparse.ArgumentParser()
    for arg in ("report","target","digest","release-tag","image-repository","architecture"):
        p.add_argument("--"+arg, required=True)
    p.add_argument("--decision")
    a=p.parse_args()
    try:
        report=json.loads(Path(a.report).read_text())
        decision=json.loads(Path(a.decision).read_text()) if a.decision else None
        result=validate(decision,report,target=a.target,digest=a.digest,
                        release_tag=a.release_tag,image_repository=a.image_repository,
                        architecture=a.architecture,now=dt.datetime.now(dt.timezone.utc))
    except (ValueError, OSError, TypeError) as exc:
        p.error(str(exc))
    print(json.dumps(result,sort_keys=True))
if __name__=="__main__":
    main()
