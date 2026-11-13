#!/usr/bin/env python3
"""Bounded DEV-10 executive risk acceptance of *known*, unremediated OS advisories.

This is not VEX "not_affected", an Ubuntu patch, or a staging/production
approval. Preserve complete Trivy findings and deny new/unrecognised CVEs.
Applies only to open dev PRs #65–#67, development-main and one exact
tagged DEVELOPMENT CONTAINER distributions v1.5.0-rc.N and v1.5.0,
before 2026-11-26 UTC.
Approval source: user's explicit Baobab-dev distribution clarification
(2026-11-03). A tag is a development image distribution, not deployment.
Directive / audit: https://github.com/baobab-platform/baobab-dev/issues/54
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import sys

INVENTORY_BLOB_SHA1 = "a98090feb9e3df2d9df72654516df69c64daf50e"
EXPIRY = dt.datetime(2026, 11, 26, 0, 0, tzinfo=dt.timezone.utc)
PACKAGE = "linux-libc-dev"
VERSION = "7.0.0-42.42"
# Owner-authorised 12 Nov 2026: exact new Ubuntu package and eight HIGH CVEs.
# Independent of the immutable 295-CVE inventory for 7.0.0-42.42.
ADDITIONAL_VERSION = "7.0.0-43.43"
ADDITIONAL_CVES = frozenset({
    "CVE-2022-50240",
    "CVE-2025-40190",
    "CVE-2026-68103",
    "CVE-2026-72198",
    "CVE-2026-74578",
    "CVE-2026-89805",
    "CVE-2026-98376",
    "CVE-2026-98420",
})
CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
TARGETS = {"final", "infra", "frontend", "frontend-e2e"}
PLATFORMS = {"linux/amd64", "linux/arm64"}
# Only open PRs #65/#66/#67 remain eligible; closed #62/#63 and merged PRs are retired.
# Owner-directed publication: RC candidates first, then GA for development
# consumers. No other pre-releases, future tags or production deployments.
APPROVED_DEVELOPMENT_PRS = frozenset({65, 66, 67})
APPROVED_DEVELOPMENT_IMAGE_REF = "refs/tags/v1.5.0"
APPROVED_DEVELOPMENT_RC_REF = re.compile(r"^refs/tags/v1[.]5[.]0-rc[.][1-9][0-9]*$")


class RiskGateError(ValueError):
    pass


def require(ok: bool, why: str) -> None:
    if not ok:
        raise RiskGateError(why)


def inventory(path: Path) -> dict[str, str]:
    raw = path.read_bytes()
    object_id = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    require(object_id == INVENTORY_BLOB_SHA1,
            "CVE inventory content changed; reauthorise explicit risk scope")
    rows = list(csv.DictReader(raw.decode("utf-8").splitlines(), delimiter="\t"))
    allowed = {row["cve"]: row["severity"] for row in rows}
    require(len(rows) == len(allowed) == 295
            and all(CVE.fullmatch(k) and v in {"HIGH", "CRITICAL"}
                    for k, v in allowed.items()),
            "incomplete, duplicated or malformed approved inventory")
    require(sum(x == "CRITICAL" for x in allowed.values()) == 12,
            "approved severity inventory changed")
    return allowed


def validate(report: dict, allowed: dict[str, str], *, target: str, platform: str,
             event: str, ref: str, repository: str, pr_number: int,
             now: dt.datetime | None = None) -> dict:
    now = now or dt.datetime.now(dt.timezone.utc)
    require(now.tzinfo is not None and now < EXPIRY, "risk decision expired")
    require(repository == "baobab-platform/baobab-dev",
            "outside Baobab development repository")
    is_qualified_dev_pr = (event == "pull_request" and pr_number in APPROVED_DEVELOPMENT_PRS
                           and ref == f"refs/pull/{pr_number}/merge")
    is_dev_main = event == "push" and ref == "refs/heads/main" and pr_number == 0
    is_dev_image_release = (event == "push" and pr_number == 0
                            and (ref == APPROVED_DEVELOPMENT_IMAGE_REF
                                 or APPROVED_DEVELOPMENT_RC_REF.fullmatch(ref) is not None))
    require(is_qualified_dev_pr or is_dev_main or is_dev_image_release,
            "risk acceptance only valid for open PRs #65-#67, untagged "
            "development main or v1.5.0-rc.N / v1.5.0 devcontainer GHCR distribution")
    require(target in TARGETS and platform in PLATFORMS,
            "unapproved target or architecture")
    results = report.get("Results")
    require(isinstance(results, list) and results, "missing complete Trivy Results inventory")
    observed: dict[str, str] = {}
    observed_version: str | None = None
    for result in results:
        require(isinstance(result, dict) and isinstance(result.get("Target"), str),
                "invalid Trivy target")
        require(not result.get("Secrets"), "secret findings cannot be risk accepted")
        vulns = result.get("Vulnerabilities") or []
        require(isinstance(vulns, list), "invalid Trivy vulnerabilities")
        for finding in vulns:
            require(isinstance(finding, dict), "invalid Trivy finding")
            cve = finding.get("VulnerabilityID")
            require(isinstance(cve, str) and CVE.fullmatch(cve) is not None,
                    "unrecognised security finding")
            version = finding.get("InstalledVersion")
            permitted = (allowed if version == VERSION else
                         {key: "HIGH" for key in ADDITIONAL_CVES}
                         if version == ADDITIONAL_VERSION else {})
            require(cve in permitted, "unapproved HIGH/CRITICAL CVE: " + cve)
            require(observed_version is None or observed_version == version,
                    "mixed kernel-header package versions in one report")
            observed_version = version
            require(result.get("Type") == "ubuntu"
                    and finding.get("PkgName") == PACKAGE
                    and version in {VERSION, ADDITIONAL_VERSION},
                    "unapproved affected package, OS or version: " + cve)
            require(finding.get("Severity") == permitted[cve],
                    "CVE severity changed; risk scope requires review: " + cve)
            require(not finding.get("FixedVersion"),
                    "supported fixed-version signal; remediate instead: " + cve)
            require(cve not in observed, "duplicate or ambiguous CVE finding: " + cve)
            observed[cve] = finding["Severity"]
    require(observed, "unexpected empty risk-acceptance scan; use ordinary clean scan path")
    if observed_version == ADDITIONAL_VERSION:
        require(set(observed) == ADDITIONAL_CVES,
                "incomplete or changed 7.0.0-43.43 eight-CVE inventory")
    return {
        "decision": "development_risk_accepted_not_remediated",
        "authority": "owner-directed development-only risk treatment; not independently signed",
        "issue": "https://github.com/baobab-platform/baobab-dev/issues/54",
        "package": PACKAGE, "version": observed_version, "profile": target, "platform": platform,
        "known_cves_observed": len(observed),
        "critical": sum(x == "CRITICAL" for x in observed.values()),
        "expiry_utc": EXPIRY.isoformat(),
        "scope": "DEV TOOLCHAIN ONLY; v1.5.0-rc.N and v1.5.0 GHCR distribution; "
                 "no staging/production deployment or other tags",
        "distribution": (("v1.5.0_release_candidate" if ref != APPROVED_DEVELOPMENT_IMAGE_REF
                          else "v1.5.0_tagged_development_container")
                         if is_dev_image_release else "development_ci"),
        "technical_applicability": "under_investigation",
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--raw-trivy", type=Path, required=True)
    p.add_argument("--inventory", type=Path, required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--platform", required=True)
    p.add_argument("--event", required=True)
    p.add_argument("--ref", required=True)
    p.add_argument("--repository", required=True)
    p.add_argument("--pr-number", type=int, default=0)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    try:
        raw = json.loads(a.raw_trivy.read_text())
        decision = validate(raw, inventory(a.inventory),
                            target=a.target, platform=a.platform,
                            event=a.event, ref=a.ref, repository=a.repository,
                            pr_number=a.pr_number)
        a.output.parent.mkdir(parents=True, exist_ok=True)
        a.output.write_text(json.dumps(decision, indent=2, sort_keys=True) + "\n")
        print("::warning::DEV-10 explicit risk accepted, NOT REMEDIATED:",
              decision["known_cves_observed"], "known kernel-header advisory matches;",
              "review issue #54; expiry", decision["expiry_utc"])
        return 0
    except (OSError, ValueError, KeyError, TypeError) as e:
        print("::error::DEV-10 security risk acceptance DENIED:", e, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
