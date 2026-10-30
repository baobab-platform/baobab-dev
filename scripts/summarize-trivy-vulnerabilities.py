#!/usr/bin/env python3
"""Preserve all Trivy HIGH/CRITICAL findings and package provenance as CI JSON.

This is an evidence formatter, not an exception engine. Trivy's original exit
status remains the blocking security decision.
"""
from __future__ import annotations
import json
import sys
from collections import Counter
from pathlib import Path


def summarize(data: object, target: str, platform: str) -> dict:
    if not isinstance(data, dict) or not isinstance(data.get("Results"), list):
        raise ValueError("Missing/invalid Trivy Results: fail closed")
    if not data["Results"]:
        raise ValueError("Empty Trivy Results: no image inventory evidence")
    findings: list[dict] = []
    for result in data["Results"]:
        if not isinstance(result, dict) or not isinstance(result.get("Target"), str):
            raise ValueError("Invalid Trivy scan target")
        vulnerabilities = result.get("Vulnerabilities") or []
        if not isinstance(vulnerabilities, list):
            raise ValueError("Invalid Trivy vulnerability list")
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                raise ValueError("Invalid Trivy finding")
            findings.append({
                "target": result["Target"],
                "type": result.get("Type"),
                "vulnerability_id": vulnerability.get("VulnerabilityID"),
                "package": vulnerability.get("PkgName"),
                "package_id": vulnerability.get("PkgID"),
                "package_path": vulnerability.get("PkgPath"),
                "installed_version": vulnerability.get("InstalledVersion"),
                "fixed_version": vulnerability.get("FixedVersion"),
                "severity": vulnerability.get("Severity"),
                "severity_source": vulnerability.get("SeveritySource"),
                "status": vulnerability.get("Status"),
                "primary_url": vulnerability.get("PrimaryURL"),
                "data_source": result.get("DataSource"),
            })
    counts = Counter(item["severity"] for item in findings)
    packages: dict[tuple[str, str], int] = {}
    for item in findings:
        key = (item["package"] or "", item["installed_version"] or "")
        packages[key] = packages.get(key, 0) + 1
    return {
        "schema": "baobab.trivy.evidence.v1",
        "image_target": target,
        "platform": platform,
        "trivy_schema_version": data.get("SchemaVersion"),
        "total_findings": len(findings),
        "severity_counts": dict(sorted(counts.items())),
        "package_inventory": [
            {"name": name, "installed_version": version, "finding_count": count}
            for (name, version), count in sorted(packages.items())
        ],
        "findings": findings,
    }


def main(argv: list[str]) -> int:
    if len(argv) != 5:
        print("Usage: summarize-trivy-vulnerabilities.py INPUT OUTPUT TARGET PLATFORM", file=sys.stderr)
        return 2
    try:
        source = Path(argv[1])
        output = Path(argv[2])
        summary = summarize(json.loads(source.read_text()), argv[3], argv[4])
        output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
        print(f"Trivy evidence: {summary['total_findings']} findings; "
              f"severities={summary['severity_counts']}; "
              f"full results at {source}; normalized evidence at {output}")
        for package in summary["package_inventory"]:
            print(f"  {package['name']} {package['installed_version']}: "
                  f"{package['finding_count']} advisory matches")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"::error::Trivy evidence unavailable or invalid: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
