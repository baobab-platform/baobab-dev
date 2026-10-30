#!/usr/bin/env python3
"""DEV-14 non-mutating engine toolchain diagnostic.

No image pulls, credential access, IAM/CP creation, Docker mutations or
provider certification. Report missing prerequisites; never infer readiness.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

SHARED_PIN = "32b71f3335e566daeb58246f17fcbbf162cf7f53"
SHA = re.compile(r"^[0-9a-f]{40}$")
VERSION = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")
REQUIREMENTS = {
    "pulse-intelligence": {"python": (3, 14), "docker": None, "git": None},
    "payments-sandbox": {"rustc": (1, 88), "cargo": None, "docker": None, "git": None},
}


def probe(command: list[str], *, timeout: int = 12) -> tuple[bool, str]:
    """Return only a scrubbed first-line version string, never raw errors."""
    try:
        proc = subprocess.run(command, capture_output=True, text=True,
                              timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False, "UNAVAILABLE"
    if proc.returncode:
        return False, "UNAVAILABLE"
    first = proc.stdout.strip().splitlines()
    return True, (first[0][:120] if first else "OBSERVED")


def meets_version(text: str, minimum: tuple[int, int]) -> bool:
    match = VERSION.search(text)
    return bool(match and tuple(map(int, match.groups()[:2])) >= minimum)


def python_line_supported(observed: str) -> bool:
    """DEV-14 qualifies Python 3.14.x, not newer unqualified major/minor lines."""
    match = VERSION.search(observed)
    return bool(match and tuple(map(int, match.groups()[:2])) == (3, 14))


def inspect(profile: str, shared_root: Path | None = None) -> dict:
    if profile not in REQUIREMENTS:
        raise ValueError("UNKNOWN_DEV14_PROFILE")
    checks = {}
    for tool, minimum in REQUIREMENTS[profile].items():
        executable = sys.executable if tool == "python" else shutil.which(tool)
        if executable is None:
            checks[tool] = "MISSING"
            continue
        command = ([executable, "--version"] if tool == "python" else
                   [executable, "--version"])
        ok, observed = probe(command)
        version_supported = (
            python_line_supported(observed) if tool == "python"
            else minimum is None or meets_version(observed, minimum)
        )
        checks[tool] = ("SUPPORTED" if ok and version_supported
                        else "VERSION_UNSUPPORTED" if ok else "UNAVAILABLE")
    docker_ok, _ = probe(["docker", "info", "--format", "{{.ServerVersion}}"]) if checks["docker"] == "SUPPORTED" else (False, "")
    compose_ok, _ = probe(["docker", "compose", "version", "--short"]) if checks["docker"] == "SUPPORTED" else (False, "")
    checks["docker_daemon"] = "OBSERVED" if docker_ok else "UNAVAILABLE"
    checks["docker_compose"] = "OBSERVED" if compose_ok else "UNAVAILABLE"

    if shared_root is None:
        checks["shared_contract_pin"] = "NOT_INSPECTED"
    else:
        if shared_root.is_symlink() or not shared_root.is_dir():
            checks["shared_contract_pin"] = "REFUSED"
        else:
            ok, sha = probe(["git", "-C", str(shared_root), "rev-parse", "HEAD"])
            clean, dirt = probe(["git", "-C", str(shared_root), "status", "--porcelain"])
            checks["shared_contract_pin"] = (
                "MATCHED" if ok and sha == SHARED_PIN and clean and dirt == "OBSERVED"
                else "MISMATCH"
            )

    blocked = sorted(key for key, result in checks.items()
                     if result not in {"SUPPORTED", "OBSERVED", "MATCHED"})
    # IAM and CP credentials, native images, network isolation and health are
    # NOT checked here. Another executor must prove all of them before L4 PASS.
    return {
        "schema": "baobab-dev.dev14-doctor.v1",
        "profile": profile,
        "checks": checks,
        "blocked_prerequisites": blocked,
        "result": "BLOCKED" if blocked else "LOCAL_TOOLCHAIN_OBSERVED",
        "scope": "TOOLCHAIN_DIAGNOSTIC_ONLY",
        "engine_runtime": "NOT_OBSERVED",
        "iam_cp_authority": "NOT_OBSERVED",
        "eng_onb_runtime_cases": "NOT_EXECUTED",
        "protected_acceptance": False,
        "production_authorized": False,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=sorted(REQUIREMENTS), required=True)
    parser.add_argument("--shared-root", type=Path)
    parser.add_argument("--fail-on-blocked", action="store_true")
    args = parser.parse_args(argv)
    result = inspect(args.profile, args.shared_root)
    print(json.dumps(result, sort_keys=True))
    return int(args.fail_on_blocked and result["result"] == "BLOCKED")


if __name__ == "__main__":
    raise SystemExit(main())
