#!/usr/bin/env python3
"""DEV-14 non-mutating engine toolchain diagnostic.

No image pulls, credential access, IAM/CP creation, Docker mutations or
provider certification. Report missing prerequisites; never infer readiness.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from urllib.parse import urlsplit

SHARED_PIN = "32b71f3335e566daeb58246f17fcbbf162cf7f53"
VERSION = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")
MAX_PROBE_OUTPUT = 1024 * 1024
REQUIREMENTS = {
    "pulse-intelligence": {"python": (3, 14), "docker": None, "git": None},
    "payments-sandbox": {"rustc": (1, 88), "cargo": None, "docker": None, "git": None},
}


def probe(command: list[str], *, timeout: int = 12) -> tuple[bool, str]:
    """Return complete bounded machine output; never return raw errors."""
    try:
        proc = subprocess.run(
            command, capture_output=True, text=True, errors="surrogateescape",
            timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False, "UNAVAILABLE"
    if proc.returncode or len(proc.stdout) > MAX_PROBE_OUTPUT:
        return False, "UNAVAILABLE"
    return True, proc.stdout.rstrip("\r\n")


def git_probe(root: Path, arguments: list[str], *, timeout: int = 12) -> tuple[bool, str]:
    """Run local Git observations without hooks, credentials, network or index writes."""
    env = os.environ.copy()
    # Environment-injected Git directories/config/indexes can redirect a -C
    # operation. Remove all Git overrides and install an isolated read-only set.
    for key in tuple(env):
        if key.startswith("GIT_"):
            env.pop(key, None)
    env.update({
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
    })
    command = [
        "git", "--no-optional-locks",
        "-c", "core.fsmonitor=false",
        "-c", f"core.hooksPath={os.devnull}",
        "-c", "submodule.recurse=false",
        "-C", str(root), *arguments,
    ]
    try:
        proc = subprocess.run(
            command, capture_output=True, text=True, errors="surrogateescape",
            timeout=timeout, check=False, env=env,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False, "UNAVAILABLE"
    if proc.returncode or len(proc.stdout) > MAX_PROBE_OUTPUT:
        return False, "UNAVAILABLE"
    return True, proc.stdout.rstrip("\r\n")


def meets_version(text: str, minimum: tuple[int, int]) -> bool:
    match = VERSION.search(text)
    return bool(match and tuple(map(int, match.groups()[:2])) >= minimum)


def python_line_supported(observed: str) -> bool:
    """DEV-14 qualifies Python 3.14.x, not newer unqualified major/minor lines."""
    match = VERSION.search(observed)
    return bool(match and tuple(map(int, match.groups()[:2])) == (3, 14))


def is_canonical_shared_remote(remote: str) -> bool:
    """Accept only the canonical Shared GitHub repository over HTTPS or SSH."""
    remote = remote.strip()
    if remote.startswith("git@github.com:"):
        path = remote.removeprefix("git@github.com:")
    else:
        try:
            parsed = urlsplit(remote)
            if parsed.scheme not in {"https", "ssh"} or parsed.hostname != "github.com":
                return False
            if parsed.query or parsed.fragment or parsed.password is not None:
                return False
            if parsed.scheme == "https":
                if parsed.username is not None or parsed.port not in (None, 443):
                    return False
            elif parsed.username != "git" or parsed.port not in (None, 22):
                return False
            path = parsed.path.lstrip("/")
        except ValueError:
            return False
    return path.removesuffix(".git") == "baobab-platform/shared"


def inspect_shared_checkout(shared_root: Path, *, expected_pin: str | None = None) -> str:
    """Require the actual clean Shared root, canonical origin and exact commit."""
    if shared_root.is_symlink() or not shared_root.is_dir():
        return "REFUSED"
    try:
        root = shared_root.resolve(strict=True)
    except OSError:
        return "REFUSED"

    top_ok, top_level = git_probe(root, ["rev-parse", "--show-toplevel"])
    if not top_ok or Path(top_level).resolve() != root:
        return "NOT_REPOSITORY_ROOT"

    # Read the literal local origin value. This does not apply URL rewrites or
    # invoke credential helpers, unlike operations that contact a remote.
    remote_ok, remote = git_probe(root, ["config", "--local", "--get", "remote.origin.url"])
    if not remote_ok or not is_canonical_shared_remote(remote):
        return "UNTRUSTED_REMOTE"

    pin_ok, sha = git_probe(root, ["rev-parse", "HEAD"])
    pin = expected_pin or SHARED_PIN
    if not pin_ok or sha != pin:
        return "MISMATCH"

    # Sparse checkouts and index flags can conceal modified tracked files from
    # status. Refuse them rather than treating an incomplete view as clean.
    sparse_ok, sparse = git_probe(root, [
        "config", "--local", "--bool", "--get-regexp", r"^core\.sparse(Checkout|Index)$"
    ])
    if sparse_ok and any(line.rsplit(" ", 1)[-1].lower() == "true"
                         for line in sparse.splitlines()):
        return "INCOMPLETE_INDEX"
    flags_ok, flags = git_probe(root, ["ls-files", "-v", "-z"])
    if not flags_ok:
        return "INCOMPLETE_INDEX"
    for entry in flags.split("\0"):
        if not entry:
            continue
        tag = entry[0]
        if tag == "S" or tag.islower():
            return "INCOMPLETE_INDEX"

    clean, status = git_probe(root, [
        "status", "--porcelain=v1", "--untracked-files=all",
        "--ignore-submodules=none",
    ])
    if not clean or status:
        return "DIRTY_WORKTREE"
    return "MATCHED"


def inspect(profile: str, shared_root: Path | None = None) -> dict:
    if profile not in REQUIREMENTS:
        raise ValueError("UNKNOWN_DEV14_PROFILE")
    checks = {}
    for tool, minimum in REQUIREMENTS[profile].items():
        executable = sys.executable if tool == "python" else shutil.which(tool)
        if executable is None:
            checks[tool] = "MISSING"
            continue
        ok, observed = probe([executable, "--version"])
        version_supported = (
            python_line_supported(observed) if tool == "python"
            else minimum is None or meets_version(observed, minimum)
        )
        checks[tool] = ("SUPPORTED" if ok and version_supported
                        else "VERSION_UNSUPPORTED" if ok else "UNAVAILABLE")

    docker_ok, _ = probe(
        ["docker", "info", "--format", "{{.ServerVersion}}"]
    ) if checks["docker"] == "SUPPORTED" else (False, "")
    compose_ok, _ = probe(
        ["docker", "compose", "version", "--short"]
    ) if checks["docker"] == "SUPPORTED" else (False, "")
    checks["docker_daemon"] = "OBSERVED" if docker_ok else "UNAVAILABLE"
    checks["docker_compose"] = "OBSERVED" if compose_ok else "UNAVAILABLE"

    checks["shared_contract_pin"] = (
        inspect_shared_checkout(shared_root)
        if shared_root is not None else "NOT_INSPECTED"
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
