#!/usr/bin/env python3
"""DEV-10 pre-tag release matrix: read-only RC/GA identity, job graph, artifact and tooling checks."""
import argparse
import re
from pathlib import Path
from release_tag_policy import classify

TARGETS = ("final", "frontend", "frontend-e2e", "infra")
JOBS = {
    "sanity-check": (),
    "ga-reuse": ("sanity-check",),
    "build": ("sanity-check",),
    "release-digests": ("sanity-check", "build"),
    "publish": ("release-digests", "sanity-check"),
    "promote": ("publish", "ga-reuse", "sanity-check"),
    "release": ("promote", "sanity-check", "ga-reuse"),
}
REQUIRED_FILES = (
    "scripts/verify-image.sh",
    "scripts/test-verify-image-release-identity.sh",
    "scripts/verify_release_artifact_contract.py",
    "scripts/verify_rc_ga_workflow.py",
    "scripts/prepare_ga_reuse.py",
    "scripts/select_qualified_rc_run.py",
    "scripts/release_tag_policy.py",
    "scripts/plan_rc_recovery.py",
    "config/resolve.sh",
    "config/versions.yaml",
    "config/versions.lock",
)
REQUIRED_TOOLS = {
    "yq": "Install yq dependency",
    "crane": "Install crane CLI tool",
    "cosign": "cosign-installer@",
    "trivy": "Install Trivy",
    "gh": "gh api",
    "python3": "python3 -m unittest",
    "docker": "docker/",
}

def job_blocks(workflow):
    matches = list(re.finditer(r"^  ([a-z][a-z0-9-]*):\s*$", workflow, re.M))
    return {m.group(1): workflow[m.end():matches[i + 1].start() if i + 1 < len(matches) else len(workflow)]
            for i, m in enumerate(matches)}

def check(root: Path, workflow: str):
    errors = []
    blocks = job_blocks(workflow)
    for name, dependencies in JOBS.items():
        block = blocks.get(name)
        if block is None:
            errors.append("missing job " + name)
            continue
        match = re.search(r"^    needs:\s*(\[[^\n]+\]|[a-z][a-z0-9-]*)", block, re.M)
        actual = set()
        if match:
            actual = {x.strip() for x in match.group(1).strip("[]").split(",")}
        if actual != set(dependencies):
            errors.append("job dependency mismatch " + name)
    for name in REQUIRED_FILES:
        if not (root / name).is_file():
            errors.append("missing required source " + name)
    for tool, evidence in REQUIRED_TOOLS.items():
        if evidence not in workflow:
            errors.append("missing executable provisioning/use " + tool)
    for fragment in (
        "name: resolved-lockfile",
        "name: ga-reused-candidates",
        "name: published-info-${{ matrix.target }}",
        "pattern: ${{ needs.sanity-check.outputs.is_stable_release == 'true' && 'ga-reused-candidates' || 'published-info-*' }}",
        "scripts/verify_release_artifact_contract.py",
        "scripts/test-verify-image-release-identity.sh",
        "tests/test_release_artifact_contract.py",
        "tests/test_immutable_rc_recovery.py",
        "if-no-files-found: error",
        'gh api --paginate --slurp "repos/${GITHUB_REPOSITORY}/actions/workflows/publish.yml/runs?head_sha=${GITHUB_SHA}&event=push&status=completed&per_page=100"',
        "scripts/select_qualified_rc_run.py",
        "verify_rc_ga_workflow.py",
    ):
        if fragment not in workflow:
            errors.append("missing release artifact or qualification contract: " + fragment)
    for target in TARGETS:
        if target not in workflow:
            errors.append("missing release target " + target)
    # Both channels must have independent publication paths.
    if "is_stable_release == 'true'" not in workflow or "is_stable_release != 'true'" not in workflow:
        errors.append("missing RC/GA workflow branch")
    for tag, expected in (
        ("v1.5.0-rc.1", "rc"), ("v1.5.1-rc.2", "rc"),
        ("v1.5.2-rc.1", "rc"), ("v1.5.2", "ga"), ("v2.0.0", "ga"),
        ("v1.5.2-rc.0", None), ("v1.5.2-rc.01", None),
        ("v1.5.2-beta.1", None), ("v01.5.2", None),
    ):
        if classify(tag) != expected:
            errors.append("release tag matrix mismatch " + tag)
    return errors

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = p.parse_args()
    workflow = (args.root / ".github/workflows/publish.yml").read_text()
    errors = check(args.root, workflow)
    if errors:
        for error in errors:
            print("PREFLIGHT FAILED: " + error)
        return 1
    print("DEV-10 pre-tag RC/GA matrix passed: identity, four targets, artifact names, source tools and job graph")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
