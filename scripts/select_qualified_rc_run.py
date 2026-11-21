#!/usr/bin/env python3
"""Select a successful same-source RC Publish run for GA digest continuity."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

from release_tag_policy import classify


class QualifiedRunSelectionError(ValueError):
    pass


def select_qualified_rc_run(data: dict, ga_tag: str, source_sha: str) -> dict:
    if classify(ga_tag) != "ga":
        raise QualifiedRunSelectionError("GA selection requires a canonical stable release tag")
    if not re.fullmatch(r"[a-f0-9]{40}", source_sha):
        raise QualifiedRunSelectionError("GA source SHA must be a full lowercase commit SHA")
    # The workflow API is fetched with gh api --paginate --slurp.  Its
    # JSON shape is an array of response pages; validate the shared total_count
    # and require every reported run to be present before selecting anything.
    if isinstance(data, list):
        pages = data
        if not pages:
            raise QualifiedRunSelectionError("workflow-runs pagination returned no pages")
        totals = []
        for page in pages:
            if not isinstance(page, dict) or not isinstance(page.get("workflow_runs"), list):
                raise QualifiedRunSelectionError("invalid workflow-runs page")
            total = page.get("total_count")
            if isinstance(total, bool) or not isinstance(total, int) or total < 0:
                raise QualifiedRunSelectionError("workflow-runs page has no valid total_count")
            totals.append(total)
        if len(set(totals)) != 1:
            raise QualifiedRunSelectionError("workflow-runs pagination totals disagree")
        runs = [run for page in pages for run in page["workflow_runs"]]
        if len(runs) != totals[0]:
            raise QualifiedRunSelectionError(
                f"incomplete workflow-runs pagination: observed {len(runs)}, expected {totals[0]}")
    elif isinstance(data, dict) and isinstance(data.get("workflow_runs"), list):
        # Retain the pure selector's single-page input for focused unit tests
        # and callers that already supply a complete response.
        runs = data["workflow_runs"]
        total = data.get("total_count")
        if total is not None and (isinstance(total, bool) or not isinstance(total, int)
                                  or total != len(runs)):
            raise QualifiedRunSelectionError("single-page workflow-runs response is incomplete")
    else:
        raise QualifiedRunSelectionError("workflow-runs response is missing workflow_runs")
    rc_pattern = re.compile(re.escape(ga_tag) + r"-rc\.[1-9][0-9]*")
    candidates = []
    for run in runs:
        if not isinstance(run, dict):
            continue
        workflow_path = run.get("path")
        if not isinstance(workflow_path, str) or workflow_path.split("@", 1)[0] != ".github/workflows/publish.yml":
            continue
        if (run.get("event") != "push" or run.get("status") != "completed"
                or run.get("conclusion") != "success" or run.get("head_sha") != source_sha):
            continue
        if not isinstance(run.get("head_branch"), str) or not rc_pattern.fullmatch(run["head_branch"]):
            continue
        run_id, run_number = run.get("id"), run.get("run_number")
        if (isinstance(run_id, bool) or not isinstance(run_id, int) or run_id <= 0
                or isinstance(run_number, bool) or not isinstance(run_number, int) or run_number <= 0):
            continue
        candidates.append(run)
    if not candidates:
        raise QualifiedRunSelectionError(
            "no successful same-commit, same-version-family RC Publish run found")
    return max(candidates, key=lambda run: (run["run_number"], run["id"]))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--sha", required=True)
    args = parser.parse_args()
    try:
        run = select_qualified_rc_run(json.loads(args.input.read_text()), args.tag, args.sha)
    except (OSError, json.JSONDecodeError, QualifiedRunSelectionError) as exc:
        parser.error(str(exc))
    print(run["id"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
