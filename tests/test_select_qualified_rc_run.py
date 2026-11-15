"""Selection of the successful same-source RC workflow for GA continuity."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from select_qualified_rc_run import QualifiedRunSelectionError, select_qualified_rc_run  # noqa: E402

SHA = "a" * 40
OTHER = "b" * 40


def run(run_id, run_number, tag="v1.5.2-rc.1", sha=SHA, **overrides):
    value = {
        "id": run_id, "run_number": run_number,
        "path": ".github/workflows/publish.yml@refs/tags/" + tag,
        "event": "push", "status": "completed", "conclusion": "success",
        "head_branch": tag, "head_sha": sha,
    }
    value.update(overrides)
    return value


class QualifiedRcRunSelectionTests(unittest.TestCase):
    def test_selects_latest_successful_exact_family_run(self):
        data = {"workflow_runs": [
            run(10, 10),
            run(11, 11, tag="v1.5.1-rc.9"),
            run(12, 12, sha=OTHER),
            run(13, 13, tag="v1.5.2-rc.2"),
            # The live GitHub API returns the workflow path without an @ref suffix.
            run(14, 14, tag="v1.5.2-rc.3", path=".github/workflows/publish.yml"),
        ]}
        self.assertEqual(select_qualified_rc_run(data, "v1.5.2", SHA)["id"], 14)

    def test_rejects_other_workflow_event_status_or_conclusion(self):
        candidates = [
            run(1, 1, path=".github/workflows/other.yml@refs/tags/v1.5.2-rc.1"),
            run(2, 2, event="workflow_dispatch"),
            run(3, 3, status="in_progress"),
            run(4, 4, conclusion="failure"),
            run(5, 5, sha=OTHER),
        ]
        with self.assertRaises(QualifiedRunSelectionError):
            select_qualified_rc_run({"workflow_runs": candidates}, "v1.5.2", SHA)

    def test_rejects_wrong_family_and_malformed_rc_tags(self):
        for tag in ("v1.5.1-rc.1", "v1.5.2-rc.0", "v1.5.2-rc.01",
                    "v1.5.2-beta.1", "v1.5.2-rc.1-extra"):
            with self.subTest(tag=tag), self.assertRaises(QualifiedRunSelectionError):
                select_qualified_rc_run({"workflow_runs": [run(1, 1, tag=tag)]},
                                        "v1.5.2", SHA)

    def test_rejects_invalid_ga_tag_or_sha(self):
        for tag, sha in (("v1.5.2-rc.1", SHA), ("v01.5.2", SHA),
                         ("v1.5.2", "a" * 39), ("v1.5.2", "A" * 40)):
            with self.subTest(tag=tag, sha=sha), self.assertRaises(QualifiedRunSelectionError):
                select_qualified_rc_run({"workflow_runs": [run(1, 1)]}, tag, sha)

    def test_rejects_invalid_response_and_run_ids(self):
        for data in ({}, {"workflow_runs": [run(0, 1)]},
                     {"workflow_runs": [run(1, 0)]},
                     {"workflow_runs": [run(True, 1)]}):
            with self.subTest(data=data), self.assertRaises(QualifiedRunSelectionError):
                select_qualified_rc_run(data, "v1.5.2", SHA)


if __name__ == "__main__":
    unittest.main()
