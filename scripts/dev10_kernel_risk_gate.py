"""Retired legacy DEV-10 risk gate; retained only for historical release-note disclosure.

The historical 295-CVE inventory and its old development-only decision remain
available as audit evidence. They are not an active authorization mechanism.
Current development scans use the authenticated protected-policy evaluator;
release publication and promotion use separate exact-digest release gates.
"""
from __future__ import annotations

import re


HISTORICAL_DISCLOSURE_IMAGE_REFS = frozenset({"refs/tags/v1.5.0", "refs/tags/v1.5.1"})
HISTORICAL_DISCLOSURE_RC_REF = re.compile(
    r"^refs/tags/v1[.]5[.](?:0|1)-rc[.][1-9][0-9]*$"
)


class RiskGateError(ValueError):
    """Raised whenever a caller attempts to use the retired legacy gate."""


def is_historical_development_risk_disclosure_ref(tag: str) -> bool:
    """Return whether a release note should disclose a historical decision.

    This helper is informational only. It must never be used to authorize
    publication, tag movement, alias promotion, staging, or production use.
    """
    if not isinstance(tag, str) or not re.fullmatch(r"v[0-9]+[.][0-9]+[.][0-9]+(?:-rc[.][1-9][0-9]*)?", tag):
        return False
    ref = f"refs/tags/{tag}"
    return (
        ref in HISTORICAL_DISCLOSURE_IMAGE_REFS
        or HISTORICAL_DISCLOSURE_RC_REF.fullmatch(ref) is not None
    )


def validate(*_args, **_kwargs):
    """Fail closed: the historical 295-CVE gate is no longer an authority."""
    raise RiskGateError(
        "legacy DEV-10 risk gate is retired; it cannot authorize release publication or promotion"
    )


def main() -> int:
    validate()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
