"""Fail-closed role and actor typing for read-only DEV-10 evidence.

This module does not authorize reviews or modify provisioning policy.
"""
from dataclasses import dataclass
from enum import Enum


class IdentityError(ValueError):
    pass


class Role(str, Enum):
    PR_AUTHOR = "pr_author"
    COMMIT_AUTHOR = "commit_author"
    CO_AUTHOR = "co_author"
    COMMITTER = "committer"
    REVIEWER = "reviewer"
    OWNER = "owner"
    WORKFLOW_INITIATOR = "workflow_initiator"
    MERGER = "merger"


class Classification(str, Enum):
    USER = "user_unverified_human"
    SERVICE = "service"
    BOT = "bot"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ActorEvidence:
    user_id: int
    role: Role
    classification: Classification
    source: str
    exact_sha: str | None = None


def resolve_actor(actor, *, role: Role, source: str, exact_sha=None):
    if not isinstance(role, Role) or not isinstance(source, str) or not source:
        raise IdentityError("role and provenance are required")
    if not isinstance(actor, dict):
        raise IdentityError("actor evidence is absent")
    actor_type = actor.get("type", actor.get("__typename"))
    if actor_type not in ("User", "Bot"):
        raise IdentityError("unknown or non-user actor classification")
    user_id = actor.get("id", actor.get("databaseId"))
    if type(user_id) is not int or user_id <= 0:
        raise IdentityError("immutable numeric GitHub user ID required")
    if role is Role.COMMITTER and source == "rest_exact_sha":
        if not isinstance(exact_sha, str) or len(exact_sha) != 40 or any(
            c not in "0123456789abcdef" for c in exact_sha
        ):
            raise IdentityError("REST committer fallback requires exact SHA")
        if actor_type != "User":
            raise IdentityError("REST committer fallback requires linked User")
    elif source == "rest_exact_sha":
        raise IdentityError("REST exact-SHA fallback is committer-only")
    classification = Classification.BOT if actor_type == "Bot" else Classification.USER
    # The GitHub API User type is NOT human attestation.
    return ActorEvidence(user_id, role, classification, source, exact_sha)


def require_human_eligibility(evidence, *, trusted_ids):
    """Conservative policy: explicit trusted numeric ID AND separate human attestation.

    Do not infer human status from GitHub User type or a commit signature.
    """
    if not isinstance(evidence, ActorEvidence) or evidence.role not in (
        Role.REVIEWER, Role.OWNER
    ):
        raise IdentityError("role is ineligible for independent human authorization")
    if evidence.classification is not Classification.USER:
        raise IdentityError("non-user actor is ineligible")
    if evidence.user_id not in trusted_ids:
        raise IdentityError("numeric actor is not trusted")
    raise IdentityError("separate authenticated human eligibility evidence required")
