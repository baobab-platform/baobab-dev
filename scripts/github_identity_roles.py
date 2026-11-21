"""Type the provenance of GitHub actors for read-only audit receipts."""
from dataclasses import dataclass
from enum import Enum
import re

from custody_independence import GITHUB_WEB_FLOW_ID, is_positive_id


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


class Source(str, Enum):
    GRAPHQL = "graphql"
    REST_PR = "rest_pr"
    REST_REVIEWS = "rest_reviews"
    REST_COMMENTS = "rest_issue_comments"
    REST_RUN = "rest_workflow_run"
    REST_EXACT_SHA = "rest_exact_sha"


class Classification(str, Enum):
    USER = "user_unverified_human"
    SERVICE = "service"
    BOT = "bot"
    APP = "app"


ROLE_SOURCES = {
    Role.PR_AUTHOR: (Source.GRAPHQL, Source.REST_PR),
    Role.COMMIT_AUTHOR: (Source.GRAPHQL,),
    Role.CO_AUTHOR: (Source.GRAPHQL,),
    Role.COMMITTER: (Source.GRAPHQL, Source.REST_EXACT_SHA),
    Role.REVIEWER: (Source.REST_REVIEWS,),
    Role.OWNER: (Source.REST_COMMENTS,),
    Role.WORKFLOW_INITIATOR: (Source.REST_RUN,),
    Role.MERGER: (Source.REST_PR,),
}
COMMIT_ROLES = {Role.COMMIT_AUTHOR, Role.CO_AUTHOR, Role.COMMITTER}
ACCOUNT_TYPES = {"User": Classification.USER, "Bot": Classification.BOT, "App": Classification.APP}


@dataclass(frozen=True)
class ActorEvidence:
    user_id: int
    role: Role
    classification: Classification
    source: Source
    exact_sha: str | None


def resolve_actor(actor, *, role: Role, source: Source, exact_sha=None) -> ActorEvidence:
    """Record role and provenance after the caller has read the exact API object."""
    if not isinstance(role, Role) or not isinstance(source, Source) or source not in ROLE_SOURCES[role]:
        raise IdentityError("identity evidence source is invalid for this role")
    if not isinstance(actor, dict):
        raise IdentityError("actor evidence is absent")
    if role in COMMIT_ROLES or exact_sha is not None:
        if not isinstance(exact_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", exact_sha):
            raise IdentityError("commit evidence requires an exact SHA")
    type_key, id_key = ("__typename", "databaseId") if source is Source.GRAPHQL else ("type", "id")
    actor_type = actor.get(type_key)
    user_id = actor.get(id_key)
    if not isinstance(actor_type, str) or actor_type not in ACCOUNT_TYPES:
        raise IdentityError("unknown GitHub actor type")
    if not is_positive_id(user_id):
        raise IdentityError("actor has no positive immutable numeric GitHub ID")
    if any(key in actor and actor[key] != actor_type for key in ("type", "__typename")):
        raise IdentityError("conflicting GitHub actor types")
    if any(key in actor and (not is_positive_id(actor[key]) or actor[key] != user_id)
           for key in ("id", "databaseId")):
        raise IdentityError("conflicting numeric GitHub actor IDs")
    if (source is Source.REST_EXACT_SHA or user_id == GITHUB_WEB_FLOW_ID) and actor_type != "User":
        raise IdentityError("service identity and REST committer evidence require a typed GitHub User")
    classification = Classification.SERVICE if user_id == GITHUB_WEB_FLOW_ID else ACCOUNT_TYPES[actor_type]
    return ActorEvidence(user_id, role, classification, source, exact_sha)
