"""Domain models: access requests, grants and their lifecycle states."""

from enum import StrEnum

from pydantic import AwareDatetime, BaseModel, ConfigDict


class RequestStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


class DecisionKind(StrEnum):
    APPROVE = "approve"
    DENY = "deny"


class RequestRecord(BaseModel):
    """One access request, as stored. Immutable: changes create a new instance."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: int
    requester: str
    role: str
    duration_minutes: int
    justification: str
    ticket: str | None
    status: RequestStatus
    created_at: AwareDatetime
    expires_at: AwareDatetime
    decided_at: AwareDatetime | None
    approvals: int = 0


class Grant(BaseModel):
    """Time-bound access created by a fully approved request."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: int
    request_id: int
    grantee: str
    role: str
    starts_at: AwareDatetime
    ends_at: AwareDatetime
    revoked_at: AwareDatetime | None


class AccessResult(BaseModel):
    """Answer of an access check."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    user: str
    role: str
    allowed: bool
    ends_at: AwareDatetime | None


class Account(BaseModel):
    """A local login account. The password is stored only as an Argon2id hash."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    username: str
    password_hash: str
    failed_count: int
    locked_until: AwareDatetime | None
    created_at: AwareDatetime


class Session(BaseModel):
    """A login session (the browser holds a random token; only its hash is stored)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    username: str
    csrf: str
    created_at: AwareDatetime
    last_seen: AwareDatetime
    expires_at: AwareDatetime
