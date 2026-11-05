"""Domain models: access requests and their lifecycle states."""

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
