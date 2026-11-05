"""Policy models and loader.

The policy is deny-by-default: a role that is not listed, or a user that is not
listed as requester/approver for it, gets nothing. Loading is strict: unknown
fields, wrong types and broken references are rejected.
"""

from datetime import timedelta
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal, Self

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    model_validator,
)

MIN_DURATION_MINUTES = 15
MAX_DURATION_MINUTES = 1440
MAX_POLICY_FILE_BYTES = 1_000_000

Identifier = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9-]{1,31}$")]


class PolicyError(Exception):
    """Raised when the policy file cannot be loaded or is invalid."""


class Risk(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Capability(StrEnum):
    REQUEST = "request"
    APPROVE = "approve"
    ADMIN = "admin"


class _Strict(BaseModel):
    """Base model: reject unknown fields and make instances immutable."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class User(_Strict):
    display_name: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    capabilities: list[Capability] = Field(min_length=1)


class Role(_Strict):
    description: Annotated[str, StringConstraints(min_length=1, max_length=200)]
    risk: Risk
    max_duration_minutes: int = Field(ge=MIN_DURATION_MINUTES, le=MAX_DURATION_MINUTES)
    approvals_required: int = Field(ge=1, le=5)
    requesters: list[Identifier] = Field(min_length=1)
    approvers: list[Identifier] = Field(min_length=1)

    @property
    def max_duration(self) -> timedelta:
        return timedelta(minutes=self.max_duration_minutes)

    @model_validator(mode="after")
    def _check_lists(self) -> Self:
        if len(set(self.requesters)) != len(self.requesters):
            raise ValueError("duplicate requesters")
        if len(set(self.approvers)) != len(self.approvers):
            raise ValueError("duplicate approvers")
        if self.approvals_required > len(self.approvers):
            raise ValueError(
                f"approvals_required ({self.approvals_required}) exceeds "
                f"the number of approvers ({len(self.approvers)})"
            )
        return self


class Policy(_Strict):
    schema_version: Literal[1]
    pending_request_ttl_minutes: int = Field(default=1440, ge=15, le=10080)
    users: dict[Identifier, User] = Field(min_length=1)
    roles: dict[Identifier, Role] = Field(min_length=1)

    @model_validator(mode="after")
    def _check_references(self) -> Self:
        for role_name, role in self.roles.items():
            self._check_people(role_name, "requester", role.requesters, Capability.REQUEST)
            self._check_people(role_name, "approver", role.approvers, Capability.APPROVE)
        return self

    def _check_people(
        self, role_name: str, label: str, user_ids: list[str], needed: Capability
    ) -> None:
        for user_id in user_ids:
            user = self.users.get(user_id)
            if user is None:
                raise ValueError(f"role '{role_name}': unknown {label} '{user_id}'")
            if needed not in user.capabilities:
                raise ValueError(
                    f"role '{role_name}': {label} '{user_id}' lacks the '{needed}' capability"
                )


def _format_errors(exc: ValidationError) -> str:
    # Only locations and messages: never echo input values (they could be secrets).
    lines = [
        f"{'.'.join(str(part) for part in err['loc']) or '<root>'}: {err['msg']}"
        for err in exc.errors()
    ]
    return "invalid policy:\n" + "\n".join(lines)


def load_policy(path: Path) -> Policy:
    """Load and strictly validate a policy file. Raises PolicyError on any problem."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise PolicyError(f"cannot read policy file: {exc.strerror}") from exc
    if size > MAX_POLICY_FILE_BYTES:
        raise PolicyError("policy file is too large")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise PolicyError("policy file is not valid YAML") from exc
    if not isinstance(raw, dict):
        raise PolicyError("invalid policy: the root must be a mapping")
    try:
        return Policy.model_validate(raw)
    except ValidationError as exc:
        raise PolicyError(_format_errors(exc)) from exc
