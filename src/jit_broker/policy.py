"""Policy models and loader.

The policy is deny-by-default: a role that is not listed, or a user that is not
listed as requester/approver for it, gets nothing. Loading is strict: unknown
fields, wrong types and broken references are rejected.
"""

import hashlib
import json
from collections.abc import Hashable
from datetime import timedelta
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Literal, Self

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
        text = path.read_text(encoding="utf-8")
        raw = yaml.load(text, Loader=_UniqueKeyLoader)  # noqa: S506  # nosec B506
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise PolicyError("policy file is not valid YAML") from exc
    if not isinstance(raw, dict):
        raise PolicyError("invalid policy: the root must be a mapping")
    try:
        return Policy.model_validate(raw)
    except ValidationError as exc:
        raise PolicyError(_format_errors(exc)) from exc


class _UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys instead of keeping the last one."""

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Hashable, Any]:
        seen: set[Hashable] = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, Hashable):
                continue
            if key in seen:
                raise yaml.YAMLError("duplicate key")
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


def policy_from_mapping(raw: object) -> Policy:
    """Validate an in-memory mapping (for example from the editor) with the same strict rules."""
    if not isinstance(raw, dict):
        raise PolicyError("invalid policy: the root must be a mapping")
    try:
        return Policy.model_validate(raw)
    except ValidationError as exc:
        raise PolicyError(_format_errors(exc)) from exc


def policy_to_data(policy: Policy) -> dict[str, Any]:
    """Plain JSON-compatible data for a policy."""
    return policy.model_dump(mode="json")


def policy_digest(policy: Policy) -> str:
    """SHA-256 of the canonical JSON of the policy (independent of file formatting)."""
    canonical = json.dumps(
        policy_to_data(policy), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def policy_to_yaml(policy: Policy) -> str:
    return yaml.safe_dump(policy_to_data(policy), sort_keys=False, allow_unicode=False)
