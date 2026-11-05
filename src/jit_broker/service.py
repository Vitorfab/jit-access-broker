"""Use cases of the broker. No printing here: it returns data or raises BrokerError."""

import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from jit_broker.domain import DecisionKind, RequestRecord, RequestStatus
from jit_broker.policy import MIN_DURATION_MINUTES, Capability, Policy
from jit_broker.store import Store

MAX_PENDING_PER_USER = 5
_TICKET_PATTERN = re.compile(r"[A-Za-z0-9._-]{1,40}")

Clock = Callable[[], datetime]


class BrokerError(Exception):
    """A request or decision was refused. The message is safe to show to the user."""


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _clean_text(value: str, name: str, min_len: int, max_len: int) -> str:
    text = value.strip()
    if not min_len <= len(text) <= max_len:
        raise BrokerError(f"{name} must be {min_len}-{max_len} characters")
    if not text.isprintable():
        raise BrokerError(f"{name} contains control characters")
    return text


class Broker:
    def __init__(self, policy: Policy, store: Store, clock: Clock = _utc_now) -> None:
        self._policy = policy
        self._store = store
        self._clock = clock

    def request_access(
        self,
        user: str,
        role: str,
        duration_minutes: int,
        justification: str,
        ticket: str | None = None,
    ) -> RequestRecord:
        if user not in self._policy.users:
            raise BrokerError("unknown user")
        role_def = self._policy.roles.get(role)
        # Same message for "no such role" and "not allowed": do not reveal role names.
        if role_def is None or user not in role_def.requesters:
            raise BrokerError("you cannot request this role")
        if not MIN_DURATION_MINUTES <= duration_minutes <= role_def.max_duration_minutes:
            raise BrokerError(
                f"duration must be between {MIN_DURATION_MINUTES} and "
                f"{role_def.max_duration_minutes} minutes for this role"
            )
        text = _clean_text(justification, "justification", 10, 500)
        if ticket is not None and not _TICKET_PATTERN.fullmatch(ticket):
            raise BrokerError("ticket must be 1-40 characters: letters, digits, '.', '_' or '-'")

        now = self._clock()
        expires_at = now + timedelta(minutes=self._policy.pending_request_ttl_minutes)
        with self._store.transaction():
            if self._store.count_pending(user, now) >= MAX_PENDING_PER_USER:
                raise BrokerError("too many pending requests")
            new_id = self._store.insert_request(
                requester=user,
                role=role,
                duration_minutes=duration_minutes,
                justification=text,
                ticket=ticket,
                created_at=now,
                expires_at=expires_at,
            )
        return self._reload(new_id)

    def approve(self, request_id: int, approver: str, reason: str) -> RequestRecord:
        return self._decide(request_id, approver, DecisionKind.APPROVE, reason)

    def deny(self, request_id: int, approver: str, reason: str) -> RequestRecord:
        return self._decide(request_id, approver, DecisionKind.DENY, reason)

    def list_requests(self, status: RequestStatus | None = None) -> list[RequestRecord]:
        return self._store.list_requests(status)

    def _reload(self, request_id: int) -> RequestRecord:
        record = self._store.get_request(request_id)
        if record is None:
            raise BrokerError("request not found")
        return record

    def _decide(
        self, request_id: int, approver: str, kind: DecisionKind, reason: str
    ) -> RequestRecord:
        text = _clean_text(reason, "reason", 3, 200)
        user = self._policy.users.get(approver)
        if user is None or Capability.APPROVE not in user.capabilities:
            raise BrokerError("this user cannot approve or deny requests")

        expired = False
        with self._store.transaction():
            request = self._store.get_request(request_id)
            if request is None:
                raise BrokerError("request not found")
            if request.status is not RequestStatus.PENDING:
                raise BrokerError(f"request is already {request.status.value}")
            now = self._clock()
            if now >= request.expires_at:
                # Persist the expiry now; raise only after the transaction commits.
                self._store.set_status(request_id, RequestStatus.EXPIRED, now)
                expired = True
            else:
                if approver == request.requester:
                    raise BrokerError("self-approval is not allowed")
                role = self._policy.roles.get(request.role)
                if role is None or approver not in role.approvers:
                    raise BrokerError("you are not an approver for this role")
                if self._store.has_decision(request_id, approver):
                    raise BrokerError("you already decided on this request")
                self._store.add_decision(request_id, approver, kind, text, now)
                if kind is DecisionKind.DENY:
                    self._store.set_status(request_id, RequestStatus.DENIED, now)
                elif self._store.count_approvals(request_id) >= role.approvals_required:
                    self._store.set_status(request_id, RequestStatus.APPROVED, now)
        if expired:
            raise BrokerError("request expired before it was decided")
        return self._reload(request_id)
