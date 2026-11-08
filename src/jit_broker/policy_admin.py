"""Two-person policy changes (lab).

An admin proposes a complete new policy; a different admin approves it. The proposal is validated
with the same strict model as the policy file, must keep at least two admins, and may not give the
person acting any new privilege. Applying writes a numbered backup, then replaces the policy file
atomically. The audit log records hashes only, never the policy content.
"""

import json
import os
import re
import shutil
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypeVar

from jit_broker.audit import AuditError, AuditLog, Detail
from jit_broker.domain import PolicyChange
from jit_broker.policy import (
    Capability,
    Policy,
    PolicyError,
    load_policy,
    policy_digest,
    policy_from_mapping,
    policy_to_data,
    policy_to_yaml,
)
from jit_broker.service import BrokerError
from jit_broker.store import Store

MIN_ADMINS = 2
MAX_PENDING_CHANGES = 5
MAX_PROPOSAL_CHARS = 200_000
_IDENT = re.compile(r"[a-z][a-z0-9-]{1,31}")

T = TypeVar("T")
Clock = Callable[[], datetime]


class InvalidProposalError(BrokerError):
    """The proposed policy failed validation (the message lists locations, not values)."""


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _diff(label: str, old: Mapping[str, object], new: Mapping[str, object]) -> list[str]:
    added = sorted(set(new) - set(old))
    removed = sorted(set(old) - set(new))
    changed = sorted(key for key in set(old) & set(new) if old[key] != new[key])
    parts: list[str] = []
    for word, items in (("added", added), ("removed", removed), ("changed", changed)):
        if items:
            parts.append(f"{label} {word}: {', '.join(items)}")
    return parts


def summarize(old: Policy, new: Policy) -> str:
    """Short description of a change. Identifiers only (they are validated by the policy model)."""
    parts = _diff("users", old.users, new.users) + _diff("roles", old.roles, new.roles)
    if old.pending_request_ttl_minutes != new.pending_request_ttl_minutes:
        parts.append("pending request ttl changed")
    return ("; ".join(parts) or "no visible change")[:500]


class PolicyAdmin:
    def __init__(self, path: Path, store: Store, audit: AuditLog, clock: Clock = _utc_now) -> None:
        self._path = path
        self._store = store
        self._audit = audit
        self._clock = clock

    # ---- public use cases ----

    def view_policy(self, admin: str) -> tuple[dict[str, Any], str]:
        policy = self._current()
        self._require_admin(policy, admin)
        return policy_to_data(policy), policy_digest(policy)

    def list_changes(self, admin: str) -> list[PolicyChange]:
        self._require_admin(self._current(), admin)
        return self._store.list_policy_changes()

    def propose(self, admin: str, proposal: object) -> PolicyChange:
        return self._guarded("policy_propose", admin, None, lambda: self._propose(admin, proposal))

    def approve(self, change_id: int, admin: str) -> PolicyChange:
        return self._guarded(
            "policy_approve", admin, change_id, lambda: self._approve(change_id, admin)
        )

    def reject(self, change_id: int, admin: str) -> PolicyChange:
        return self._guarded(
            "policy_reject", admin, change_id, lambda: self._reject(change_id, admin)
        )

    # ---- rules ----

    def _current(self) -> Policy:
        try:
            return load_policy(self._path)
        except PolicyError as exc:
            raise BrokerError("the policy file cannot be loaded") from exc

    @staticmethod
    def _require_admin(policy: Policy, user: str) -> None:
        person = policy.users.get(user)
        if person is None or Capability.ADMIN not in person.capabilities:
            raise BrokerError("this action requires an admin")

    @staticmethod
    def _check_rules(new: Policy) -> None:
        admins = [n for n, p in new.users.items() if Capability.ADMIN in p.capabilities]
        if len(admins) < MIN_ADMINS:
            raise BrokerError(
                f"the policy must keep at least {MIN_ADMINS} admins, "
                "so changes can always be approved"
            )

    @staticmethod
    def _check_self_grants(old: Policy, new: Policy, user: str) -> None:
        """Nobody may use a policy change to give themselves a new privilege."""
        old_person = old.users.get(user)
        old_caps = set(old_person.capabilities) if old_person is not None else set()
        new_person = new.users.get(user)
        if new_person is not None and not set(new_person.capabilities) <= old_caps:
            raise BrokerError("you cannot grant yourself new capabilities")
        for name, role in new.roles.items():
            before = old.roles.get(name)
            old_requesters = before.requesters if before is not None else []
            old_approvers = before.approvers if before is not None else []
            if user in role.requesters and user not in old_requesters:
                raise BrokerError("you cannot add yourself as requester of a role")
            if user in role.approvers and user not in old_approvers:
                raise BrokerError("you cannot add yourself as approver of a role")

    # ---- implementations ----

    def _propose(self, admin: str, proposal: object) -> PolicyChange:
        old = self._current()
        self._require_admin(old, admin)
        try:
            encoded = json.dumps(proposal, ensure_ascii=True)
        except (TypeError, ValueError) as exc:
            raise InvalidProposalError("invalid policy:\nthe proposal is not JSON data") from exc
        if len(encoded) > MAX_PROPOSAL_CHARS:
            raise InvalidProposalError("invalid policy:\nthe proposal is too large")
        try:
            new = policy_from_mapping(proposal)
        except PolicyError as exc:
            raise InvalidProposalError(str(exc)) from exc
        new_hash = policy_digest(new)
        base_hash = policy_digest(old)
        if new_hash == base_hash:
            raise BrokerError("the proposal does not change the policy")
        self._check_rules(new)
        self._check_self_grants(old, new, admin)

        now = self._clock()
        body = json.dumps(policy_to_data(new), sort_keys=True, separators=(",", ":"))
        with self._store.transaction():
            if self._store.count_pending_policy_changes() >= MAX_PENDING_CHANGES:
                raise BrokerError("too many pending policy changes")
            change_id = self._store.insert_policy_change(
                proposer=admin,
                summary=summarize(old, new),
                base_hash=base_hash,
                new_hash=new_hash,
                new_policy=body,
                proposed_at=now,
            )
            self._audit.record(
                "policy_proposed",
                admin,
                now,
                {"change_id": change_id, "base_hash": base_hash, "new_hash": new_hash},
            )
        return self._reload(change_id)

    def _approve(self, change_id: int, admin: str) -> PolicyChange:
        now = self._clock()
        stale = False
        with self._store.transaction():
            change = self._pending(change_id)
            old = self._current()
            self._require_admin(old, admin)
            if admin == change.proposer:
                raise BrokerError("the proposer cannot approve their own change")
            new = self._stored_policy(change)
            if policy_digest(old) != change.base_hash:
                # Persist the stale mark; raise only after the transaction commits.
                self._store.decide_policy_change(change_id, "stale", "system", now)
                self._audit.record("policy_change_stale", "system", now, {"change_id": change_id})
                stale = True
            else:
                self._check_rules(new)
                self._check_self_grants(old, new, admin)
                staged = self._stage(new, change_id)
                try:
                    self._store.decide_policy_change(change_id, "applied", admin, now)
                    details: dict[str, Detail] = {
                        "change_id": change_id,
                        "new_hash": change.new_hash,
                    }
                    self._audit.record("policy_approved", admin, now, details)
                    self._audit.record("policy_applied", "system", now, details)
                    os.replace(staged, self._path)
                except OSError as exc:
                    staged.unlink(missing_ok=True)
                    raise BrokerError("could not write the policy file") from exc
                except BaseException:
                    staged.unlink(missing_ok=True)
                    raise
        if stale:
            raise BrokerError("the policy changed after this proposal; propose it again")
        return self._reload(change_id)

    def _reject(self, change_id: int, admin: str) -> PolicyChange:
        now = self._clock()
        with self._store.transaction():
            self._pending(change_id)
            self._require_admin(self._current(), admin)
            self._store.decide_policy_change(change_id, "rejected", admin, now)
            self._audit.record("policy_rejected", admin, now, {"change_id": change_id})
        return self._reload(change_id)

    def _pending(self, change_id: int) -> PolicyChange:
        change = self._store.get_policy_change(change_id)
        if change is None:
            raise BrokerError("policy change not found")
        if change.status != "pending":
            raise BrokerError(f"policy change is already {change.status}")
        return change

    def _reload(self, change_id: int) -> PolicyChange:
        change = self._store.get_policy_change(change_id)
        if change is None:
            raise BrokerError("policy change not found")
        return change

    def _stored_policy(self, change: PolicyChange) -> Policy:
        body = self._store.get_policy_change_body(change.id)
        if body is None:
            raise BrokerError("policy change not found")
        try:
            new = policy_from_mapping(json.loads(body))
        except (ValueError, PolicyError) as exc:
            raise BrokerError("the stored proposal is no longer valid") from exc
        if policy_digest(new) != change.new_hash:
            raise BrokerError("the stored proposal does not match its hash")
        return new

    def _stage(self, new: Policy, change_id: int) -> Path:
        """Write the backup and a validated temporary file next to the policy file."""
        staged = self._path.with_name(f".{self._path.name}.new")
        backups = self._path.parent / "backups"
        name = f"{self._path.stem}.before-change-{change_id:04d}{self._path.suffix}"
        try:
            backups.mkdir(exist_ok=True)
            shutil.copyfile(self._path, backups / name)
            with staged.open("w", encoding="utf-8", newline="\n") as handle:
                handle.write(policy_to_yaml(new))
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            raise BrokerError("could not prepare the new policy file") from exc
        try:
            check = load_policy(staged)
        except PolicyError as exc:
            staged.unlink(missing_ok=True)
            raise BrokerError("the new policy file failed its own validation") from exc
        if policy_digest(check) != policy_digest(new):
            staged.unlink(missing_ok=True)
            raise BrokerError("the new policy file does not match the proposal")
        return staged

    # ---- refusal logging ----

    def _guarded(self, action: str, actor: str, target_id: int | None, call: Callable[[], T]) -> T:
        try:
            return call()
        except BrokerError as exc:
            self._log_refusal(action, actor, exc, target_id)
            raise

    def _log_refusal(
        self, action: str, actor: str, exc: BrokerError, target_id: int | None
    ) -> None:
        # Validation messages can contain admin-typed key names: log a fixed reason instead.
        reason = "invalid policy" if isinstance(exc, InvalidProposalError) else str(exc)
        details: dict[str, Detail] = {
            "action": action,
            "reason": reason,
            "target_id": target_id,
            "role": None,
        }
        who = actor if _IDENT.fullmatch(actor) else "invalid"
        try:
            with self._store.transaction():
                self._audit.record("action_refused", who, self._clock(), details)
        except AuditError:
            return
