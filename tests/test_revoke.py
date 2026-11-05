import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from jit_broker.audit import AuditLog
from jit_broker.policy import load_policy
from jit_broker.service import Broker, BrokerError
from jit_broker.store import Store

EXAMPLE = Path(__file__).resolve().parents[1] / "policies" / "example.yaml"
JUSTIFICATION = "Investigating a simulated incident"


class FakeClock:
    def __init__(self) -> None:
        self.now = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kwargs: float) -> None:
        self.now += timedelta(**kwargs)


Env = tuple[Broker, FakeClock, Path]


@pytest.fixture
def env(tmp_path: Path) -> Iterator[Env]:
    clock = FakeClock()
    store = Store(tmp_path / "state.db")
    audit_path = tmp_path / "audit.jsonl"
    yield Broker(load_policy(EXAMPLE), store, AuditLog(audit_path), clock), clock, audit_path
    store.close()


def _events(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _granted(broker: Broker) -> int:
    request = broker.request_access("alice", "db-readonly", 60, JUSTIFICATION)
    broker.approve(request.id, "carol", "Looks fine")
    return broker.list_grants()[0].id


def test_revocation_removes_access_immediately(env: Env) -> None:
    broker, _, _ = env
    grant_id = _granted(broker)
    assert broker.check_access("alice", "db-readonly").allowed is True
    grant = broker.revoke_grant(grant_id, "arthur")
    assert grant.revoked_at is not None
    assert broker.check_access("alice", "db-readonly").allowed is False


def test_only_admins_can_revoke(env: Env) -> None:
    broker, _, _ = env
    grant_id = _granted(broker)
    for user in ("carol", "alice", "ghost"):
        with pytest.raises(BrokerError, match="requires an admin"):
            broker.revoke_grant(grant_id, user)
    assert broker.check_access("alice", "db-readonly").allowed is True


def test_revoking_unknown_grant_fails(env: Env) -> None:
    broker, _, _ = env
    with pytest.raises(BrokerError, match="grant not found"):
        broker.revoke_grant(999, "arthur")


def test_revocation_is_idempotent_and_logged_once(env: Env) -> None:
    broker, clock, audit_path = env
    grant_id = _granted(broker)
    first = broker.revoke_grant(grant_id, "arthur")
    clock.advance(minutes=5)
    second = broker.revoke_grant(grant_id, "arthur")
    assert second.revoked_at == first.revoked_at
    revoked = [e for e in _events(audit_path) if e["event"] == "grant_revoked"]
    assert len(revoked) == 1
    assert revoked[0]["actor"] == "arthur"
    assert revoked[0]["details"]["was_active"] is True


def test_revoking_an_already_ended_grant_is_safe(env: Env) -> None:
    broker, clock, audit_path = env
    grant_id = _granted(broker)
    clock.advance(hours=2)
    broker.revoke_grant(grant_id, "arthur")
    entry = [e for e in _events(audit_path) if e["event"] == "grant_revoked"][0]
    assert entry["details"]["was_active"] is False


def test_sweep_expires_only_overdue_pending_requests(env: Env) -> None:
    broker, clock, audit_path = env
    broker.request_access("alice", "db-readonly", 60, JUSTIFICATION)
    broker.request_access("jonas", "audit-viewer", 60, JUSTIFICATION)
    clock.advance(hours=25)
    broker.request_access("alice", "audit-viewer", 60, JUSTIFICATION)
    assert broker.sweep_expired("arthur") == 2
    statuses = [r.status.value for r in broker.list_requests()]
    assert statuses == ["expired", "expired", "pending"]
    assert broker.sweep_expired("arthur") == 0
    expired = [e for e in _events(audit_path) if e["event"] == "request_expired"]
    assert len(expired) == 2


def test_only_admins_can_sweep(env: Env) -> None:
    broker, _, _ = env
    with pytest.raises(BrokerError, match="requires an admin"):
        broker.sweep_expired("carol")
