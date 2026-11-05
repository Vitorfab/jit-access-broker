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


def test_final_approval_creates_grant_with_time_window(env: Env) -> None:
    broker, clock, _ = env
    request = broker.request_access("alice", "db-readonly", 60, JUSTIFICATION)
    broker.approve(request.id, "carol", "Looks fine")
    grants = broker.list_grants()
    assert len(grants) == 1
    assert grants[0].grantee == "alice"
    assert grants[0].starts_at == clock.now
    assert grants[0].ends_at == clock.now + timedelta(minutes=60)


def test_access_is_valid_only_inside_the_window(env: Env) -> None:
    broker, clock, _ = env
    request = broker.request_access("alice", "db-readonly", 60, JUSTIFICATION)
    broker.approve(request.id, "carol", "Looks fine")
    assert broker.check_access("alice", "db-readonly").allowed is True
    clock.advance(minutes=59)
    assert broker.check_access("alice", "db-readonly").allowed is True
    clock.advance(minutes=1)  # exactly at the end: no longer valid
    result = broker.check_access("alice", "db-readonly")
    assert result.allowed is False
    assert result.ends_at is None


def test_pending_request_gives_no_access(env: Env) -> None:
    broker, _, _ = env
    broker.request_access("alice", "db-readonly", 60, JUSTIFICATION)
    assert broker.check_access("alice", "db-readonly").allowed is False


def test_high_risk_grant_exists_only_after_second_approval(env: Env) -> None:
    broker, _, _ = env
    request = broker.request_access("alice", "db-admin", 60, JUSTIFICATION)
    broker.approve(request.id, "carol", "First approval")
    assert broker.check_access("alice", "db-admin").allowed is False
    broker.approve(request.id, "carlos", "Second approval")
    assert broker.check_access("alice", "db-admin").allowed is True


def test_denied_request_creates_no_grant(env: Env) -> None:
    broker, _, _ = env
    request = broker.request_access("alice", "db-readonly", 60, JUSTIFICATION)
    broker.deny(request.id, "carol", "Not needed")
    assert broker.list_grants() == []
    assert broker.check_access("alice", "db-readonly").allowed is False


def test_grant_is_bound_to_user_and_role(env: Env) -> None:
    broker, _, _ = env
    request = broker.request_access("alice", "db-readonly", 60, JUSTIFICATION)
    broker.approve(request.id, "carol", "Looks fine")
    assert broker.check_access("jonas", "db-readonly").allowed is False
    assert broker.check_access("alice", "audit-viewer").allowed is False


def test_check_rejects_unknown_user_and_malformed_role(env: Env) -> None:
    broker, _, _ = env
    with pytest.raises(BrokerError, match="unknown user"):
        broker.check_access("ghost", "db-readonly")
    with pytest.raises(BrokerError, match="invalid role"):
        broker.check_access("alice", "Bad Role!")


def test_audit_log_records_the_full_flow_without_free_text(env: Env) -> None:
    broker, _, audit_path = env
    request = broker.request_access("alice", "db-readonly", 60, JUSTIFICATION, "TCK-7")
    broker.approve(request.id, "carol", "Looks fine")
    broker.check_access("alice", "db-readonly")
    entries = _events(audit_path)
    assert [entry["event"] for entry in entries] == [
        "request_created",
        "approved",
        "grant_created",
        "access_check",
    ]
    assert [entry["seq"] for entry in entries] == [1, 2, 3, 4]
    assert entries[-1]["details"]["allowed"] is True
    content = audit_path.read_text(encoding="utf-8")
    assert JUSTIFICATION not in content
    assert "Looks fine" not in content


def test_denied_check_is_logged(env: Env) -> None:
    broker, _, audit_path = env
    broker.check_access("alice", "db-readonly")
    entry = _events(audit_path)[-1]
    assert entry["event"] == "access_check"
    assert entry["details"]["allowed"] is False


def test_expiry_of_pending_request_is_logged(env: Env) -> None:
    broker, clock, audit_path = env
    request = broker.request_access("alice", "db-readonly", 60, JUSTIFICATION)
    clock.advance(hours=25)
    with pytest.raises(BrokerError, match="expired"):
        broker.approve(request.id, "carol", "Too late")
    assert _events(audit_path)[-1]["event"] == "request_expired"
