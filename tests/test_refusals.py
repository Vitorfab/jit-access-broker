import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from jit_broker.audit import AuditLog, verify_log
from jit_broker.policy import load_policy
from jit_broker.service import Broker, BrokerError
from jit_broker.store import Store

EXAMPLE = Path(__file__).resolve().parents[1] / "policies" / "example.yaml"
JUSTIFICATION = "Investigating a simulated incident"

Env = tuple[Broker, Path]


@pytest.fixture
def env(tmp_path: Path) -> Iterator[Env]:
    store = Store(tmp_path / "state.db")
    audit_path = tmp_path / "audit.jsonl"
    yield Broker(load_policy(EXAMPLE), store, AuditLog(audit_path)), audit_path
    store.close()


def _entries(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _refusals(path: Path) -> list[dict[str, Any]]:
    return [e for e in _entries(path) if e["event"] == "action_refused"]


def test_refused_request_is_logged(env: Env) -> None:
    broker, audit_path = env
    with pytest.raises(BrokerError, match="cannot request"):
        broker.request_access("jonas", "db-admin", 60, JUSTIFICATION)
    (entry,) = _refusals(audit_path)
    assert entry["actor"] == "jonas"
    assert entry["details"]["action"] == "request"
    assert entry["details"]["role"] == "db-admin"
    assert "cannot request" in entry["details"]["reason"]


def test_refused_approval_by_non_approver_is_logged(env: Env) -> None:
    broker, audit_path = env
    request = broker.request_access("alice", "db-readonly", 60, JUSTIFICATION)
    with pytest.raises(BrokerError, match="cannot approve"):
        broker.approve(request.id, "jonas", "Not my job")
    (entry,) = _refusals(audit_path)
    assert entry["actor"] == "jonas"
    assert entry["details"]["action"] == "approve"
    assert entry["details"]["target_id"] == request.id


def test_repeated_decision_is_refused_and_logged(env: Env) -> None:
    broker, audit_path = env
    request = broker.request_access("alice", "db-admin", 60, JUSTIFICATION)
    broker.approve(request.id, "carol", "First approval")
    with pytest.raises(BrokerError, match="already decided"):
        broker.approve(request.id, "carol", "Trying again")
    (entry,) = _refusals(audit_path)
    assert "already decided" in entry["details"]["reason"]


def test_refused_admin_actions_are_logged(env: Env) -> None:
    broker, audit_path = env
    with pytest.raises(BrokerError, match="requires an admin"):
        broker.revoke_grant(5, "carol")
    with pytest.raises(BrokerError, match="requires an admin"):
        broker.sweep_expired("carol")
    actions = [e["details"]["action"] for e in _refusals(audit_path)]
    assert actions == ["revoke", "sweep"]
    assert _refusals(audit_path)[0]["details"]["target_id"] == 5


def test_refused_check_is_logged_without_unsafe_role(env: Env) -> None:
    broker, audit_path = env
    with pytest.raises(BrokerError, match="unknown user"):
        broker.check_access("ghost", "db-readonly")
    with pytest.raises(BrokerError, match="invalid role"):
        broker.check_access("alice", "Bad Role!")
    first, second = _refusals(audit_path)
    assert first["actor"] == "ghost"
    assert second["details"]["role"] is None


def test_actor_with_unsafe_characters_is_not_logged_verbatim(env: Env) -> None:
    broker, audit_path = env
    with pytest.raises(BrokerError, match="unknown user"):
        broker.request_access("Evil\nUser; DROP", "db-readonly", 60, JUSTIFICATION)
    (entry,) = _refusals(audit_path)
    assert entry["actor"] == "invalid"
    assert "Evil" not in audit_path.read_text(encoding="utf-8")


def test_refusal_never_logs_free_text(env: Env) -> None:
    broker, audit_path = env
    with pytest.raises(BrokerError, match="justification"):
        broker.request_access("alice", "db-readonly", 60, "hunter2")
    assert "hunter2" not in audit_path.read_text(encoding="utf-8")


def test_log_with_refusals_still_verifies(env: Env) -> None:
    broker, audit_path = env
    broker.request_access("alice", "db-readonly", 60, JUSTIFICATION)
    with pytest.raises(BrokerError):
        broker.approve(1, "jonas", "Not my job")
    with pytest.raises(BrokerError):
        broker.sweep_expired("carol")
    assert verify_log(audit_path).entries == len(_entries(audit_path)) == 3
