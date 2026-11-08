import json
import shutil
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml

from jit_broker.audit import AuditLog, verify_log
from jit_broker.policy import load_policy, policy_digest
from jit_broker.policy_admin import MAX_PENDING_CHANGES, PolicyAdmin
from jit_broker.service import BrokerError
from jit_broker.store import Store

EXAMPLE = Path(__file__).resolve().parents[1] / "policies" / "example.yaml"

Env = tuple[PolicyAdmin, Path, Path]


class FakeClock:
    def __call__(self) -> datetime:
        return datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def _data(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def _readonly_max(path: Path, minutes: int) -> dict[str, Any]:
    data = _data(path)
    data["roles"]["db-readonly"]["max_duration_minutes"] = minutes
    return data


@pytest.fixture
def make(tmp_path: Path) -> Iterator[Callable[..., Env]]:
    stores: list[Store] = []

    def factory(data: dict[str, Any] | None = None) -> Env:
        path = tmp_path / "policy.yaml"
        if data is None:
            shutil.copyfile(EXAMPLE, path)
        else:
            path.write_text(yaml.safe_dump(data), encoding="utf-8")
        store = Store(tmp_path / "state.db")
        stores.append(store)
        audit = tmp_path / "audit.jsonl"
        return PolicyAdmin(path, store, AuditLog(audit), FakeClock()), path, audit

    yield factory
    for store in stores:
        store.close()


def test_two_admins_apply_a_change_and_keep_a_backup(make: Callable[..., Env]) -> None:
    admin, path, _ = make()
    change = admin.propose("arthur", _readonly_max(path, 240))
    assert change.status == "pending"
    assert "roles changed: db-readonly" in change.summary
    assert load_policy(path).roles["db-readonly"].max_duration_minutes == 480
    applied = admin.approve(change.id, "beatriz")
    assert applied.status == "applied"
    assert applied.decided_by == "beatriz"
    assert load_policy(path).roles["db-readonly"].max_duration_minutes == 240
    backups = list((path.parent / "backups").glob("*.yaml"))
    assert len(backups) == 1
    assert load_policy(backups[0]).roles["db-readonly"].max_duration_minutes == 480


def test_proposer_cannot_approve_their_own_change(make: Callable[..., Env]) -> None:
    admin, path, _ = make()
    change = admin.propose("arthur", _readonly_max(path, 240))
    with pytest.raises(BrokerError, match="proposer cannot approve"):
        admin.approve(change.id, "arthur")
    assert admin.list_changes("arthur")[0].status == "pending"
    assert load_policy(path).roles["db-readonly"].max_duration_minutes == 480


@pytest.mark.parametrize("user", ["alice", "carol", "ghost"])
def test_only_admins_can_use_the_editor(make: Callable[..., Env], user: str) -> None:
    admin, path, _ = make()
    with pytest.raises(BrokerError, match="requires an admin"):
        admin.propose(user, _readonly_max(path, 240))
    with pytest.raises(BrokerError, match="requires an admin"):
        admin.list_changes(user)
    with pytest.raises(BrokerError, match="requires an admin"):
        admin.view_policy(user)
    change = admin.propose("arthur", _readonly_max(path, 240))
    with pytest.raises(BrokerError, match="requires an admin"):
        admin.approve(change.id, user)
    with pytest.raises(BrokerError, match="requires an admin"):
        admin.reject(change.id, user)


def test_admin_cannot_grant_themselves_new_capabilities(make: Callable[..., Env]) -> None:
    admin, path, _ = make()
    data = _data(path)
    data["users"]["arthur"]["capabilities"] = ["admin", "approve"]
    with pytest.raises(BrokerError, match="grant yourself"):
        admin.propose("arthur", data)


def test_admin_cannot_add_themselves_to_a_role(make: Callable[..., Env]) -> None:
    data = _data(EXAMPLE)
    data["users"]["arthur"]["capabilities"] = ["admin", "approve"]
    admin, _, _ = make(data)
    proposal = json.loads(json.dumps(data))
    proposal["roles"]["db-readonly"]["approvers"].append("arthur")
    with pytest.raises(BrokerError, match="add yourself as approver"):
        admin.propose("arthur", proposal)


def test_approver_cannot_approve_a_change_that_benefits_them(make: Callable[..., Env]) -> None:
    data = _data(EXAMPLE)
    data["users"]["beatriz"]["capabilities"] = ["admin", "approve"]
    admin, _, _ = make(data)
    proposal = json.loads(json.dumps(data))
    proposal["roles"]["db-readonly"]["approvers"].append("beatriz")
    change = admin.propose("arthur", proposal)
    with pytest.raises(BrokerError, match="add yourself as approver"):
        admin.approve(change.id, "beatriz")
    assert admin.list_changes("arthur")[0].status == "pending"


def test_policy_must_keep_two_admins(make: Callable[..., Env]) -> None:
    admin, path, _ = make()
    data = _data(path)
    data["users"]["beatriz"]["capabilities"] = ["request"]
    with pytest.raises(BrokerError, match="at least 2 admins"):
        admin.propose("arthur", data)


def test_invalid_proposal_is_rejected_without_echoing_values(make: Callable[..., Env]) -> None:
    admin, path, audit = make()
    data = _data(path)
    data["roles"]["db-admin"]["approvals_required"] = "hunter2-not-a-number"
    with pytest.raises(BrokerError, match="invalid policy") as excinfo:
        admin.propose("arthur", data)
    assert "hunter2" not in str(excinfo.value)
    assert "hunter2" not in audit.read_text(encoding="utf-8")


def test_unknown_keys_are_rejected_and_not_logged(make: Callable[..., Env]) -> None:
    admin, path, audit = make()
    data = _data(path)
    data["roles"]["db-admin"]["secret-key-name"] = 1
    with pytest.raises(BrokerError, match="invalid policy"):
        admin.propose("arthur", data)
    assert "secret-key-name" not in audit.read_text(encoding="utf-8")


def test_proposal_that_changes_nothing_is_refused(make: Callable[..., Env]) -> None:
    admin, path, _ = make()
    with pytest.raises(BrokerError, match="does not change"):
        admin.propose("arthur", _data(path))


def test_stale_proposal_is_not_applied(make: Callable[..., Env]) -> None:
    admin, path, _ = make()
    first = admin.propose("arthur", _readonly_max(path, 240))
    other = _data(path)
    other["roles"]["db-admin"]["max_duration_minutes"] = 90
    second = admin.propose("beatriz", other)
    assert admin.approve(second.id, "arthur").status == "applied"
    with pytest.raises(BrokerError, match="changed after this proposal"):
        admin.approve(first.id, "beatriz")
    statuses = {c.id: c.status for c in admin.list_changes("arthur")}
    assert statuses[first.id] == "stale"
    assert load_policy(path).roles["db-readonly"].max_duration_minutes == 480


def test_rejected_change_is_final(make: Callable[..., Env]) -> None:
    admin, path, _ = make()
    change = admin.propose("arthur", _readonly_max(path, 240))
    assert admin.reject(change.id, "beatriz").status == "rejected"
    with pytest.raises(BrokerError, match="already rejected"):
        admin.approve(change.id, "beatriz")
    assert load_policy(path).roles["db-readonly"].max_duration_minutes == 480


def test_unknown_change_id_is_refused(make: Callable[..., Env]) -> None:
    admin, _, _ = make()
    with pytest.raises(BrokerError, match="not found"):
        admin.approve(99, "beatriz")


def test_audit_records_hashes_only_and_verifies(make: Callable[..., Env]) -> None:
    admin, path, audit = make()
    change = admin.propose("arthur", _readonly_max(path, 240))
    admin.approve(change.id, "beatriz")
    events = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
    assert [e["event"] for e in events] == [
        "policy_proposed",
        "policy_approved",
        "policy_applied",
    ]
    assert events[0]["details"]["new_hash"] == policy_digest(load_policy(path))
    assert "Read-only access" not in audit.read_text(encoding="utf-8")
    assert verify_log(audit).entries == 3


def test_pending_proposals_are_limited(make: Callable[..., Env]) -> None:
    admin, path, _ = make()
    for minutes in range(100, 100 + MAX_PENDING_CHANGES):
        admin.propose("arthur", _readonly_max(path, minutes))
    with pytest.raises(BrokerError, match="too many pending"):
        admin.propose("arthur", _readonly_max(path, 400))


def test_refused_attempts_are_logged(make: Callable[..., Env]) -> None:
    admin, path, audit = make()
    with pytest.raises(BrokerError):
        admin.propose("alice", _readonly_max(path, 240))
    entry = json.loads(audit.read_text(encoding="utf-8").splitlines()[-1])
    assert entry["event"] == "action_refused"
    assert entry["details"]["action"] == "policy_propose"


def test_view_policy_returns_digest(make: Callable[..., Env]) -> None:
    admin, path, _ = make()
    data, digest = admin.view_policy("arthur")
    assert digest == policy_digest(load_policy(path))
    assert "db-admin" in data["roles"]
