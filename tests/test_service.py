import copy
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml

from jit_broker.domain import RequestStatus
from jit_broker.policy import load_policy
from jit_broker.service import MAX_PENDING_PER_USER, Broker, BrokerError
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


def _policy_data() -> dict[str, Any]:
    data = yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return copy.deepcopy(data)


@pytest.fixture
def make(tmp_path: Path) -> Iterator[Callable[..., tuple[Broker, FakeClock]]]:
    stores: list[Store] = []

    def factory(data: dict[str, Any] | None = None) -> tuple[Broker, FakeClock]:
        policy_path = EXAMPLE
        if data is not None:
            policy_path = tmp_path / "policy.yaml"
            policy_path.write_text(yaml.safe_dump(data), encoding="utf-8")
        clock = FakeClock()
        store = Store(tmp_path / f"state{len(stores)}.db")
        stores.append(store)
        return Broker(load_policy(policy_path), store, clock), clock

    yield factory
    for store in stores:
        store.close()


def test_request_is_stored_as_pending(make: Callable[..., tuple[Broker, FakeClock]]) -> None:
    broker, _ = make()
    record = broker.request_access("alice", "db-readonly", 60, JUSTIFICATION, "TCK-1")
    assert record.id == 1
    assert record.status is RequestStatus.PENDING
    assert record.requester == "alice"
    assert record.ticket == "TCK-1"
    assert record.approvals == 0


def test_unknown_user_is_rejected(make: Callable[..., tuple[Broker, FakeClock]]) -> None:
    broker, _ = make()
    with pytest.raises(BrokerError, match="unknown user"):
        broker.request_access("ghost", "db-readonly", 60, JUSTIFICATION)


def test_role_not_allowed_for_user_is_rejected(
    make: Callable[..., tuple[Broker, FakeClock]],
) -> None:
    broker, _ = make()
    with pytest.raises(BrokerError, match="cannot request"):
        broker.request_access("jonas", "db-admin", 60, JUSTIFICATION)


def test_unknown_role_gives_same_error_as_forbidden_role(
    make: Callable[..., tuple[Broker, FakeClock]],
) -> None:
    broker, _ = make()
    with pytest.raises(BrokerError, match="cannot request"):
        broker.request_access("alice", "no-such-role", 60, JUSTIFICATION)


def test_duration_above_role_maximum_is_rejected(
    make: Callable[..., tuple[Broker, FakeClock]],
) -> None:
    broker, _ = make()
    with pytest.raises(BrokerError, match="duration"):
        broker.request_access("alice", "db-admin", 121, JUSTIFICATION)


def test_duration_below_minimum_is_rejected(
    make: Callable[..., tuple[Broker, FakeClock]],
) -> None:
    broker, _ = make()
    with pytest.raises(BrokerError, match="duration"):
        broker.request_access("alice", "db-readonly", 5, JUSTIFICATION)


def test_short_justification_is_rejected(make: Callable[..., tuple[Broker, FakeClock]]) -> None:
    broker, _ = make()
    with pytest.raises(BrokerError, match="justification"):
        broker.request_access("alice", "db-readonly", 60, "too short")


def test_justification_with_control_characters_is_rejected(
    make: Callable[..., tuple[Broker, FakeClock]],
) -> None:
    broker, _ = make()
    with pytest.raises(BrokerError, match="control characters"):
        broker.request_access("alice", "db-readonly", 60, "first line\nsecond line here")


def test_bad_ticket_is_rejected(make: Callable[..., tuple[Broker, FakeClock]]) -> None:
    broker, _ = make()
    with pytest.raises(BrokerError, match="ticket"):
        broker.request_access("alice", "db-readonly", 60, JUSTIFICATION, "bad ticket!")


def test_pending_request_limit_is_enforced(make: Callable[..., tuple[Broker, FakeClock]]) -> None:
    broker, _ = make()
    for _ in range(MAX_PENDING_PER_USER):
        broker.request_access("alice", "db-readonly", 60, JUSTIFICATION)
    with pytest.raises(BrokerError, match="too many pending"):
        broker.request_access("alice", "db-readonly", 60, JUSTIFICATION)


def test_single_approval_completes_a_normal_role(
    make: Callable[..., tuple[Broker, FakeClock]],
) -> None:
    broker, _ = make()
    request = broker.request_access("alice", "db-readonly", 60, JUSTIFICATION)
    result = broker.approve(request.id, "carol", "Looks fine")
    assert result.status is RequestStatus.APPROVED
    assert result.decided_at is not None
    assert result.approvals == 1


def test_high_risk_role_needs_two_distinct_approvers(
    make: Callable[..., tuple[Broker, FakeClock]],
) -> None:
    broker, _ = make()
    request = broker.request_access("alice", "db-admin", 60, JUSTIFICATION)
    first = broker.approve(request.id, "carol", "First approval")
    assert first.status is RequestStatus.PENDING
    assert first.approvals == 1
    second = broker.approve(request.id, "carlos", "Second approval")
    assert second.status is RequestStatus.APPROVED
    assert second.approvals == 2


def test_same_approver_cannot_decide_twice(make: Callable[..., tuple[Broker, FakeClock]]) -> None:
    broker, _ = make()
    request = broker.request_access("alice", "db-admin", 60, JUSTIFICATION)
    broker.approve(request.id, "carol", "First approval")
    with pytest.raises(BrokerError, match="already decided"):
        broker.approve(request.id, "carol", "Trying again")


def test_denied_request_cannot_be_approved_later(
    make: Callable[..., tuple[Broker, FakeClock]],
) -> None:
    broker, _ = make()
    request = broker.request_access("alice", "db-readonly", 60, JUSTIFICATION)
    denied = broker.deny(request.id, "carol", "Not needed")
    assert denied.status is RequestStatus.DENIED
    with pytest.raises(BrokerError, match="already denied"):
        broker.approve(request.id, "carlos", "Changed my mind")


def test_self_approval_is_blocked(make: Callable[..., tuple[Broker, FakeClock]]) -> None:
    data = _policy_data()
    data["users"]["alice"]["capabilities"] = ["request", "approve"]
    data["roles"]["db-readonly"]["approvers"].append("alice")
    broker, _ = make(data)
    request = broker.request_access("alice", "db-readonly", 60, JUSTIFICATION)
    with pytest.raises(BrokerError, match="self-approval"):
        broker.approve(request.id, "alice", "Approving myself")
    assert broker.list_requests()[0].status is RequestStatus.PENDING


def test_user_without_approve_capability_is_blocked(
    make: Callable[..., tuple[Broker, FakeClock]],
) -> None:
    broker, _ = make()
    request = broker.request_access("alice", "db-readonly", 60, JUSTIFICATION)
    with pytest.raises(BrokerError, match="cannot approve"):
        broker.approve(request.id, "jonas", "Not my job")
    with pytest.raises(BrokerError, match="cannot approve"):
        broker.approve(request.id, "ghost", "Not a user")


def test_approver_not_listed_for_the_role_is_blocked(
    make: Callable[..., tuple[Broker, FakeClock]],
) -> None:
    data = _policy_data()
    data["roles"]["server-ops"]["approvers"] = ["carol"]
    broker, _ = make(data)
    request = broker.request_access("jonas", "server-ops", 60, JUSTIFICATION)
    with pytest.raises(BrokerError, match="not an approver"):
        broker.approve(request.id, "carlos", "Not on the list")


def test_expired_pending_request_cannot_be_decided_and_is_marked(
    make: Callable[..., tuple[Broker, FakeClock]],
) -> None:
    broker, clock = make()
    request = broker.request_access("alice", "db-readonly", 60, JUSTIFICATION)
    clock.advance(hours=25)
    with pytest.raises(BrokerError, match="expired"):
        broker.approve(request.id, "carol", "Too late")
    assert broker.list_requests()[0].status is RequestStatus.EXPIRED


def test_unknown_request_id_is_rejected(make: Callable[..., tuple[Broker, FakeClock]]) -> None:
    broker, _ = make()
    with pytest.raises(BrokerError, match="not found"):
        broker.approve(999, "carol", "Does not exist")


def test_empty_reason_is_rejected(make: Callable[..., tuple[Broker, FakeClock]]) -> None:
    broker, _ = make()
    request = broker.request_access("alice", "db-readonly", 60, JUSTIFICATION)
    with pytest.raises(BrokerError, match="reason"):
        broker.approve(request.id, "carol", "   ")


def test_list_can_filter_by_status(make: Callable[..., tuple[Broker, FakeClock]]) -> None:
    broker, _ = make()
    first = broker.request_access("alice", "db-readonly", 60, JUSTIFICATION)
    broker.request_access("jonas", "audit-viewer", 60, JUSTIFICATION)
    broker.approve(first.id, "carol", "Looks fine")
    assert len(broker.list_requests()) == 2
    assert len(broker.list_requests(RequestStatus.PENDING)) == 1
    assert len(broker.list_requests(RequestStatus.APPROVED)) == 1
