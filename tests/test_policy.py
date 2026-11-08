import copy
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml

from jit_broker.policy import MAX_POLICY_FILE_BYTES, Capability, PolicyError, load_policy

EXAMPLE = Path(__file__).resolve().parents[1] / "policies" / "example.yaml"


def _example_data() -> dict[str, Any]:
    data = yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return copy.deepcopy(data)


def _write(tmp_path: Path, data: dict[str, Any]) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def test_example_policy_loads() -> None:
    policy = load_policy(EXAMPLE)
    assert len(policy.users) == 6
    assert len(policy.roles) == 4
    assert Capability.ADMIN in policy.users["arthur"].capabilities


def test_high_risk_role_requires_two_approvals_and_two_hours() -> None:
    role = load_policy(EXAMPLE).roles["db-admin"]
    assert role.approvals_required == 2
    assert role.max_duration == timedelta(hours=2)


def test_unknown_field_is_rejected(tmp_path: Path) -> None:
    data = _example_data()
    data["roles"]["db-admin"]["ttl"] = 1
    with pytest.raises(PolicyError, match="ttl"):
        load_policy(_write(tmp_path, data))


def test_wrong_schema_version_is_rejected(tmp_path: Path) -> None:
    data = _example_data()
    data["schema_version"] = 2
    with pytest.raises(PolicyError, match="schema_version"):
        load_policy(_write(tmp_path, data))


def test_unknown_approver_is_rejected(tmp_path: Path) -> None:
    data = _example_data()
    data["roles"]["db-readonly"]["approvers"].append("ghost")
    with pytest.raises(PolicyError, match="unknown approver"):
        load_policy(_write(tmp_path, data))


def test_approver_without_approve_capability_is_rejected(tmp_path: Path) -> None:
    data = _example_data()
    data["roles"]["db-readonly"]["approvers"].append("alice")
    with pytest.raises(PolicyError, match="capability"):
        load_policy(_write(tmp_path, data))


def test_requester_without_request_capability_is_rejected(tmp_path: Path) -> None:
    data = _example_data()
    data["roles"]["db-readonly"]["requesters"].append("carol")
    with pytest.raises(PolicyError, match="capability"):
        load_policy(_write(tmp_path, data))


def test_more_approvals_than_approvers_is_rejected(tmp_path: Path) -> None:
    data = _example_data()
    data["roles"]["server-ops"]["approvals_required"] = 3
    with pytest.raises(PolicyError, match="approvals_required"):
        load_policy(_write(tmp_path, data))


def test_duplicate_approvers_are_rejected(tmp_path: Path) -> None:
    data = _example_data()
    data["roles"]["db-readonly"]["approvers"] = ["carol", "carol"]
    with pytest.raises(PolicyError, match="duplicate"):
        load_policy(_write(tmp_path, data))


def test_duration_below_minimum_is_rejected(tmp_path: Path) -> None:
    data = _example_data()
    data["roles"]["db-readonly"]["max_duration_minutes"] = 5
    with pytest.raises(PolicyError, match="max_duration_minutes"):
        load_policy(_write(tmp_path, data))


def test_bad_role_identifier_is_rejected(tmp_path: Path) -> None:
    data = _example_data()
    data["roles"]["Bad Role"] = data["roles"].pop("db-readonly")
    with pytest.raises(PolicyError, match="invalid policy"):
        load_policy(_write(tmp_path, data))


def test_error_message_does_not_echo_input_values(tmp_path: Path) -> None:
    data = _example_data()
    data["roles"]["db-admin"]["approvals_required"] = "hunter2-not-a-number"
    with pytest.raises(PolicyError) as excinfo:
        load_policy(_write(tmp_path, data))
    assert "hunter2-not-a-number" not in str(excinfo.value)


def test_missing_file_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="cannot read"):
        load_policy(tmp_path / "nope.yaml")


def test_broken_yaml_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text("a: [unclosed", encoding="utf-8")
    with pytest.raises(PolicyError, match="not valid YAML"):
        load_policy(path)


def test_python_object_tags_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text("x: !!python/object/apply:os.system ['echo hi']\n", encoding="utf-8")
    with pytest.raises(PolicyError, match="not valid YAML"):
        load_policy(path)


@pytest.mark.parametrize("content", ["", "- a\n- b\n"])
def test_non_mapping_root_is_rejected(tmp_path: Path, content: str) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(PolicyError, match="root must be a mapping"):
        load_policy(path)


def test_oversized_file_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text("#" * (MAX_POLICY_FILE_BYTES + 1), encoding="utf-8")
    with pytest.raises(PolicyError, match="too large"):
        load_policy(path)


def test_duplicate_requesters_are_rejected(tmp_path: Path) -> None:
    data = _example_data()
    data["roles"]["db-readonly"]["requesters"] = ["alice", "alice"]
    with pytest.raises(PolicyError, match="duplicate"):
        load_policy(_write(tmp_path, data))
