import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from jit_broker.audit import AuditError, AuditLog

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def test_records_are_numbered_and_valid_json(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    assert log.record("one", "alice", NOW, {"k": 1}) == 1
    assert log.record("two", "bob", NOW, {}) == 2
    lines = path.read_text(encoding="utf-8").splitlines()
    first = json.loads(lines[0])
    assert first["schema_version"] == 1
    assert first["seq"] == 1
    assert first["event"] == "one"
    assert first["actor"] == "alice"
    assert first["details"] == {"k": 1}
    assert first["timestamp"].startswith("2026-01-01T12:00:00")
    assert json.loads(lines[1])["seq"] == 2


def test_sequence_continues_across_instances(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    AuditLog(path).record("one", "alice", NOW, {})
    assert AuditLog(path).record("two", "alice", NOW, {}) == 2


def test_corrupted_log_is_refused_and_left_untouched(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text("not json\n", encoding="utf-8")
    with pytest.raises(AuditError, match="corrupted"):
        AuditLog(path).record("one", "alice", NOW, {})
    assert path.read_text(encoding="utf-8") == "not json\n"


def test_unwritable_location_raises(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "missing-dir" / "audit.jsonl")
    with pytest.raises(AuditError, match="cannot write"):
        log.record("one", "alice", NOW, {})


def test_newlines_in_values_stay_on_one_line(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    AuditLog(path).record("one", "alice", NOW, {"note": "line1\nline2"})
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["details"]["note"] == "line1\nline2"
