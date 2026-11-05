import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from jit_broker.audit import GENESIS_HASH, AuditError, AuditLog, VerifyResult, verify_log
from jit_broker.cli import app

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
EXAMPLE = Path(__file__).resolve().parents[1] / "policies" / "example.yaml"
runner = CliRunner()


def _digest(entry: dict[str, object]) -> str:
    canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _make_log(tmp_path: Path, count: int = 3) -> Path:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for index in range(count):
        log.record("event", "alice", NOW, {"n": index})
    return path


def _lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


def test_entries_are_chained(tmp_path: Path) -> None:
    path = _make_log(tmp_path, 2)
    first, second = (json.loads(line) for line in _lines(path))
    assert first["prev_hash"] == GENESIS_HASH
    assert second["prev_hash"] == first["hash"]
    assert len(first["hash"]) == 64


def test_intact_log_verifies(tmp_path: Path) -> None:
    path = _make_log(tmp_path)
    result = verify_log(path)
    assert result.entries == 3
    assert result.head_hash == json.loads(_lines(path)[-1])["hash"]


def test_chain_continues_after_reopening_the_log(tmp_path: Path) -> None:
    path = _make_log(tmp_path)
    AuditLog(path).record("event", "bob", NOW, {})
    assert verify_log(path).entries == 4


def test_modified_entry_is_detected(tmp_path: Path) -> None:
    path = _make_log(tmp_path)
    path.write_text(path.read_text(encoding="utf-8").replace('"n":1', '"n":9'), encoding="utf-8")
    with pytest.raises(AuditError, match="line 2: entry was modified"):
        verify_log(path)


def test_deleted_entry_is_detected(tmp_path: Path) -> None:
    path = _make_log(tmp_path)
    lines = _lines(path)
    path.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")
    with pytest.raises(AuditError, match="line 2: sequence number mismatch"):
        verify_log(path)


def test_modified_entry_with_recomputed_hash_still_breaks_the_chain(tmp_path: Path) -> None:
    path = _make_log(tmp_path)
    entries = [json.loads(line) for line in _lines(path)]
    entries[1]["details"]["n"] = 9
    entries[1]["hash"] = _digest({k: v for k, v in entries[1].items() if k != "hash"})
    path.write_text(
        "\n".join(json.dumps(e, sort_keys=True, separators=(",", ":")) for e in entries) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(AuditError, match="line 3: chain broken"):
        verify_log(path)


def test_truncating_the_tail_is_not_detected_known_limit(tmp_path: Path) -> None:
    # Documented limit: without an external copy of the head hash, removing the newest
    # entries leaves a valid (shorter) chain.
    path = _make_log(tmp_path)
    path.write_text("\n".join(_lines(path)[:2]) + "\n", encoding="utf-8")
    assert verify_log(path).entries == 2


def test_missing_log_is_reported(tmp_path: Path) -> None:
    with pytest.raises(AuditError, match="not found"):
        verify_log(tmp_path / "nope.jsonl")


def test_empty_log_is_valid(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text("", encoding="utf-8")
    assert verify_log(path) == VerifyResult(entries=0, head_hash=GENESIS_HASH)


def test_garbage_line_is_reported(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text("not json\n", encoding="utf-8")
    with pytest.raises(AuditError, match="line 1: not valid JSON"):
        verify_log(path)


def test_entry_without_hash_is_reported(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text('{"seq":1}\n', encoding="utf-8")
    with pytest.raises(AuditError, match="line 1: missing hash"):
        verify_log(path)


def test_cli_audit_verify_accepts_intact_and_rejects_tampered_log(tmp_path: Path) -> None:
    base = ["--policy", str(EXAMPLE), "--db", str(tmp_path / "state.db")]
    request = [
        "request",
        "--as",
        "alice",
        "--role",
        "db-readonly",
        "--minutes",
        "60",
        "--justification",
        "Checking a simulated report",
    ]
    assert runner.invoke(app, [*base, *request]).exit_code == 0
    ok = runner.invoke(app, [*base, "audit", "verify"])
    assert ok.exit_code == 0
    assert "Audit log OK: 1 entries" in ok.output
    log = tmp_path / "state-audit.jsonl"
    log.write_text(
        log.read_text(encoding="utf-8").replace("db-readonly", "db-admin"), encoding="utf-8"
    )
    bad = runner.invoke(app, [*base, "audit", "verify"])
    assert bad.exit_code == 1
    assert "modified" in bad.output
