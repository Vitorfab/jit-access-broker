import json
from pathlib import Path

from typer.testing import CliRunner

from jit_broker.cli import app

runner = CliRunner()
EXAMPLE = Path(__file__).resolve().parents[1] / "policies" / "example.yaml"


def _run(tmp_path: Path, *args: str) -> tuple[int, str]:
    result = runner.invoke(
        app, ["--policy", str(EXAMPLE), "--db", str(tmp_path / "state.db"), *args]
    )
    return result.exit_code, result.output


def test_full_lifecycle_two_person_approval_then_revocation(tmp_path: Path) -> None:
    code, _ = _run(
        tmp_path,
        "request",
        "--as",
        "alice",
        "--role",
        "db-admin",
        "--minutes",
        "60",
        "--justification",
        "Simulated database maintenance",
    )
    assert code == 0
    check = ("check", "--as", "alice", "--role", "db-admin")
    assert _run(tmp_path, *check)[0] == 1
    assert _run(tmp_path, "approve", "1", "--as", "carol", "--reason", "First approval")[0] == 0
    assert _run(tmp_path, *check)[0] == 1
    assert _run(tmp_path, "approve", "1", "--as", "carlos", "--reason", "Second approval")[0] == 0
    assert _run(tmp_path, *check)[0] == 0

    assert _run(tmp_path, "revoke", "1", "--as", "carol")[0] == 1
    assert _run(tmp_path, *check)[0] == 0
    code, output = _run(tmp_path, "revoke", "1", "--as", "arthur")
    assert code == 0
    assert "revoked" in output
    assert _run(tmp_path, *check)[0] == 1
    assert _run(tmp_path, "revoke", "1", "--as", "arthur")[0] == 0

    audit = tmp_path / "state-audit.jsonl"
    events = [json.loads(line)["event"] for line in audit.read_text(encoding="utf-8").splitlines()]
    assert events.count("grant_revoked") == 1
    assert events.count("grant_created") == 1


def test_sweep_requires_admin(tmp_path: Path) -> None:
    assert _run(tmp_path, "sweep", "--as", "carol")[0] == 1
    code, output = _run(tmp_path, "sweep", "--as", "arthur")
    assert code == 0
    assert "Expired 0" in output
