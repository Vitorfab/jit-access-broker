import json
from pathlib import Path

from typer.testing import CliRunner

from jit_broker.cli import app

runner = CliRunner()
EXAMPLE = Path(__file__).resolve().parents[1] / "policies" / "example.yaml"

REQUEST = [
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


def _args(tmp_path: Path, *rest: str) -> list[str]:
    return ["--policy", str(EXAMPLE), "--db", str(tmp_path / "state.db"), *rest]


def test_validate_policy_accepts_example() -> None:
    result = runner.invoke(app, ["validate-policy", str(EXAMPLE)])
    assert result.exit_code == 0
    assert "Policy OK: 5 users, 4 roles." in result.output


def test_validate_policy_fails_on_missing_file(tmp_path: Path) -> None:
    result = runner.invoke(app, ["validate-policy", str(tmp_path / "nope.yaml")])
    assert result.exit_code == 1


def test_request_approve_list_flow(tmp_path: Path) -> None:
    result = runner.invoke(app, _args(tmp_path, *REQUEST))
    assert result.exit_code == 0
    assert "#1 [pending]" in result.output
    approve = ["approve", "1", "--as", "carol", "--reason", "Looks fine"]
    result = runner.invoke(app, _args(tmp_path, *approve))
    assert result.exit_code == 0
    assert "[approved]" in result.output
    result = runner.invoke(app, _args(tmp_path, "list", "--status", "approved"))
    assert "#1 [approved]" in result.output


def test_list_json_prints_one_object_per_line(tmp_path: Path) -> None:
    runner.invoke(app, _args(tmp_path, *REQUEST))
    result = runner.invoke(app, _args(tmp_path, "list", "--json"))
    assert result.exit_code == 0
    lines = [line for line in result.output.splitlines() if line.strip()]
    assert len(lines) == 1
    assert json.loads(lines[0])["requester"] == "alice"


def test_unauthorized_approval_fails_with_error_message(tmp_path: Path) -> None:
    runner.invoke(app, _args(tmp_path, *REQUEST))
    result = runner.invoke(
        app, _args(tmp_path, "approve", "1", "--as", "jonas", "--reason", "Trying anyway")
    )
    assert result.exit_code == 1
    assert "error:" in result.output


def test_invalid_status_filter_fails(tmp_path: Path) -> None:
    result = runner.invoke(app, _args(tmp_path, "list", "--status", "bogus"))
    assert result.exit_code == 1
