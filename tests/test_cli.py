from pathlib import Path

from typer.testing import CliRunner

from jit_broker.cli import app

runner = CliRunner()
EXAMPLE = Path(__file__).resolve().parents[1] / "policies" / "example.yaml"


def test_validate_policy_accepts_example() -> None:
    result = runner.invoke(app, ["validate-policy", str(EXAMPLE)])
    assert result.exit_code == 0
    assert "Policy OK: 5 users, 4 roles." in result.output


def test_validate_policy_fails_on_missing_file(tmp_path: Path) -> None:
    result = runner.invoke(app, ["validate-policy", str(tmp_path / "nope.yaml")])
    assert result.exit_code == 1
