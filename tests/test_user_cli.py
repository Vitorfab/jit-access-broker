import json
from pathlib import Path

from typer.testing import CliRunner

from jit_broker.cli import app

runner = CliRunner()
EXAMPLE = Path(__file__).resolve().parents[1] / "policies" / "example.yaml"
PW = "correct horse battery"


def _base(tmp_path: Path) -> list[str]:
    return ["--policy", str(EXAMPLE), "--db", str(tmp_path / "state.db")]


def test_user_create_prompts_for_the_password_and_never_logs_it(tmp_path: Path) -> None:
    result = runner.invoke(
        app, [*_base(tmp_path), "user", "create", "alice"], input=f"{PW}\n{PW}\n"
    )
    assert result.exit_code == 0
    assert "Account created for alice." in result.output
    assert PW not in result.output
    log = (tmp_path / "state-audit.jsonl").read_text(encoding="utf-8")
    assert PW not in log
    assert json.loads(log.splitlines()[0])["event"] == "account_created"


def test_user_create_refuses_duplicates_unknown_users_and_short_passwords(tmp_path: Path) -> None:
    base = _base(tmp_path)
    assert (
        runner.invoke(app, [*base, "user", "create", "alice"], input=f"{PW}\n{PW}\n").exit_code == 0
    )
    again = runner.invoke(app, [*base, "user", "create", "alice"], input=f"{PW}\n{PW}\n")
    assert again.exit_code == 1
    ghost = runner.invoke(app, [*base, "user", "create", "ghost"], input=f"{PW}\n{PW}\n")
    assert ghost.exit_code == 1
    short = runner.invoke(app, [*base, "user", "create", "jonas"], input="tiny\ntiny\n")
    assert short.exit_code == 1


def test_password_cannot_be_passed_as_an_argument(tmp_path: Path) -> None:
    result = runner.invoke(app, [*_base(tmp_path), "user", "create", "alice", PW])
    assert result.exit_code == 2
