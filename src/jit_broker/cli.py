"""Command-line interface. It only translates commands into service calls."""

from pathlib import Path
from typing import Annotated

import typer

from jit_broker import __version__
from jit_broker.policy import PolicyError, load_policy

app = typer.Typer(help="Just-In-Time access broker (lab project).", no_args_is_help=True)


@app.callback()
def main() -> None:
    """Just-In-Time access broker (lab project)."""


@app.command()
def version() -> None:
    """Print the installed version."""
    typer.echo(__version__)


@app.command("validate-policy")
def validate_policy(
    path: Annotated[Path, typer.Argument(help="Path to the policy YAML file.")],
) -> None:
    """Validate a policy file and print a short summary."""
    try:
        policy = load_policy(path)
    except PolicyError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Policy OK: {len(policy.users)} users, {len(policy.roles)} roles.")
