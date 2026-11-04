"""Command-line interface. It only translates commands into service calls."""

import typer

from jit_broker import __version__

app = typer.Typer(help="Just-In-Time access broker (lab project).", no_args_is_help=True)


@app.callback()
def main() -> None:
    """Just-In-Time access broker (lab project)."""


@app.command()
def version() -> None:
    """Print the installed version."""
    typer.echo(__version__)
