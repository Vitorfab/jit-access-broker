"""Command-line interface. It only translates commands into service calls."""

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated

import typer

from jit_broker import __version__
from jit_broker.audit import AuditError, AuditLog
from jit_broker.domain import Grant, RequestRecord, RequestStatus
from jit_broker.policy import PolicyError, load_policy
from jit_broker.service import Broker, BrokerError
from jit_broker.store import Store

DEFAULT_POLICY = Path("policies/example.yaml")
DEFAULT_DB = Path("jit-broker.db")

app = typer.Typer(help="Just-In-Time access broker (lab project).", no_args_is_help=True)


@dataclass(frozen=True)
class Settings:
    policy: Path
    db: Path
    audit: Path


@app.callback()
def main(
    ctx: typer.Context,
    policy: Annotated[
        Path, typer.Option("--policy", envvar="JIT_BROKER_POLICY", help="Policy YAML file.")
    ] = DEFAULT_POLICY,
    db: Annotated[
        Path, typer.Option("--db", envvar="JIT_BROKER_DB", help="SQLite state file.")
    ] = DEFAULT_DB,
    audit: Annotated[
        Path | None,
        typer.Option(
            "--audit",
            envvar="JIT_BROKER_AUDIT",
            help="Audit log (JSON Lines). Default: next to the database file.",
        ),
    ] = None,
) -> None:
    """Just-In-Time access broker (lab project).

    Lab only: --as selects a simulated user. It is NOT real authentication.
    """
    audit_path = audit if audit is not None else db.with_name(f"{db.stem}-audit.jsonl")
    ctx.obj = Settings(policy=policy, db=db, audit=audit_path)


@contextmanager
def _handled() -> Iterator[None]:
    try:
        yield
    except (BrokerError, PolicyError, AuditError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc


@contextmanager
def _open_broker(ctx: typer.Context) -> Iterator[Broker]:
    settings = ctx.obj
    if not isinstance(settings, Settings):
        raise RuntimeError("settings were not initialised")
    policy = load_policy(settings.policy)
    store = Store(settings.db)
    try:
        yield Broker(policy, store, AuditLog(settings.audit))
    finally:
        store.close()


def _show(record: RequestRecord, as_json: bool) -> None:
    if as_json:
        typer.echo(record.model_dump_json())
        return
    typer.echo(
        f"#{record.id} [{record.status.value}] {record.requester} -> {record.role} "
        f"for {record.duration_minutes} min (approvals: {record.approvals})"
    )


def _show_grant(grant: Grant, as_json: bool) -> None:
    if as_json:
        typer.echo(grant.model_dump_json())
        return
    typer.echo(
        f"grant #{grant.id} (request #{grant.request_id}) {grant.grantee} -> {grant.role} "
        f"from {grant.starts_at.isoformat()} until {grant.ends_at.isoformat()}"
    )


UserOpt = Annotated[str, typer.Option("--as", help="Simulated acting user (not real auth).")]
JsonOpt = Annotated[bool, typer.Option("--json", help="Machine-readable output.")]


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


@app.command()
def request(
    ctx: typer.Context,
    user: UserOpt,
    role: Annotated[str, typer.Option(help="Role to request.")],
    minutes: Annotated[int, typer.Option(help="Duration in minutes.")],
    justification: Annotated[str, typer.Option(help="Why the access is needed.")],
    ticket: Annotated[str | None, typer.Option(help="Optional ticket id.")] = None,
    as_json: JsonOpt = False,
) -> None:
    """Request time-bound access to a role."""
    with _handled(), _open_broker(ctx) as broker:
        _show(broker.request_access(user, role, minutes, justification, ticket), as_json)


@app.command()
def approve(
    ctx: typer.Context,
    request_id: Annotated[int, typer.Argument(min=1, help="Request id.")],
    user: UserOpt,
    reason: Annotated[str, typer.Option(help="Reason for the decision.")],
    as_json: JsonOpt = False,
) -> None:
    """Approve a pending request."""
    with _handled(), _open_broker(ctx) as broker:
        _show(broker.approve(request_id, user, reason), as_json)


@app.command()
def deny(
    ctx: typer.Context,
    request_id: Annotated[int, typer.Argument(min=1, help="Request id.")],
    user: UserOpt,
    reason: Annotated[str, typer.Option(help="Reason for the decision.")],
    as_json: JsonOpt = False,
) -> None:
    """Deny a pending request."""
    with _handled(), _open_broker(ctx) as broker:
        _show(broker.deny(request_id, user, reason), as_json)


@app.command("list")
def list_requests(
    ctx: typer.Context,
    status: Annotated[
        str | None, typer.Option(help="pending, approved, denied or expired.")
    ] = None,
    as_json: JsonOpt = False,
) -> None:
    """List requests, optionally filtered by status."""
    try:
        wanted = RequestStatus(status) if status else None
    except ValueError as exc:
        typer.echo("error: invalid status", err=True)
        raise typer.Exit(code=1) from exc
    with _handled(), _open_broker(ctx) as broker:
        for record in broker.list_requests(wanted):
            _show(record, as_json)


@app.command()
def check(
    ctx: typer.Context,
    user: UserOpt,
    role: Annotated[str, typer.Option(help="Role to check.")],
    as_json: JsonOpt = False,
) -> None:
    """Check whether the user has access to the role right now (exit 0 = allowed, 1 = denied)."""
    with _handled(), _open_broker(ctx) as broker:
        result = broker.check_access(user, role)
    if as_json:
        typer.echo(result.model_dump_json())
    elif result.allowed and result.ends_at is not None:
        typer.echo(f"ALLOWED: {user} -> {role} until {result.ends_at.isoformat()}")
    else:
        typer.echo(f"DENIED: {user} -> {role}")
    if not result.allowed:
        raise typer.Exit(code=1)


@app.command("grants")
def list_grants(ctx: typer.Context, as_json: JsonOpt = False) -> None:
    """List all grants."""
    with _handled(), _open_broker(ctx) as broker:
        for grant in broker.list_grants():
            _show_grant(grant, as_json)
