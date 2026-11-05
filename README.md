# jit-access-broker

A small, well-tested Just-In-Time (JIT) privileged access broker for a local lab with simulated resources.
Users request elevated access with a justification, approvers decide, access expires automatically,
and every event goes to an append-only audit log.

> **Status:** v0.1.0, early development.
> **Lab project:** users are simulated (`--as <user>`) and there is no real authentication.
> Never use it to protect real systems.

## Why it exists
Standing privileged access is one of the most abused weaknesses in identity security.
This project demonstrates the JIT model end to end: least privilege, separation of duties,
time-bound access, approval workflows and auditability.

## Features
- Policy as code (YAML), strictly validated, deny-by-default
- Per-role approver lists and number of approvals (for example two-person approval for high-risk roles)
- Separation of duties: no self-approval, no repeated approver
- Time-bound grants; expiry is enforced at check time, not by a background job
- Pending requests expire; limit of pending requests per user
- Append-only JSON Lines audit log (free text is never logged)
- CLI with `--json` output

## Install
Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

    uv sync
    uv run jit-broker --help

## Usage

    uv run jit-broker request --as alice --role db-readonly --minutes 30 --justification "Reading a simulated report"
    uv run jit-broker approve 1 --as carol --reason "Approved"
    uv run jit-broker check --as alice --role db-readonly
    uv run jit-broker grants
    uv run jit-broker list --status approved

`check` exits with code 0 when access is allowed and 1 when it is denied.
State is stored in `jit-broker.db` and the audit log in `jit-broker-audit.jsonl` (both git-ignored).

## Project structure
See [docs/architecture.md](docs/architecture.md).

## Tech stack
Python, Typer, Pydantic, SQLite, pytest, ruff, mypy, bandit, pip-audit.

## Tests

    uv run pytest

## Security notes
See [SECURITY.md](SECURITY.md). A full threat model will be published in `docs/`.

## Roadmap
v0.2.0 revocation, expiry sweep and tamper-evident log; v0.3.0 log schema doc and local API;
v1.0.0 polish and release; v1.1.0 local GUI.

## License
MIT. See [LICENSE](LICENSE).

## Author
Vitor Fabelo