# jit-access-broker

A small, well-tested Just-In-Time (JIT) privileged access broker for a local lab with simulated resources.
Users request elevated access with a justification, approvers decide, access expires automatically,
and every event goes to an append-only, tamper-evident audit log.

Portuguese version: [README.pt-BR.md](README.pt-BR.md)

> **Status:** v1.1.0.
> **Lab project:** users are simulated (`--as <user>`) and there is no real authentication.
> Never use it to protect real systems.

## Why it exists
Standing privileged access is one of the most abused weaknesses in identity security.
JIT fixes this: a user gets elevated access only when needed, only for the time needed, only after a
justified request is approved, and every step is logged.
This project demonstrates the model end to end: least privilege, separation of duties,
time-bound access, approval workflows and auditability.

## Features
- Policy as code (YAML), strictly validated, deny-by-default
- Per-role approver lists and number of approvals (for example two-person approval for high-risk roles)
- Separation of duties: no self-approval, no repeated approver
- Time-bound grants; expiry is enforced at check time, not by a background job
- Admin-only, idempotent revocation and expiry sweep
- Append-only JSON Lines audit log with a SHA-256 hash chain and `audit verify`
  (free text is never logged; refused attempts are logged as `action_refused`)
- CLI with `--json` output
- Local REST API on 127.0.0.1 with a random bearer token
- Read-only local dashboard (strict CSP, no inline scripts, token kept in memory only)

## Install
Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

    uv sync
    uv run jit-broker --help

## Usage

    uv run jit-broker request --as alice --role db-readonly --minutes 30 --justification "Reading a simulated report"
    uv run jit-broker approve 1 --as carol --reason "Approved"
    uv run jit-broker check --as alice --role db-readonly
    uv run jit-broker grants
    uv run jit-broker revoke 1 --as arthur
    uv run jit-broker sweep --as arthur
    uv run jit-broker audit verify

`check` exits with code 0 when access is allowed and 1 when it is denied.
State is stored in `jit-broker.db` and the audit log in `jit-broker-audit.jsonl` (both git-ignored).

### Scripted demo (PowerShell)

    .\scripts\demo.ps1

### Local API

    uv run jit-broker serve

It listens on `http://127.0.0.1:8765` only and prints a random token. Example:

    curl.exe -H "Authorization: Bearer <token>" -H "X-Acting-User: alice" http://127.0.0.1:8765/requests

Endpoints: `GET /health`, `POST /requests`, `GET /requests`, `POST /requests/{id}/approve`,
`POST /requests/{id}/deny`, `GET /grants`, `POST /check`, `POST /grants/{id}/revoke`,
`POST /sweep`, `GET /audit/verify`. `X-Acting-User` selects a simulated user; it is not authentication.

### Dashboard (read-only)

    uv run jit-broker serve

Open `http://127.0.0.1:8765/`, paste the token printed in the terminal and type a simulated user id.
The page shows requests, grants with a live countdown and the audit-chain status. It is read-only,
keeps the token in memory only and talks to the same local API.

## Project structure
See [docs/architecture.md](docs/architecture.md) (with Mermaid diagrams).
Audit log format: [docs/audit-log-schema.md](docs/audit-log-schema.md).

## Tech stack
Python, Typer, Pydantic, SQLite, FastAPI, uvicorn, pytest, ruff, mypy, bandit, pip-audit, CodeQL.

## Tests

    uv run pytest

## Security notes
See [docs/threat-model.md](docs/threat-model.md), [docs/security-review-v0.2.0.md](docs/security-review-v0.2.0.md)
and [SECURITY.md](SECURITY.md). Known limits are documented there.

## Roadmap
Next: write actions in the dashboard (not planned yet).

## License
MIT. See [LICENSE](LICENSE).

## Author
Vitor Fabelo