# jit-access-broker

A small, well-tested Just-In-Time (JIT) privileged access broker for a local lab with simulated resources.
Users request elevated access with a justification, approvers decide, access expires automatically,
and every event goes to an append-only, tamper-evident audit log.

Portuguese version: [README.pt-BR.md](README.pt-BR.md)

> **Status:** v1.4.0.
> **Lab project:** the CLI trusts `--as <user>` (local operator tool); the API and dashboard need a login. No SSO, MFA or TLS.
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
- Local REST API on 127.0.0.1 with real login: Argon2id passwords, sessions, CSRF protection, lockout
- Local dashboard with actions: request, approve, deny, revoke, sweep and check (server-side authorization, CSRF, confirmation before revoke, strict CSP)

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

It listens on `http://127.0.0.1:8765` only and needs a login. Create accounts first with `uv run jit-broker user create alice` (the password is asked without echo). Example:

    POST /auth/login with a JSON body {"username": ..., "password": ...} sets an HttpOnly session cookie

Endpoints: `GET /health`, `POST /requests`, `GET /requests`, `POST /requests/{id}/approve`,
`POST /requests/{id}/deny`, `GET /grants`, `POST /check`, `POST /grants/{id}/revoke`,
`POST /sweep`, `GET /audit/verify` (admin), `POST /auth/login`, `POST /auth/logout`, `GET /auth/me`. Writes need the `X-CSRF-Token` header.

### Dashboard

    uv run jit-broker serve

Create accounts with `uv run jit-broker user create <user>`, open `http://127.0.0.1:8765/` and sign in.
The page shows requests, grants with a live countdown and the audit-chain status, and lets each profile act: request access, approve or deny with a reason, and (admins) revoke with confirmation or sweep. The server authorizes every action;
uses an HttpOnly session cookie and talks to the same local API.

### Policy editor (admins, two-person approval)

Use a local copy so the repository file is not changed, then start the server with it:

    Copy-Item policies\example.yaml policies\local.yaml
    uv run jit-broker --policy policies\local.yaml serve

Sign in as an admin (`arthur` or `beatriz`), load the policy, edit the JSON and propose. The other
admin approves in the same panel. Every change keeps a numbered backup in `policies\backups\`.

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