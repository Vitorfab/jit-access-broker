# jit-access-broker

A small, well-tested Just-In-Time (JIT) privileged access broker for a local lab with simulated resources.
Users request elevated access with a justification, approvers decide, access expires automatically,
and every event goes to an append-only, tamper-evident audit log.

> **Status:** early development (scaffold). Not usable yet.
> **Lab project:** users are simulated and have no real authentication. Never use it to protect real systems.

## Why it exists
Standing privileged access is one of the most abused weaknesses in identity security.
This project demonstrates the JIT model end to end: least privilege, separation of duties,
time-bound access, approval workflows and auditability.

## Features (planned)
- Policy as code (YAML), deny-by-default, no self-approval, configurable approvals per role
- Time-bound grants with expiry enforced at check time
- Idempotent revocation
- JSON Lines audit log with hash chaining

## Install
Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

    uv sync
    uv run jit-broker version

## Tests
    uv run pytest

## Project structure
See [docs/architecture.md](docs/architecture.md).

## Tech stack
Python, Typer, Pydantic, SQLite, pytest, ruff, mypy.

## Security notes
See [SECURITY.md](SECURITY.md). A full threat model will be published in `docs/`.

## Roadmap
v0.1.0 core flow and CLI, v0.2.0 expiry/revocation and hash chain, v0.3.0 schema and local API,
v1.0.0 polish and release, v1.1.0 local GUI.

## License
MIT. See [LICENSE](LICENSE).

## Author
Vitor Fabelo