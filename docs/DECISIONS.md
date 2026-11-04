# Decision log

## D-001: Python + Typer + Pydantic + SQLite
Python 3.11+ (developed on 3.14). Typer for the CLI, Pydantic v2 + PyYAML `safe_load` for strict validation,
SQLite for state, pytest/ruff/mypy for quality. All free, no signup. Trade-off: more dependencies than stdlib-only.

## D-002: CLI first, local GUI later (v1.1.0)
The service layer never prints; it returns data models. CLI and a future GUI are thin front-ends.
The GUI binds to 127.0.0.1 only, because simulated users have no real authentication.

## D-003: Approvals configurable per role
`approvals_required` is set per role in the policy. Requesters can never approve their own request.

## D-004: No grant extension
More time requires a new request that goes through the policy again.

## D-005: uv + hatchling
uv manages the environment and `uv.lock`; hatchling is the build backend.