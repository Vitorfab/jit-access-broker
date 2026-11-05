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
## D-006: Strict, deny-by-default policy
The policy is loaded with `yaml.safe_load` and validated by Pydantic with `extra="forbid"`.
Each role lists its `requesters` and `approvers`; anyone not listed is denied.
`approvals_required` cannot exceed the number of approvers, and listed people must have the
matching capability. Error messages never echo input values. Files over 1 MB are rejected.
Known limit: duplicate YAML keys are silently merged by the YAML parser (last one wins).
## D-007: SQLite state, atomic decisions, expiry checked at decision time
Requests and decisions live in SQLite; every statement uses bound parameters.
Each write flow runs in a `BEGIN IMMEDIATE` transaction, so two concurrent decisions cannot both
pass the checks. A pending request that is past its expiry is refused and marked `expired` when
someone tries to decide it (not only by a background job). Any eligible denial closes the request.
A user cannot request a role they are not listed for, and unknown roles give the same error as
forbidden roles. Limits: 5 pending requests per user.
Known limits: `--as` selects a simulated user and is not authentication; policy changes apply to
requests that are still pending.
## D-008: Grants start at final approval; audit is written inside the transaction
A grant starts at the moment of the final approval and lasts the requested duration; there are no
future-dated windows. `check` compares the current time with the grant window inside a transaction,
so no background job is needed for correctness. The audit log is JSON Lines with `schema_version`,
`seq`, `timestamp`, `event`, `actor` and `details`. Events are written before the database
transaction commits: if the log cannot be written, the change is rolled back (fail closed).
Free text (justification, reasons) is never written to the log.
Known limits: refused attempts (for example a self-approval) are not logged yet; the log is not
tamper-evident yet (hash chain planned for v0.2.0).
## D-009: Admin-only revocation and sweep; grant expiry has no event
Only users with the `admin` capability can revoke a grant or run the sweep. Revocation takes effect
at the next `check` because the check reads `revoked_at` inside a transaction. Revoking twice is
safe: the first call sets `revoked_at` and logs `grant_revoked`, later calls change and log nothing.
The sweep marks pending requests past their expiry as `expired` (logged as `request_expired`).
Grants that reach their end time are not rewritten: validity is always computed from the time window
when it is checked, so no background job is needed for correctness.