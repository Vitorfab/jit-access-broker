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
## D-010: Hash-chained audit log
Each entry stores `prev_hash` and `hash = SHA-256(canonical JSON of the entry without hash)`.
The first entry uses 64 zeros as `prev_hash`. `audit verify` walks the file and reports the first
line that is modified, missing, reordered or has a broken link. Writers are serialized by the
database write lock (`BEGIN IMMEDIATE`), so two processes cannot extend the chain at once.
Known limits (see docs/security-review-v0.2.0.md): tail truncation is not detected without an
external copy of the head hash, and there is no signing key.
## D-011: Refused attempts are logged
Refusals (self-service errors, wrong approver, non-admin admin actions, bad input) are written as
`action_refused` after the database transaction rolled back, inside a new transaction so the hash
chain keeps a single writer. Only well-formed identifiers are copied into the log; free text never.
A failure to write a refusal never hides the refusal itself. An expired request is logged as
`request_expired`, not as a refusal. Known limit: anyone who can run the CLI can add noise.

## D-012: Local REST API (FastAPI + uvicorn)
The API wraps the same Broker, so no rule is duplicated. It listens on 127.0.0.1 only (the host is
not configurable), needs a random bearer token generated at each `serve`, rejects foreign Host
headers, has no CORS and no interactive docs. `X-Acting-User` is a lab simplification and not
authentication. SQLite connections are opened per call in the same thread.
## D-013: v1.0.0 scope and framework mapping
v1.0.0 is the end of the CLI/API line: no new runtime behavior, only the threat model, the
architecture diagrams and the Portuguese README. The framework mapping names families and tactics
only, without control or technique identifiers, so nothing unverified is published. The local GUI
is planned for v1.1.0 and will reuse the same Broker service.
## D-014: Read-only dashboard served by the local API
The dashboard is static HTML, CSS and JavaScript served by the same 127.0.0.1-only API. The files
contain no data; everything is fetched from the token-protected endpoints. The token lives only in
page memory (never in the URL, storage or cookies). The JavaScript renders with `textContent` only,
and tests forbid dangerous sinks and any storage API. Every response carries a strict CSP (no inline
script, no framing), `nosniff`, `no-store` and `no-referrer`. There are no write actions in the page.
## D-015: Local accounts with Argon2id, server-side sessions
Accounts live in SQLite (separate from the policy) and are created only by the local operator
(`user create`, password prompted without echo). Passwords use Argon2id (argon2-cffi defaults).
A session token is random and held in an HttpOnly, SameSite=Strict cookie; only its SHA-256 is
stored. Limits: 15 minutes idle (user actions only) and 8 hours absolute. Login failures lock the
account for 15 minutes after 5 attempts. No SSO and no MFA, on purpose, to keep the lab small;
the docs say production needs both.

## D-016: Authorization stays in the server; X-Acting-User removed
The API and dashboard use the session user only. Reads are filtered by profile in `Broker`.
State-changing calls need the CSRF header and a same-origin Origin. The CLI keeps `--as` as a
local operator tool. Duplicate YAML keys are now rejected by the policy loader.