# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: [SemVer](https://semver.org/).

## [Unreleased]

## [1.4.0] - 2026-11-07

### Added
- Policy editor in the dashboard (admins): propose a new policy, a different admin approves it, numbered backup and atomic apply.
- Rules: at least two admins, nobody can grant themselves new privileges, stale proposals are refused.
- Audit events for policy changes (hashes only).
- Second demo admin (beatriz) in the example policy.

### Changed
- The API reloads the policy when the file changes and answers 503 when it cannot load it.

## [1.3.0] - 2026-11-07

### Added
- Dashboard actions: request access, approve, deny (with reason), revoke (with confirmation), sweep and check access.
- GET /roles: roles the signed-in user may request.
- Threat model section for dashboard actions.

## [1.2.0] - 2026-11-06

### Added
- Real login: local accounts with Argon2id passwords, server-side sessions in an HttpOnly SameSite=Strict cookie, CSRF protection, lockout after repeated failures and login events in the audit log.
- user create command (password prompted without echo).
- Reads filtered by profile; audit verify is admin only.
- Security review for v1.2.0.

### Changed
- The API and dashboard no longer accept X-Acting-User or the shared bearer token.
- The policy loader rejects duplicate YAML keys.

## [1.1.0] - 2026-11-05

### Added
- Read-only local dashboard served by the API: requests, grants with countdown, audit chain status.
- Strict security headers (CSP, frame denial, nosniff, no-store) on every API response.
- Dashboard section in the threat model.

## [1.0.0] - 2026-11-05

### Added
- Threat model (STRIDE-lite) in `docs/threat-model.md`.
- Architecture document with Mermaid diagrams.
- Portuguese README (`README.pt-BR.md`).
- Final README polish.

## [0.3.0] - 2026-11-05

### Added
- Refused attempts are written to the audit log as `action_refused` (malformed ids are not logged verbatim).
- Local REST API (`serve` command): 127.0.0.1 only, random bearer token, Host header check, no CORS, no docs endpoint.
- `docs/audit-log-schema.md`: audit log schema version 1.
- `scripts/demo.ps1`: scripted demo scenario.

## [0.2.0] - 2026-11-05

### Added
- `revoke` command: admin-only, immediate, idempotent grant revocation (logged as `grant_revoked`).
- `sweep` command: admin-only, marks overdue pending requests as expired.
- Integration tests for the full lifecycle through the CLI.
- Tamper-evident audit log: every entry carries `prev_hash` and `hash` (SHA-256 chain).
- `audit verify` command: detects modified, deleted or reordered entries (exit 1 on failure).
- Security review document for v0.2.0.
- Note: audit logs written by v0.1.0 have no hashes and are refused; delete them in the lab.

## [0.1.0] - 2026-11-05

### Added
- Repository scaffold, CI, security tooling and project documentation.
- Strict YAML policy models and loader (deny-by-default, no unknown fields).
- `validate-policy` CLI command and an example policy with fictional users and roles.
- SQLite store and request/approve/deny flow with separation of duties
  (no self-approval, distinct approvers, approver lists per role).
- CLI commands `request`, `approve`, `deny` and `list` (with `--json`).
- Pending requests expire after the policy TTL; limit of pending requests per user.
- Time-bound grants created by the final approval; expiry is enforced at check time.
- `check` command (exit code 0 = allowed, 1 = denied) and `grants` command.
- Append-only JSON Lines audit log (`schema_version` 1) for requests, decisions, grants and checks.

[Unreleased]: https://github.com/Vitorfab/jit-access-broker/compare/v1.4.0...HEAD
[1.4.0]: https://github.com/Vitorfab/jit-access-broker/releases/tag/v1.4.0
[1.3.0]: https://github.com/Vitorfab/jit-access-broker/releases/tag/v1.3.0
[1.2.0]: https://github.com/Vitorfab/jit-access-broker/releases/tag/v1.2.0
[1.1.0]: https://github.com/Vitorfab/jit-access-broker/releases/tag/v1.1.0
[1.0.0]: https://github.com/Vitorfab/jit-access-broker/releases/tag/v1.0.0
[0.3.0]: https://github.com/Vitorfab/jit-access-broker/releases/tag/v0.3.0
[0.2.0]: https://github.com/Vitorfab/jit-access-broker/releases/tag/v0.2.0
[0.1.0]: https://github.com/Vitorfab/jit-access-broker/releases/tag/v0.1.0