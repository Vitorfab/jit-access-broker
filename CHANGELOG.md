# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: [SemVer](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/Vitorfab/jit-access-broker/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Vitorfab/jit-access-broker/releases/tag/v0.1.0