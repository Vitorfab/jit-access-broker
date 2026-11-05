# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: [SemVer](https://semver.org/).

## [Unreleased]

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