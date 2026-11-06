# Audit log schema (version 1)

File: JSON Lines, UTF-8, one JSON object per line, append-only. Default name:
`<database name>-audit.jsonl`, next to the database (override with `--audit`).
Schema version 1 is final: new event types or detail keys may be added, existing ones will not
change meaning.

## Envelope (every line)
| Field | Type | Meaning |
|---|---|---|
| `schema_version` | integer | Always `1`. |
| `seq` | integer | 1, 2, 3, ... without gaps. |
| `timestamp` | string | UTC, ISO 8601 with microseconds. |
| `event` | string | Event type (table below). |
| `actor` | string | Simulated user id, or `system`. `invalid` when the supplied id was malformed. |
| `details` | object | Event-specific, flat, values are strings, integers, booleans or null. |
| `prev_hash` | string | `hash` of the previous line; 64 zeros for the first line. |
| `hash` | string | SHA-256 (hex) of the canonical JSON of the line without `hash`. |

Canonical JSON: keys sorted, separators `,` and `:`, ASCII only.

## Events
| Event | Actor | Details |
|---|---|---|
| `request_created` | requester | `request_id`, `role`, `duration_minutes`, `ticket` |
| `approved` | approver | `request_id`, `role`, `approvals`, `required` |
| `denied` | approver | `request_id`, `role`, `approvals`, `required` |
| `grant_created` | `system` | `request_id`, `grant_id`, `grantee`, `role`, `starts_at`, `ends_at` |
| `access_check` | user | `role`, `allowed`, `grant_id` |
| `grant_revoked` | admin | `grant_id`, `grantee`, `role`, `was_active` |
| `request_expired` | `system` | `request_id` |
| `action_refused` | user | `action`, `reason`, `target_id`, `role` |

`action_refused.action` is one of `request`, `approve`, `deny`, `check`, `revoke`, `sweep`.
`target_id` is the request id (approve/deny) or grant id (revoke), otherwise null. `role` is null
when the supplied value was not a well-formed identifier.

## What is never logged
Justifications and decision reasons (free text), the API token, and malformed user or role
values exactly as typed.

## Verification
`jit-broker audit verify` (or `GET /audit/verify`) walks the file and reports the first line that is
not valid JSON, has no hash, breaks the sequence, breaks the chain or was modified. It prints the
head hash on success.

## Limits
- Removing the newest lines is not detected unless you keep a copy of an earlier head hash.
- No signing key: someone who can rewrite the whole file can rebuild a consistent chain.
- Refusals can be produced by anyone who can run the CLI, so the log can grow from noise.
- Logs written by v0.1.0 have no hashes and are refused.
## Events added in v1.2.0
| Event | Actor | Details |
|---|---|---|
| `account_created` | `system` | `username` |
| `login_succeeded` | user | none |
| `login_failed` | user, or `invalid` when the id was malformed | `known_account`, `locked` |
| `account_locked` | user | `minutes` |
| `logout` | user | none |

Passwords, session tokens and CSRF tokens are never logged.