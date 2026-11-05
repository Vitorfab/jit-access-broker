# Threat model (STRIDE-lite)

Scope: the broker (CLI, local API, policy, SQLite state, audit log) running in a local lab with
simulated users. **Out of scope:** real authentication (`--as` and `X-Acting-User` only select a
simulated user), multi-user hosts with hostile local users, network exposure, protecting real systems.

## Assets
Policy file, SQLite state (requests, decisions, grants), audit log, API token.

## Threats and controls
| # | STRIDE | Threat | Controls | Residual risk |
|---|---|---|---|---|
| 1 | Elevation | Self-approval | The requester can never approve; checked in the service and tested | None known |
| 2 | Elevation | Approver collusion | Approver lists per role; N distinct approvers (`approvals_required`); every decision logged | Colluding people are only detectable from the log |
| 3 | Elevation | Escalation by extending a grant | No extension exists; a new request goes through the policy again | None known |
| 4 | Spoofing/Replay | Replaying an old approval | A decision is bound to a request id and is only valid while the request is `pending`; one decision per approver | None known |
| 5 | Tampering | Editing or deleting audit entries | SHA-256 hash chain, `audit verify`, API `/audit/verify` | Tail truncation and whole-file rewrite are not detected without an external copy of the head hash or a signing key |
| 6 | Tampering | TOCTOU around expiry | Validity is computed from the time window inside a transaction; `BEGIN IMMEDIATE` serializes writers | None known |
| 7 | Tampering | Clock manipulation | UTC everywhere; the clock is injectable for tests | Not mitigated: a changed system clock changes the window (planned improvement: reject a clock earlier than the last log entry) |
| 8 | Denial of service | Request flooding | Limit of 5 pending requests per user; pending requests expire | A refusal flood can still grow the log |
| 9 | Tampering | Weak input validation, injection | Strict Pydantic models, `yaml.safe_load`, size limits, validated text, bound SQL parameters | None known |
| 10 | Info disclosure | Secrets or free text in logs | Free text is never logged; malformed ids are logged as `invalid`; error messages never echo values | Token is printed once in the terminal by design |
| 11 | Info disclosure | Role enumeration | Same error for unknown and forbidden roles | Timing differences are not analyzed |
| 12 | Spoofing | Local API abuse | 127.0.0.1 only, random bearer token per run (constant-time compare), Host header check, no CORS, no docs endpoint | Any local process that learns the token can use it |
| 13 | Repudiation | Denying an action | Every request, decision, grant, revoke, check and refusal is logged with actor and time | The actor is a simulated identity, so it is not a proof of who typed the command |

## Framework mapping (family level)
- **NIST SP 800-53:** the Access Control family (least privilege, separation of duties) and the
  Audit and Accountability family (audit records, protection of audit information). Specific control
  identifiers are intentionally not listed here; verify them on the official NIST site before citing.
- **Zero Trust:** deny by default, time-bound access, explicit approval, continuous logging.
- **MITRE ATT&CK:** relevant tactics are Persistence and Privilege Escalation (misuse of valid
  accounts) and Defense Evasion (log tampering). Technique identifiers are intentionally not listed;
  verify them on the official MITRE site before citing.
- **OWASP:** input validation, safe error handling, no secrets in logs.

## Assumptions
- The operator protects the machine, the policy file and the database with OS permissions.
- The head hash printed by `audit verify` can be stored somewhere else to detect tail truncation.

## Improvement ideas
HMAC-signed log entries with a secret key, external anchoring of the head hash, rejecting a clock
earlier than the last log entry, real authentication and SSO.