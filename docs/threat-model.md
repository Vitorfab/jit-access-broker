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
## Dashboard (v1.1.0)
| Threat | Control | Residual risk |
|---|---|---|
| XSS through stored values (ticket, ids, roles) | Rendering with `textContent` only, CSP `script-src 'self'` without inline script, tests that forbid dangerous sinks | A future change could add a sink; the tests are the guard |
| Token theft in the browser | Token kept in page memory, never in URL, storage or cookies; cleared on disconnect | Any script already running on the same origin could read it |
| Clickjacking | `frame-ancestors 'none'` and `X-Frame-Options: DENY` | None known |
| DNS rebinding | Host header allow-list (127.0.0.1, localhost) | None known |
| Cached sensitive data | `Cache-Control: no-store` | None known |
| Data visible to any simulated user | Read endpoints are not restricted by role | Known limit, to be reviewed in the v1.1.0 security review |
## Identity and sessions (v1.2.0)
| Threat | Control | Residual risk |
|---|---|---|
| Password guessing | Argon2id hashes, lockout after 5 failures for 15 minutes, generic error, dummy hash verification for unknown or locked accounts | An attacker can lock a victim out (DoS) |
| Session theft | Random 256-bit token, HttpOnly cookie, only the SHA-256 stored, idle (15 min) and absolute (8 h) limits, server-side logout | No TLS on localhost; any local process that reads the cookie can reuse it |
| CSRF | `SameSite=Strict`, `X-CSRF-Token` header compared in constant time, Origin must match Host, no CORS | None known |
| Account enumeration | One message for every login failure | Differences in the audit log are visible to operators only |
| Information exposure | Reads filtered by profile; `audit verify` admin only | Role lists and policy are not editable or visible in the GUI yet |
| Privilege escalation through accounts | Accounts only for users that exist in the policy; permissions still come from the policy | Whoever edits the policy file or the database controls everything |

## Production notes
This lab deliberately has no SSO, no MFA and no TLS. A real deployment should use an identity
provider (SSO) with MFA, HTTPS everywhere with the `Secure` cookie flag, per-IP rate limiting,
password reset and rotation, and centralized log shipping.
## Dashboard actions (v1.3.0)
| Threat | Control | Residual risk |
|---|---|---|
| Hidden buttons treated as security | The page only hides controls; the server re-checks every action | None known |
| Accidental or forged revoke | Confirmation box, CSRF header, Origin check, admin only | A script already running on the page could click through |
| Disclosure of policy through `/roles` | Only roles the user may request, public fields only | Role names are visible to users who can request them |
| Stored text shown back (ticket, ids) | `textContent` only, strict CSP, tests that forbid dangerous sinks | A future change could add a sink; the tests guard it |
| Approval by a distracted approver | Reason required, every decision logged, distinct approvers | Social engineering is out of scope |
## Policy editor (v1.4.0)
| Threat | Control | Residual risk |
|---|---|---|
| An admin gives themselves more privilege | Nobody may add new capabilities to themselves or add themselves as requester or approver of a role; checked for the proposer and again for the approver | Weakening a role where the person already has access (for example fewer approvals) is allowed with approval |
| One admin changes the policy alone | Two-person rule: a different admin must approve; the policy must keep at least two admins | Two admins who collude or are both compromised can change anything; there is no MFA |
| Invalid or hostile policy | Same strict model as the file, size limit, pending limit, staged file re-validated, atomic replace | None known |
| Concurrent or outdated proposals | Each proposal stores the hash of the policy it was based on; if the policy changed it becomes stale | None known |
| Loss of the previous policy | A numbered backup is written before every change | Backups sit next to the policy file |
| Policy content in logs | Only hashes, change ids and fixed reasons are logged; validation key names are not logged | Hashes reveal that a change happened, not what |
| Policy file broken or removed outside the editor | The API reloads on change and answers 503 (fail closed) when it cannot load it | The CLI loads the file on every call and reports the error |
| Removed users | Sessions and checks use the current policy, so a removed user loses access at once | Their account row stays in the database |