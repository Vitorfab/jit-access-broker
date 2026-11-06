# Security review (v1.2.0)

Scope: the whole application as of v1.1.0 plus the new identity layer. Method: manual review of
every flow, the automated checks (ruff, mypy, bandit, pip-audit, CodeQL) and new tests.

## Fixed in v1.2.0
| # | Finding | Fix |
|---|---|---|
| F1 | The API trusted any `X-Acting-User` value, without even checking the policy | Removed. Login with a password and a server-side session |
| F2 | One shared bearer token printed in the terminal | Removed. Per-user sessions, HttpOnly cookie, only the token hash is stored |
| F3 | Read endpoints showed every request and grant to everyone | Filtered: own items, items of roles the user approves, everything for admins |
| F4 | `audit verify` was open to any caller | Admin only |
| F5 | Duplicate YAML keys were merged silently (last one wins) | The policy is rejected |
| F6 | No protection against password guessing | Lockout for 15 minutes after 5 failures, generic error, similar timing |
| F7 | State-changing API calls had no CSRF defence | `SameSite=Strict`, `X-CSRF-Token` header, Origin check |

## Known limits (open)
| # | Limit | Note |
|---|---|---|
| O1 | No TLS: traffic is plain HTTP on 127.0.0.1 | Production must use HTTPS and the `Secure` cookie flag |
| O2 | No SSO and no MFA | Production should use an identity provider with MFA |
| O3 | The CLI trusts `--as` | It is a local operator tool; whoever runs it can already read the database file |
| O4 | Anyone able to lock an account by failing 5 logins (lockout DoS) | Accepted for a lab; production needs per-IP throttling and alerts |
| O5 | No password change or reset command | Accounts can only be created |
| O6 | Audit writes re-read the whole file | Slows down as the log grows; noise can inflate it |
| O7 | State and log can diverge on a crash between log write and commit | Documented in D-008 |
| O8 | Tail truncation and whole-file rewrite of the audit log are not detected | Keep an external copy of the head hash; signing key is a future idea |
| O9 | Hashes and sessions are readable by anyone with file access to the database | Protect it with OS permissions |
| O10 | Idle timeout counts user actions only | Automatic page refreshes do not renew the session |