# Security review (v0.2.0)

Scope: policy loading, request/approval flow, grants, revocation, audit log. Lab project:
simulated users, no real authentication. Done by the author with automated checks
(ruff, mypy, bandit, pip-audit in CI, CodeQL) and manual review of the flows below.

## Controls checked
| Area | Control | Evidence |
|---|---|---|
| Input | Strict policy schema, `yaml.safe_load`, size limit, no value echo in errors | `tests/test_policy.py` |
| Input | Justification, reason, ticket and role names validated | `tests/test_service.py` |
| Separation of duties | No self-approval, no repeated approver, per-role approver list | `tests/test_service.py` |
| Least privilege | Deny-by-default; grants bound to user and role; admin-only revoke/sweep | `tests/test_grants.py`, `tests/test_revoke.py` |
| Time | Expiry decided at check time inside a transaction; revocation immediate | `tests/test_grants.py` |
| Concurrency | `BEGIN IMMEDIATE` around every write flow | `src/jit_broker/store.py` |
| SQL | Bound parameters only | `src/jit_broker/store.py` |
| Audit | Append-only, hash-chained, `audit verify`, no free text logged | `tests/test_audit_chain.py` |
| Fail closed | Audit is written inside the transaction; a write failure rolls the change back | `tests/test_audit.py` |

## Findings and known limits
1. **Tail truncation is not detected.** Removing the newest entries leaves a valid shorter chain.
   Mitigation: keep a copy of the head hash printed by `audit verify` somewhere else.
2. **No signing key.** Someone who can rewrite the whole file can rebuild a consistent chain.
   The chain is tamper-evident against partial edits, not tamper-proof. An HMAC with a secret key
   would raise the bar; it is out of scope for this lab.
3. **Refused attempts are not logged** (for example a rejected self-approval). Candidate for v0.3.0.
4. **State and log can diverge on a crash** between the log write and the database commit.
   The log may then hold an entry for a change that was rolled back.
5. **`--as` is not authentication.** Anyone who can run the CLI can act as any simulated user.
6. **Files are not encrypted or access-controlled** beyond OS permissions.
7. **Duplicate YAML keys** are merged silently by the parser (last wins).

Mapping to NIST SP 800-53 families (access control, audit) and MITRE ATT&CK will be finalized
and verified against the official sources in the v1.0.0 threat model.