"""SQLite state store. This is the only module that talks to the database.

All values reach SQL through bound parameters, never through string formatting.
"""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from jit_broker.domain import (
    Account,
    DecisionKind,
    Grant,
    PolicyChange,
    RequestRecord,
    RequestStatus,
    Session,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    requester TEXT NOT NULL,
    role TEXT NOT NULL,
    duration_minutes INTEGER NOT NULL CHECK (duration_minutes > 0),
    justification TEXT NOT NULL,
    ticket TEXT,
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'expired')),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    decided_at TEXT
);
CREATE TABLE IF NOT EXISTS decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER NOT NULL REFERENCES requests (id),
    approver TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('approve', 'deny')),
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (request_id, approver)
);
CREATE TABLE IF NOT EXISTS grants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER NOT NULL UNIQUE REFERENCES requests (id),
    grantee TEXT NOT NULL,
    role TEXT NOT NULL,
    starts_at TEXT NOT NULL,
    ends_at TEXT NOT NULL,
    revoked_at TEXT,
    CHECK (ends_at > starts_at)
);
CREATE TABLE IF NOT EXISTS accounts (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    failed_count INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    csrf TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS policy_changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    proposer TEXT NOT NULL,
    summary TEXT NOT NULL,
    base_hash TEXT NOT NULL,
    new_hash TEXT NOT NULL,
    new_policy TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'applied', 'rejected', 'stale')),
    proposed_at TEXT NOT NULL,
    decided_by TEXT,
    decided_at TEXT
);
CREATE VIEW IF NOT EXISTS request_view AS
SELECT r.*,
    (SELECT COUNT(*) FROM decisions d
     WHERE d.request_id = r.id AND d.decision = 'approve') AS approvals
FROM requests r;
"""


def _iso(moment: datetime) -> str:
    """Fixed-width UTC ISO 8601, so text comparison matches time order."""
    return moment.astimezone(UTC).isoformat(timespec="microseconds")


class Store:
    def __init__(self, path: Path) -> None:
        self._conn = sqlite3.connect(str(path), isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """Run a block atomically. BEGIN IMMEDIATE takes the write lock up front."""
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        else:
            self._conn.execute("COMMIT")

    def insert_request(
        self,
        *,
        requester: str,
        role: str,
        duration_minutes: int,
        justification: str,
        ticket: str | None,
        created_at: datetime,
        expires_at: datetime,
    ) -> int:
        cursor = self._conn.execute(
            "INSERT INTO requests (requester, role, duration_minutes, justification, "
            "ticket, status, created_at, expires_at) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)",
            (
                requester,
                role,
                duration_minutes,
                justification,
                ticket,
                _iso(created_at),
                _iso(expires_at),
            ),
        )
        if cursor.lastrowid is None:
            raise RuntimeError("insert did not return a row id")
        return cursor.lastrowid

    def get_request(self, request_id: int) -> RequestRecord | None:
        row = self._conn.execute(
            "SELECT * FROM request_view WHERE id = ?", (request_id,)
        ).fetchone()
        return None if row is None else RequestRecord.model_validate(dict(row))

    def list_requests(self, status: RequestStatus | None = None) -> list[RequestRecord]:
        if status is None:
            rows = self._conn.execute("SELECT * FROM request_view ORDER BY id").fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM request_view WHERE status = ? ORDER BY id", (status.value,)
            ).fetchall()
        return [RequestRecord.model_validate(dict(row)) for row in rows]

    def count_pending(self, requester: str, now: datetime) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) FROM requests "
            "WHERE requester = ? AND status = 'pending' AND expires_at > ?",
            (requester, _iso(now)),
        ).fetchone()
        return int(row[0])

    def has_decision(self, request_id: int, approver: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM decisions WHERE request_id = ? AND approver = ?",
            (request_id, approver),
        ).fetchone()
        return row is not None

    def add_decision(
        self,
        request_id: int,
        approver: str,
        kind: DecisionKind,
        reason: str,
        created_at: datetime,
    ) -> None:
        self._conn.execute(
            "INSERT INTO decisions (request_id, approver, decision, reason, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (request_id, approver, kind.value, reason, _iso(created_at)),
        )

    def count_approvals(self, request_id: int) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) FROM decisions WHERE request_id = ? AND decision = 'approve'",
            (request_id,),
        ).fetchone()
        return int(row[0])

    def set_status(self, request_id: int, status: RequestStatus, decided_at: datetime) -> None:
        self._conn.execute(
            "UPDATE requests SET status = ?, decided_at = ? WHERE id = ?",
            (status.value, _iso(decided_at), request_id),
        )

    def insert_grant(
        self,
        *,
        request_id: int,
        grantee: str,
        role: str,
        starts_at: datetime,
        ends_at: datetime,
    ) -> int:
        cursor = self._conn.execute(
            "INSERT INTO grants (request_id, grantee, role, starts_at, ends_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (request_id, grantee, role, _iso(starts_at), _iso(ends_at)),
        )
        if cursor.lastrowid is None:
            raise RuntimeError("insert did not return a row id")
        return cursor.lastrowid

    def get_active_grant(self, grantee: str, role: str, now: datetime) -> Grant | None:
        """The grant that is valid at `now`: started, not ended, not revoked."""
        row = self._conn.execute(
            "SELECT * FROM grants WHERE grantee = ? AND role = ? "
            "AND starts_at <= ? AND ends_at > ? AND revoked_at IS NULL "
            "ORDER BY ends_at DESC LIMIT 1",
            (grantee, role, _iso(now), _iso(now)),
        ).fetchone()
        return None if row is None else Grant.model_validate(dict(row))

    def list_grants(self) -> list[Grant]:
        rows = self._conn.execute("SELECT * FROM grants ORDER BY id").fetchall()
        return [Grant.model_validate(dict(row)) for row in rows]

    def get_grant(self, grant_id: int) -> Grant | None:
        row = self._conn.execute("SELECT * FROM grants WHERE id = ?", (grant_id,)).fetchone()
        return None if row is None else Grant.model_validate(dict(row))

    def revoke_grant(self, grant_id: int, revoked_at: datetime) -> None:
        self._conn.execute(
            "UPDATE grants SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
            (_iso(revoked_at), grant_id),
        )

    def list_overdue_pending(self, now: datetime) -> list[RequestRecord]:
        rows = self._conn.execute(
            "SELECT * FROM request_view WHERE status = 'pending' AND expires_at <= ? ORDER BY id",
            (_iso(now),),
        ).fetchall()
        return [RequestRecord.model_validate(dict(row)) for row in rows]

    def create_account(self, username: str, password_hash: str, created_at: datetime) -> bool:
        """Insert an account. Returns False when it already exists."""
        cursor = self._conn.execute(
            "INSERT OR IGNORE INTO accounts (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, password_hash, _iso(created_at)),
        )
        return cursor.rowcount == 1

    def get_account(self, username: str) -> Account | None:
        row = self._conn.execute(
            "SELECT username, password_hash, failed_count, locked_until, created_at "
            "FROM accounts WHERE username = ?",
            (username,),
        ).fetchone()
        return None if row is None else Account.model_validate(dict(row))

    def set_login_failures(
        self, username: str, failed_count: int, locked_until: datetime | None
    ) -> None:
        self._conn.execute(
            "UPDATE accounts SET failed_count = ?, locked_until = ? WHERE username = ?",
            (failed_count, None if locked_until is None else _iso(locked_until), username),
        )

    def insert_session(
        self,
        *,
        token_hash: str,
        username: str,
        csrf: str,
        created_at: datetime,
        last_seen: datetime,
        expires_at: datetime,
    ) -> None:
        self._conn.execute(
            "INSERT INTO sessions (token_hash, username, csrf, created_at, last_seen, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (token_hash, username, csrf, _iso(created_at), _iso(last_seen), _iso(expires_at)),
        )

    def get_session(self, token_hash: str) -> Session | None:
        row = self._conn.execute(
            "SELECT username, csrf, created_at, last_seen, expires_at "
            "FROM sessions WHERE token_hash = ?",
            (token_hash,),
        ).fetchone()
        return None if row is None else Session.model_validate(dict(row))

    def touch_session(self, token_hash: str, last_seen: datetime) -> None:
        self._conn.execute(
            "UPDATE sessions SET last_seen = ? WHERE token_hash = ?",
            (_iso(last_seen), token_hash),
        )

    def delete_session(self, token_hash: str) -> bool:
        cursor = self._conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
        return cursor.rowcount == 1

    def delete_stale_sessions(self, now: datetime, idle_cutoff: datetime) -> None:
        self._conn.execute(
            "DELETE FROM sessions WHERE expires_at <= ? OR last_seen <= ?",
            (_iso(now), _iso(idle_cutoff)),
        )

    def insert_policy_change(
        self,
        *,
        proposer: str,
        summary: str,
        base_hash: str,
        new_hash: str,
        new_policy: str,
        proposed_at: datetime,
    ) -> int:
        cursor = self._conn.execute(
            "INSERT INTO policy_changes (proposer, summary, base_hash, new_hash, new_policy, "
            "status, proposed_at) VALUES (?, ?, ?, ?, ?, 'pending', ?)",
            (proposer, summary, base_hash, new_hash, new_policy, _iso(proposed_at)),
        )
        if cursor.lastrowid is None:
            raise RuntimeError("insert did not return a row id")
        return cursor.lastrowid

    def get_policy_change(self, change_id: int) -> PolicyChange | None:
        row = self._conn.execute(
            "SELECT id, proposer, summary, base_hash, new_hash, status, proposed_at, "
            "decided_by, decided_at FROM policy_changes WHERE id = ?",
            (change_id,),
        ).fetchone()
        return None if row is None else PolicyChange.model_validate(dict(row))

    def get_policy_change_body(self, change_id: int) -> str | None:
        row = self._conn.execute(
            "SELECT new_policy FROM policy_changes WHERE id = ?", (change_id,)
        ).fetchone()
        return None if row is None else str(row[0])

    def list_policy_changes(self) -> list[PolicyChange]:
        rows = self._conn.execute(
            "SELECT id, proposer, summary, base_hash, new_hash, status, proposed_at, "
            "decided_by, decided_at FROM policy_changes ORDER BY id DESC LIMIT 50"
        ).fetchall()
        return [PolicyChange.model_validate(dict(row)) for row in rows]

    def count_pending_policy_changes(self) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) FROM policy_changes WHERE status = 'pending'"
        ).fetchone()
        return int(row[0])

    def decide_policy_change(
        self, change_id: int, status: str, decided_by: str, decided_at: datetime
    ) -> None:
        self._conn.execute(
            "UPDATE policy_changes SET status = ?, decided_by = ?, decided_at = ? "
            "WHERE id = ? AND status = 'pending'",
            (status, decided_by, _iso(decided_at), change_id),
        )
