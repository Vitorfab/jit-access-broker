"""SQLite state store. This is the only module that talks to the database.

All values reach SQL through bound parameters, never through string formatting.
"""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from jit_broker.domain import DecisionKind, RequestRecord, RequestStatus

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
