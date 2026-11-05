"""Append-only audit log in JSON Lines format (schema_version 1).

One JSON object per line. Free-text fields (justification, reasons) are never written here.
"""

import json
import os
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = 1

Detail = str | int | bool | None


class AuditError(Exception):
    """The audit log cannot be read or written safely."""


class AuditLog:
    def __init__(self, path: Path) -> None:
        self._path = path

    def record(
        self, event: str, actor: str, timestamp: datetime, details: dict[str, Detail]
    ) -> int:
        """Append one event and return its sequence number."""
        seq = self._next_seq()
        entry = {
            "schema_version": SCHEMA_VERSION,
            "seq": seq,
            "timestamp": timestamp.astimezone(UTC).isoformat(timespec="microseconds"),
            "event": event,
            "actor": actor,
            "details": details,
        }
        line = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        try:
            with self._path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(line + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            raise AuditError("cannot write to the audit log") from exc
        return seq

    def _next_seq(self) -> int:
        try:
            text = self._path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return 1
        except (OSError, UnicodeDecodeError) as exc:
            raise AuditError("cannot read the audit log") from exc
        lines = [line for line in text.splitlines() if line.strip()]
        if not lines:
            return 1
        try:
            seq = json.loads(lines[-1])["seq"]
        except (ValueError, KeyError, TypeError) as exc:
            raise AuditError("audit log is corrupted") from exc
        if not isinstance(seq, int) or isinstance(seq, bool):
            raise AuditError("audit log is corrupted")
        return seq + 1
