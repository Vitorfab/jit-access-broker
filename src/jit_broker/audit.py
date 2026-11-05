"""Append-only, tamper-evident audit log in JSON Lines format (schema_version 1).

One JSON object per line. Every entry carries `prev_hash` (the hash of the previous entry,
or GENESIS_HASH for the first) and `hash` (SHA-256 of the entry without its own `hash`).
Changing, deleting or reordering an entry breaks the chain and `verify_log` reports it.
Free-text fields (justification, reasons) are never written here.
"""

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
GENESIS_HASH = "0" * 64

Detail = str | int | bool | None


class AuditError(Exception):
    """The audit log cannot be read, written or verified safely."""


@dataclass(frozen=True)
class VerifyResult:
    entries: int
    head_hash: str


def _digest(entry: dict[str, Any]) -> str:
    canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: Path) -> None:
        self._path = path

    def record(
        self, event: str, actor: str, timestamp: datetime, details: dict[str, Detail]
    ) -> int:
        """Append one chained event and return its sequence number."""
        last_seq, prev_hash = self._last_state()
        seq = last_seq + 1
        entry: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "seq": seq,
            "timestamp": timestamp.astimezone(UTC).isoformat(timespec="microseconds"),
            "event": event,
            "actor": actor,
            "details": details,
            "prev_hash": prev_hash,
        }
        entry["hash"] = _digest(entry)
        line = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        try:
            with self._path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(line + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            raise AuditError("cannot write to the audit log") from exc
        return seq

    def _last_state(self) -> tuple[int, str]:
        try:
            text = self._path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return 0, GENESIS_HASH
        except (OSError, UnicodeDecodeError) as exc:
            raise AuditError("cannot read the audit log") from exc
        lines = [line for line in text.splitlines() if line.strip()]
        if not lines:
            return 0, GENESIS_HASH
        try:
            last = json.loads(lines[-1])
            seq = last["seq"]
            entry_hash = last["hash"]
        except (ValueError, KeyError, TypeError) as exc:
            raise AuditError("audit log is corrupted") from exc
        if not isinstance(seq, int) or isinstance(seq, bool) or not isinstance(entry_hash, str):
            raise AuditError("audit log is corrupted")
        return seq, entry_hash


def verify_log(path: Path) -> VerifyResult:
    """Check the whole chain. Raises AuditError naming the first bad line."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise AuditError("audit log not found") from exc
    except (OSError, UnicodeDecodeError) as exc:
        raise AuditError("cannot read the audit log") from exc
    previous = GENESIS_HASH
    count = 0
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except ValueError as exc:
            raise AuditError(f"line {number}: not valid JSON") from exc
        if not isinstance(entry, dict):
            raise AuditError(f"line {number}: not a JSON object")
        stored = entry.pop("hash", None)
        if not isinstance(stored, str):
            raise AuditError(f"line {number}: missing hash")
        if entry.get("seq") != count + 1:
            raise AuditError(f"line {number}: sequence number mismatch")
        if entry.get("prev_hash") != previous:
            raise AuditError(f"line {number}: chain broken")
        if _digest(entry) != stored:
            raise AuditError(f"line {number}: entry was modified")
        previous = stored
        count += 1
    return VerifyResult(entries=count, head_hash=previous)
