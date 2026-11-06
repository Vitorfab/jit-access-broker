"""Local accounts, sessions and login throttling (lab identity layer).

Passwords are hashed with Argon2id. A session token is random, lives in an HttpOnly cookie and
only its SHA-256 is stored. Every login outcome is written to the audit log (never the password).
Failures give one generic message, so the response does not reveal which part was wrong.
Not a replacement for SSO and MFA: see docs/threat-model.md.
"""

import hashlib
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from jit_broker.audit import AuditLog, Detail
from jit_broker.domain import Session
from jit_broker.policy import Policy
from jit_broker.service import BrokerError
from jit_broker.store import Store

MIN_PASSWORD = 12
MAX_PASSWORD = 128
MAX_FAILED = 5
LOCK_MINUTES = 15
IDLE_MINUTES = 15
ABSOLUTE_HOURS = 8

_IDENT = re.compile(r"[a-z][a-z0-9-]{1,31}")
_HASHER = PasswordHasher()
# Verified when the account does not exist (or is locked) so timing stays similar.
_DUMMY_HASH = _HASHER.hash(secrets.token_urlsafe(16))
_GENERIC = "invalid credentials"

Clock = Callable[[], datetime]


class AuthError(BrokerError):
    """Authentication failed. The message never says which part was wrong."""


@dataclass(frozen=True)
class LoginResult:
    username: str
    token: str
    csrf: str


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _verify(stored: str, candidate: str) -> bool:
    try:
        return _HASHER.verify(stored, candidate)
    except (VerificationError, InvalidHashError):
        return False


class Auth:
    def __init__(
        self, policy: Policy, store: Store, audit: AuditLog, clock: Clock = _utc_now
    ) -> None:
        self._policy = policy
        self._store = store
        self._audit = audit
        self._clock = clock

    def create_account(self, username: str, password: str) -> None:
        if username not in self._policy.users:
            raise BrokerError("unknown user")
        if not MIN_PASSWORD <= len(password) <= MAX_PASSWORD:
            raise BrokerError(f"password must have {MIN_PASSWORD}-{MAX_PASSWORD} characters")
        stored = _HASHER.hash(password)
        now = self._clock()
        with self._store.transaction():
            if not self._store.create_account(username, stored, now):
                raise BrokerError("account already exists")
            self._audit.record("account_created", "system", now, {"username": username})

    def login(self, username: str, password: str) -> LoginResult:
        now = self._clock()
        well_formed = _IDENT.fullmatch(username) is not None
        account = self._store.get_account(username) if well_formed else None
        locked = (
            account is not None and account.locked_until is not None and account.locked_until > now
        )
        if account is not None and not locked and len(password) <= MAX_PASSWORD:
            verified = _verify(account.password_hash, password)
        else:
            _verify(_DUMMY_HASH, "not-the-password")
            verified = False
        actor = username if well_formed else "invalid"

        if verified:
            token = secrets.token_urlsafe(32)
            csrf = secrets.token_urlsafe(32)
            with self._store.transaction():
                self._store.set_login_failures(username, 0, None)
                self._store.delete_stale_sessions(now, now - timedelta(minutes=IDLE_MINUTES))
                self._store.insert_session(
                    token_hash=_digest(token),
                    username=username,
                    csrf=csrf,
                    created_at=now,
                    last_seen=now,
                    expires_at=now + timedelta(hours=ABSOLUTE_HOURS),
                )
                self._audit.record("login_succeeded", username, now, {})
            return LoginResult(username=username, token=token, csrf=csrf)

        details: dict[str, Detail] = {"known_account": account is not None, "locked": locked}
        with self._store.transaction():
            self._audit.record("login_failed", actor, now, details)
            current = self._store.get_account(username) if account is not None else None
            if current is not None and not locked:
                count = current.failed_count + 1
                if count >= MAX_FAILED:
                    until = now + timedelta(minutes=LOCK_MINUTES)
                    self._store.set_login_failures(username, 0, until)
                    self._audit.record("account_locked", actor, now, {"minutes": LOCK_MINUTES})
                else:
                    self._store.set_login_failures(username, count, None)
        raise AuthError(_GENERIC)

    def authenticate(self, token: str, touch: bool = True) -> Session | None:
        """Return the live session for this token, or None. Idle and absolute limits apply."""
        if not token or len(token) > 128:
            return None
        digest = _digest(token)
        now = self._clock()
        session = self._store.get_session(digest)
        if session is None:
            return None
        idle_limit = session.last_seen + timedelta(minutes=IDLE_MINUTES)
        if now >= session.expires_at or now >= idle_limit:
            self._store.delete_session(digest)
            return None
        if touch:
            self._store.touch_session(digest, now)
        return session

    def logout(self, token: str) -> None:
        digest = _digest(token)
        now = self._clock()
        session = self._store.get_session(digest)
        with self._store.transaction():
            if self._store.delete_session(digest) and session is not None:
                self._audit.record("logout", session.username, now, {})
