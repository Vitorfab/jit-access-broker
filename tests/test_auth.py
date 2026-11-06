import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from jit_broker.audit import AuditLog
from jit_broker.auth import IDLE_MINUTES, LOCK_MINUTES, MAX_FAILED, Auth, AuthError
from jit_broker.policy import load_policy
from jit_broker.service import BrokerError
from jit_broker.store import Store

EXAMPLE = Path(__file__).resolve().parents[1] / "policies" / "example.yaml"
PW = "correct horse battery"
WRONG = "definitely not it!"


class FakeClock:
    def __init__(self) -> None:
        self.now = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kwargs: float) -> None:
        self.now += timedelta(**kwargs)


Env = tuple[Auth, FakeClock, Store, Path]


@pytest.fixture
def env(tmp_path: Path) -> Iterator[Env]:
    clock = FakeClock()
    store = Store(tmp_path / "state.db")
    audit_path = tmp_path / "audit.jsonl"
    auth = Auth(load_policy(EXAMPLE), store, AuditLog(audit_path), clock)
    yield auth, clock, store, audit_path
    store.close()


def _events(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_account_is_stored_as_argon2id_hash(env: Env) -> None:
    auth, _, store, audit_path = env
    auth.create_account("alice", PW)
    account = store.get_account("alice")
    assert account is not None
    assert account.password_hash.startswith("$argon2id$")
    assert PW not in account.password_hash
    assert PW not in audit_path.read_text(encoding="utf-8")


def test_account_needs_a_policy_user_and_a_long_password(env: Env) -> None:
    auth, _, _, _ = env
    with pytest.raises(BrokerError, match="unknown user"):
        auth.create_account("ghost", PW)
    with pytest.raises(BrokerError, match="password must"):
        auth.create_account("alice", "short")


def test_duplicate_account_is_refused(env: Env) -> None:
    auth, _, _, _ = env
    auth.create_account("alice", PW)
    with pytest.raises(BrokerError, match="already exists"):
        auth.create_account("alice", PW)


def test_login_and_authenticate(env: Env) -> None:
    auth, _, _, _ = env
    auth.create_account("alice", PW)
    result = auth.login("alice", PW)
    session = auth.authenticate(result.token)
    assert session is not None
    assert session.username == "alice"
    assert session.csrf == result.csrf
    assert auth.authenticate("not-a-token") is None
    assert auth.authenticate("") is None


def test_wrong_password_and_unknown_user_give_the_same_error(env: Env) -> None:
    auth, _, _, _ = env
    auth.create_account("alice", PW)
    with pytest.raises(AuthError) as wrong:
        auth.login("alice", WRONG)
    with pytest.raises(AuthError) as unknown:
        auth.login("nobody", WRONG)
    with pytest.raises(AuthError) as malformed:
        auth.login("Bad User!", WRONG)
    assert str(wrong.value) == str(unknown.value) == str(malformed.value) == "invalid credentials"


def test_lockout_after_repeated_failures_then_recovery(env: Env) -> None:
    auth, clock, _, audit_path = env
    auth.create_account("alice", PW)
    for _ in range(MAX_FAILED):
        with pytest.raises(AuthError):
            auth.login("alice", WRONG)
    with pytest.raises(AuthError):
        auth.login("alice", PW)  # locked: even the right password is refused
    clock.advance(minutes=LOCK_MINUTES + 1)
    assert auth.login("alice", PW).username == "alice"
    events = [e["event"] for e in _events(audit_path)]
    assert "account_locked" in events
    assert events.count("login_failed") == MAX_FAILED + 1


def test_success_resets_the_failure_counter(env: Env) -> None:
    auth, _, _, _ = env
    auth.create_account("alice", PW)
    for _ in range(MAX_FAILED - 1):
        with pytest.raises(AuthError):
            auth.login("alice", WRONG)
    auth.login("alice", PW)
    for _ in range(MAX_FAILED - 1):
        with pytest.raises(AuthError):
            auth.login("alice", WRONG)
    assert auth.login("alice", PW).username == "alice"


def test_idle_timeout_ends_the_session(env: Env) -> None:
    auth, clock, _, _ = env
    auth.create_account("alice", PW)
    token = auth.login("alice", PW).token
    clock.advance(minutes=IDLE_MINUTES - 1)
    assert auth.authenticate(token) is not None
    clock.advance(minutes=IDLE_MINUTES - 1)
    assert auth.authenticate(token) is not None  # activity renewed it
    clock.advance(minutes=IDLE_MINUTES)
    assert auth.authenticate(token) is None


def test_passive_reads_do_not_renew_the_session(env: Env) -> None:
    auth, clock, _, _ = env
    auth.create_account("alice", PW)
    token = auth.login("alice", PW).token
    clock.advance(minutes=IDLE_MINUTES - 1)
    assert auth.authenticate(token, touch=False) is not None
    clock.advance(minutes=2)
    assert auth.authenticate(token, touch=False) is None


def test_absolute_lifetime_ends_an_active_session(env: Env) -> None:
    auth, clock, _, _ = env
    auth.create_account("alice", PW)
    token = auth.login("alice", PW).token
    for _ in range(47):
        clock.advance(minutes=10)
        assert auth.authenticate(token) is not None
    clock.advance(minutes=10)  # exactly 8 hours after login
    assert auth.authenticate(token) is None


def test_logout_invalidates_the_session_on_the_server(env: Env) -> None:
    auth, _, _, audit_path = env
    auth.create_account("alice", PW)
    token = auth.login("alice", PW).token
    auth.logout(token)
    assert auth.authenticate(token) is None
    assert "logout" in [e["event"] for e in _events(audit_path)]


def test_login_events_are_logged_without_secrets(env: Env) -> None:
    auth, _, _, audit_path = env
    auth.create_account("alice", PW)
    result = auth.login("alice", PW)
    with pytest.raises(AuthError):
        auth.login("alice", WRONG)
    text = audit_path.read_text(encoding="utf-8")
    assert PW not in text
    assert WRONG not in text
    assert result.token not in text
    events = [e["event"] for e in _events(audit_path)]
    assert events == ["account_created", "login_succeeded", "login_failed"]
