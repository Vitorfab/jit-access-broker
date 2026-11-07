from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from jit_broker.api import create_app
from jit_broker.audit import AuditLog
from jit_broker.auth import Auth
from jit_broker.policy import load_policy
from jit_broker.service import Broker
from jit_broker.store import Store
from jit_broker.ui import APP_JS, INDEX_HTML

EXAMPLE = Path(__file__).resolve().parents[1] / "policies" / "example.yaml"
BASE = "http://127.0.0.1"
PW = "correct horse battery"
REQUEST = {"role": "db-readonly", "minutes": 60, "justification": "Checking a simulated report"}


def _api(tmp_path: Path) -> FastAPI:
    policy = load_policy(EXAMPLE)
    db = tmp_path / "state.db"
    audit = tmp_path / "audit.jsonl"
    store = Store(db)
    auth = Auth(policy, store, AuditLog(audit))
    for user in policy.users:
        auth.create_account(user, PW)
    store.close()
    return create_app(policy, db, audit)


def _login(api: FastAPI, user: str) -> tuple[TestClient, dict[str, str]]:
    client = TestClient(api, base_url=BASE)
    response = client.post("/auth/login", json={"username": user, "password": PW})
    assert response.status_code == 200, response.text
    return client, {"X-CSRF-Token": response.json()["csrf_token"]}


def _names(client: TestClient) -> set[str]:
    return {role["name"] for role in client.get("/roles").json()}


def test_roles_need_a_session(tmp_path: Path) -> None:
    assert TestClient(_api(tmp_path), base_url=BASE).get("/roles").status_code == 401


def test_roles_are_limited_to_what_the_user_may_request(tmp_path: Path) -> None:
    api = _api(tmp_path)
    alice, _ = _login(api, "alice")
    jonas, _ = _login(api, "jonas")
    carol, _ = _login(api, "carol")
    arthur, _ = _login(api, "arthur")
    assert _names(alice) == {"db-readonly", "db-admin", "audit-viewer"}
    assert _names(jonas) == {"db-readonly", "server-ops", "audit-viewer"}
    assert _names(carol) == set()
    assert _names(arthur) == set()


def test_roles_expose_only_public_fields(tmp_path: Path) -> None:
    alice, _ = _login(_api(tmp_path), "alice")
    first = alice.get("/roles").json()[0]
    assert set(first) == {
        "name",
        "description",
        "risk",
        "max_duration_minutes",
        "approvals_required",
    }


def test_approve_and_deny_as_the_page_does(tmp_path: Path) -> None:
    api = _api(tmp_path)
    alice, alice_csrf = _login(api, "alice")
    jonas, jonas_csrf = _login(api, "jonas")
    carol, carol_csrf = _login(api, "carol")
    alice.post("/requests", headers=alice_csrf, json=REQUEST)
    other = {"role": "audit-viewer", "minutes": 30, "justification": "Reading a simulated audit"}
    jonas.post("/requests", headers=jonas_csrf, json=other)
    approved = carol.post("/requests/1/approve", headers=carol_csrf, json={"reason": "Fine"})
    denied = carol.post("/requests/2/deny", headers=carol_csrf, json={"reason": "No need"})
    assert approved.json()["status"] == "approved"
    assert denied.json()["status"] == "denied"


def test_server_refuses_what_the_page_would_hide(tmp_path: Path) -> None:
    api = _api(tmp_path)
    alice, alice_csrf = _login(api, "alice")
    alice.post("/requests", headers=alice_csrf, json=REQUEST)
    own = alice.post("/requests/1/approve", headers=alice_csrf, json={"reason": "Myself"})
    assert own.status_code == 400
    assert alice.post("/sweep", headers=alice_csrf).status_code == 400
    assert alice.post("/grants/1/revoke", headers=alice_csrf).status_code == 400


def test_requestable_roles_for_unknown_user_is_empty(tmp_path: Path) -> None:
    store = Store(tmp_path / "state.db")
    broker = Broker(load_policy(EXAMPLE), store, AuditLog(tmp_path / "audit.jsonl"))
    assert broker.requestable_roles("ghost") == []
    store.close()


def test_page_has_the_action_controls() -> None:
    for element in ("request-form", "check-form", "confirm-box", "sweep-btn", 'id="reason"'):
        assert element in INDEX_HTML


def test_revoke_is_only_reachable_through_the_confirmation() -> None:
    assert APP_JS.count("/revoke") == 1
    assert "askRevoke" in APP_JS
    assert "confirm-yes" in APP_JS


def test_page_never_sends_the_session_user_from_the_browser() -> None:
    assert "X-Acting-User" not in APP_JS
    assert "username:" in APP_JS  # only the login body names a user
    assert APP_JS.count("username:") == 1
