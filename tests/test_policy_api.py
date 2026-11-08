import shutil
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient

from jit_broker.api import create_app
from jit_broker.audit import AuditLog
from jit_broker.auth import Auth
from jit_broker.policy import load_policy
from jit_broker.store import Store
from jit_broker.ui import APP_JS, INDEX_HTML

EXAMPLE = Path(__file__).resolve().parents[1] / "policies" / "example.yaml"
BASE = "http://127.0.0.1"
PW = "correct horse battery"


def _setup(tmp_path: Path, editor: bool = True) -> tuple[FastAPI, Path]:
    policy_path = tmp_path / "policy.yaml"
    shutil.copyfile(EXAMPLE, policy_path)
    policy = load_policy(policy_path)
    db = tmp_path / "state.db"
    audit = tmp_path / "audit.jsonl"
    store = Store(db)
    auth = Auth(policy, store, AuditLog(audit))
    for user in policy.users:
        auth.create_account(user, PW)
    store.close()
    return create_app(policy, db, audit, policy_path if editor else None), policy_path


def _login(api: FastAPI, user: str) -> tuple[TestClient, dict[str, str]]:
    client = TestClient(api, base_url=BASE)
    response = client.post("/auth/login", json={"username": user, "password": PW})
    assert response.status_code == 200, response.text
    return client, {"X-CSRF-Token": response.json()["csrf_token"]}


def _edited(client: TestClient, minutes: int) -> dict[str, Any]:
    data = client.get("/policy").json()["policy"]
    data["roles"]["db-readonly"]["max_duration_minutes"] = minutes
    return {"policy": data}


def test_policy_endpoints_need_a_session(tmp_path: Path) -> None:
    api, _ = _setup(tmp_path)
    client = TestClient(api, base_url=BASE)
    assert client.get("/policy").status_code == 401
    assert client.get("/policy/changes").status_code == 401
    assert client.post("/policy/changes", json={"policy": {}}).status_code == 401


def test_non_admins_cannot_read_the_policy(tmp_path: Path) -> None:
    api, _ = _setup(tmp_path)
    alice, _ = _login(api, "alice")
    response = alice.get("/policy")
    assert response.status_code == 400
    assert "requires an admin" in response.json()["detail"]
    assert alice.get("/policy/changes").status_code == 400


def test_two_admin_flow_and_policy_reload(tmp_path: Path) -> None:
    api, path = _setup(tmp_path)
    arthur, arthur_csrf = _login(api, "arthur")
    beatriz, beatriz_csrf = _login(api, "beatriz")
    alice, _ = _login(api, "alice")

    created = arthur.post("/policy/changes", headers=arthur_csrf, json=_edited(arthur, 240))
    assert created.status_code == 201
    assert created.json()["status"] == "pending"
    assert "policy" not in created.json()

    own = arthur.post("/policy/changes/1/approve", headers=arthur_csrf)
    assert own.status_code == 400

    applied = beatriz.post("/policy/changes/1/approve", headers=beatriz_csrf)
    assert applied.status_code == 200
    assert applied.json()["status"] == "applied"
    assert load_policy(path).roles["db-readonly"].max_duration_minutes == 240

    roles = {r["name"]: r for r in alice.get("/roles").json()}
    assert roles["db-readonly"]["max_duration_minutes"] == 240
    assert arthur.get("/policy/changes").json()[0]["status"] == "applied"


def test_reject_endpoint(tmp_path: Path) -> None:
    api, path = _setup(tmp_path)
    arthur, arthur_csrf = _login(api, "arthur")
    beatriz, beatriz_csrf = _login(api, "beatriz")
    arthur.post("/policy/changes", headers=arthur_csrf, json=_edited(arthur, 240))
    rejected = beatriz.post("/policy/changes/1/reject", headers=beatriz_csrf)
    assert rejected.json()["status"] == "rejected"
    assert load_policy(path).roles["db-readonly"].max_duration_minutes == 480


def test_policy_writes_need_the_csrf_token(tmp_path: Path) -> None:
    api, _ = _setup(tmp_path)
    arthur, arthur_csrf = _login(api, "arthur")
    body = _edited(arthur, 240)
    assert arthur.post("/policy/changes", json=body).status_code == 403
    assert (
        arthur.post("/policy/changes", headers={"X-CSRF-Token": "x"}, json=body).status_code == 403
    )
    assert arthur.post("/policy/changes", headers=arthur_csrf, json=body).status_code == 201


def test_invalid_proposal_returns_400(tmp_path: Path) -> None:
    api, _ = _setup(tmp_path)
    arthur, arthur_csrf = _login(api, "arthur")
    body = _edited(arthur, 240)
    body["policy"]["roles"]["db-admin"]["approvals_required"] = 9
    response = arthur.post("/policy/changes", headers=arthur_csrf, json=body)
    assert response.status_code == 400
    assert "invalid policy" in response.json()["detail"]


def test_editor_is_disabled_without_a_policy_file(tmp_path: Path) -> None:
    api, _ = _setup(tmp_path, editor=False)
    arthur, _ = _login(api, "arthur")
    assert arthur.get("/policy").status_code == 404


def test_api_fails_closed_when_the_policy_file_disappears(tmp_path: Path) -> None:
    api, path = _setup(tmp_path)
    client, _ = _login(api, "alice")
    path.unlink()
    assert client.get("/auth/me").status_code == 503
    assert client.get("/health").status_code == 200


def test_page_has_the_policy_editor_without_dangerous_sinks() -> None:
    assert "panel-policy" in INDEX_HTML
    assert "/policy/changes" in APP_JS
    assert "innerHTML" not in APP_JS
