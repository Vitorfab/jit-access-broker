from pathlib import Path

from fastapi.testclient import TestClient
from typer.testing import CliRunner

from jit_broker.api import COOKIE_NAME, create_app
from jit_broker.audit import AuditLog
from jit_broker.auth import MAX_FAILED, Auth
from jit_broker.cli import app as cli_app
from jit_broker.policy import load_policy
from jit_broker.store import Store

EXAMPLE = Path(__file__).resolve().parents[1] / "policies" / "example.yaml"
BASE = "http://127.0.0.1"
PW = "correct horse battery"
REQUEST = {
    "role": "db-readonly",
    "minutes": 60,
    "justification": "Checking a simulated report",
}


def _api(tmp_path: Path):  # noqa: ANN202
    policy = load_policy(EXAMPLE)
    db = tmp_path / "state.db"
    audit = tmp_path / "audit.jsonl"
    store = Store(db)
    auth = Auth(policy, store, AuditLog(audit))
    for user in policy.users:
        auth.create_account(user, PW)
    store.close()
    return create_app(policy, db, audit)


def _login(api, user: str):  # noqa: ANN001, ANN202
    client = TestClient(api, base_url=BASE)
    response = client.post("/auth/login", json={"username": user, "password": PW})
    assert response.status_code == 200, response.text
    return client, {"X-CSRF-Token": response.json()["csrf_token"]}


def test_health_is_available(tmp_path: Path) -> None:
    response = TestClient(_api(tmp_path), base_url=BASE).get("/health")
    assert response.status_code == 200


def test_data_endpoints_need_a_session(tmp_path: Path) -> None:
    client = TestClient(_api(tmp_path), base_url=BASE)
    for path in ("/requests", "/grants", "/auth/me", "/audit/verify"):
        assert client.get(path).status_code == 401
    assert client.post("/requests", json=REQUEST).status_code == 401


def test_acting_user_header_no_longer_grants_anything(tmp_path: Path) -> None:
    client = TestClient(_api(tmp_path), base_url=BASE)
    assert client.get("/requests", headers={"X-Acting-User": "arthur"}).status_code == 401


def test_bad_credentials_get_one_generic_answer(tmp_path: Path) -> None:
    client = TestClient(_api(tmp_path), base_url=BASE)
    wrong = client.post("/auth/login", json={"username": "alice", "password": "wrong-password!"})
    unknown = client.post("/auth/login", json={"username": "nobody", "password": "wrong-password!"})
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json() == {"detail": "invalid credentials"}


def test_session_cookie_is_httponly_and_samesite_strict(tmp_path: Path) -> None:
    client = TestClient(_api(tmp_path), base_url=BASE)
    response = client.post("/auth/login", json={"username": "alice", "password": PW})
    cookie = response.headers["set-cookie"].lower()
    assert COOKIE_NAME in cookie
    assert "httponly" in cookie
    assert "samesite=strict" in cookie


def test_me_returns_the_profile_and_csrf_token(tmp_path: Path) -> None:
    client, csrf = _login(_api(tmp_path), "carol")
    body = client.get("/auth/me").json()
    assert body["username"] == "carol"
    assert body["capabilities"] == ["approve"]
    assert body["csrf_token"] == csrf["X-CSRF-Token"]


def test_foreign_host_header_is_rejected(tmp_path: Path) -> None:
    client = TestClient(_api(tmp_path), base_url=BASE)
    assert client.get("/health", headers={"Host": "evil.example"}).status_code == 400


def test_interactive_docs_are_disabled(tmp_path: Path) -> None:
    client = TestClient(_api(tmp_path), base_url=BASE)
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_full_flow_through_the_api(tmp_path: Path) -> None:
    api = _api(tmp_path)
    alice, alice_csrf = _login(api, "alice")
    carol, carol_csrf = _login(api, "carol")
    arthur, arthur_csrf = _login(api, "arthur")

    created = alice.post("/requests", headers=alice_csrf, json=REQUEST)
    assert created.status_code == 201
    approved = carol.post("/requests/1/approve", headers=carol_csrf, json={"reason": "Looks fine"})
    assert approved.json()["status"] == "approved"
    assert alice.post("/check", headers=alice_csrf, json={"role": "db-readonly"}).json()["allowed"]

    assert carol.post("/grants/1/revoke", headers=carol_csrf).status_code == 400
    assert arthur.post("/grants/1/revoke", headers=arthur_csrf).status_code == 200
    denied = alice.post("/check", headers=alice_csrf, json={"role": "db-readonly"})
    assert denied.json()["allowed"] is False


def test_writes_need_the_csrf_token(tmp_path: Path) -> None:
    client, csrf = _login(_api(tmp_path), "alice")
    assert client.post("/requests", json=REQUEST).status_code == 403
    bad = {"X-CSRF-Token": "wrong"}
    assert client.post("/requests", headers=bad, json=REQUEST).status_code == 403
    assert client.post("/requests", headers=csrf, json=REQUEST).status_code == 201


def test_cross_origin_writes_are_refused(tmp_path: Path) -> None:
    client, csrf = _login(_api(tmp_path), "alice")
    evil = {**csrf, "Origin": "http://evil.example"}
    assert client.post("/requests", headers=evil, json=REQUEST).status_code == 403
    same = {**csrf, "Origin": BASE}
    assert client.post("/requests", headers=same, json=REQUEST).status_code == 201


def test_cross_origin_login_is_refused(tmp_path: Path) -> None:
    client = TestClient(_api(tmp_path), base_url=BASE)
    response = client.post(
        "/auth/login",
        json={"username": "alice", "password": PW},
        headers={"Origin": "http://evil.example"},
    )
    assert response.status_code == 403


def test_logout_invalidates_the_cookie_on_the_server(tmp_path: Path) -> None:
    client, csrf = _login(_api(tmp_path), "alice")
    token = client.cookies.get(COOKIE_NAME)
    assert token
    assert client.post("/auth/logout", headers=csrf).status_code == 200
    replay = TestClient(client.app, base_url=BASE)
    assert replay.get("/auth/me", headers={"Cookie": f"{COOKIE_NAME}={token}"}).status_code == 401


def test_reads_are_filtered_by_profile(tmp_path: Path) -> None:
    api = _api(tmp_path)
    alice, alice_csrf = _login(api, "alice")
    jonas, _ = _login(api, "jonas")
    carol, carol_csrf = _login(api, "carol")
    arthur, _ = _login(api, "arthur")
    alice.post("/requests", headers=alice_csrf, json=REQUEST)
    carol.post("/requests/1/approve", headers=carol_csrf, json={"reason": "Looks fine"})
    assert len(alice.get("/requests").json()) == 1
    assert len(carol.get("/requests").json()) == 1
    assert len(arthur.get("/requests").json()) == 1
    assert jonas.get("/requests").json() == []
    assert jonas.get("/grants").json() == []
    assert len(alice.get("/grants").json()) == 1


def test_business_rule_violation_returns_400(tmp_path: Path) -> None:
    api = _api(tmp_path)
    alice, alice_csrf = _login(api, "alice")
    jonas, jonas_csrf = _login(api, "jonas")
    alice.post("/requests", headers=alice_csrf, json=REQUEST)
    response = jonas.post("/requests/1/approve", headers=jonas_csrf, json={"reason": "Trying"})
    assert response.status_code == 400
    assert "cannot approve" in response.json()["detail"]


def test_unknown_fields_and_bad_filters_are_rejected(tmp_path: Path) -> None:
    client, csrf = _login(_api(tmp_path), "alice")
    extra = {**REQUEST, "admin": True}
    assert client.post("/requests", headers=csrf, json=extra).status_code == 422
    assert client.get("/requests?status=bogus").status_code == 422


def test_sweep_is_admin_only(tmp_path: Path) -> None:
    api = _api(tmp_path)
    carol, carol_csrf = _login(api, "carol")
    arthur, arthur_csrf = _login(api, "arthur")
    assert carol.post("/sweep", headers=carol_csrf).status_code == 400
    response = arthur.post("/sweep", headers=arthur_csrf)
    assert response.json() == {"expired": 0}


def test_audit_verify_is_admin_only_and_detects_tampering(tmp_path: Path) -> None:
    api = _api(tmp_path)
    alice, alice_csrf = _login(api, "alice")
    arthur, _ = _login(api, "arthur")
    alice.post("/requests", headers=alice_csrf, json=REQUEST)
    assert alice.get("/audit/verify").status_code == 403
    assert arthur.get("/audit/verify").status_code == 200
    log = tmp_path / "audit.jsonl"
    log.write_text(log.read_text(encoding="utf-8").replace("db-readonly", "db-admin"), "utf-8")
    bad = arthur.get("/audit/verify")
    assert bad.status_code == 409
    assert "modified" in bad.json()["detail"]


def test_repeated_bad_logins_lock_the_account(tmp_path: Path) -> None:
    client = TestClient(_api(tmp_path), base_url=BASE)
    for _ in range(MAX_FAILED):
        body = {"username": "alice", "password": "wrong-password!"}
        assert client.post("/auth/login", json=body).status_code == 401
    right = client.post("/auth/login", json={"username": "alice", "password": PW})
    assert right.status_code == 401


def test_serve_rejects_privileged_ports() -> None:
    result = CliRunner().invoke(cli_app, ["serve", "--port", "80"])
    assert result.exit_code == 2
