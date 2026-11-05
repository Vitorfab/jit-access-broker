from pathlib import Path

from fastapi.testclient import TestClient
from typer.testing import CliRunner

from jit_broker.api import create_app
from jit_broker.cli import app as cli_app
from jit_broker.policy import load_policy

EXAMPLE = Path(__file__).resolve().parents[1] / "policies" / "example.yaml"
API_KEY = "lab-test-key"
REQUEST = {
    "role": "db-readonly",
    "minutes": 60,
    "justification": "Checking a simulated report",
}


def _client(tmp_path: Path) -> TestClient:
    api = create_app(load_policy(EXAMPLE), tmp_path / "state.db", tmp_path / "audit.jsonl", API_KEY)
    return TestClient(api, base_url="http://127.0.0.1")


def _h(user: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {API_KEY}", "X-Acting-User": user}


def test_health_is_available(tmp_path: Path) -> None:
    response = _client(tmp_path).get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_missing_or_wrong_token_is_rejected(tmp_path: Path) -> None:
    client = _client(tmp_path)
    assert client.get("/grants").status_code == 401
    wrong = {"Authorization": "Bearer nope", "X-Acting-User": "alice"}
    assert client.get("/grants", headers=wrong).status_code == 401


def test_acting_user_header_is_required(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.get("/grants", headers={"Authorization": f"Bearer {API_KEY}"})
    assert response.status_code == 400


def test_foreign_host_header_is_rejected(tmp_path: Path) -> None:
    response = _client(tmp_path).get("/health", headers={"Host": "evil.example"})
    assert response.status_code == 400


def test_interactive_docs_are_disabled(tmp_path: Path) -> None:
    client = _client(tmp_path)
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_full_flow_through_the_api(tmp_path: Path) -> None:
    client = _client(tmp_path)
    created = client.post("/requests", headers=_h("alice"), json=REQUEST)
    assert created.status_code == 201
    assert created.json()["status"] == "pending"

    approved = client.post(
        "/requests/1/approve", headers=_h("carol"), json={"reason": "Looks fine"}
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "approved"

    allowed = client.post("/check", headers=_h("alice"), json={"role": "db-readonly"})
    assert allowed.json()["allowed"] is True

    assert client.post("/grants/1/revoke", headers=_h("carol")).status_code == 400
    revoked = client.post("/grants/1/revoke", headers=_h("arthur"))
    assert revoked.status_code == 200
    assert revoked.json()["revoked_at"] is not None

    denied = client.post("/check", headers=_h("alice"), json={"role": "db-readonly"})
    assert denied.json()["allowed"] is False
    assert len(client.get("/grants", headers=_h("alice")).json()) == 1
    assert len(client.get("/requests", headers=_h("alice")).json()) == 1


def test_business_rule_violation_returns_400(tmp_path: Path) -> None:
    client = _client(tmp_path)
    client.post("/requests", headers=_h("alice"), json=REQUEST)
    response = client.post("/requests/1/approve", headers=_h("jonas"), json={"reason": "Trying"})
    assert response.status_code == 400
    assert "cannot approve" in response.json()["detail"]


def test_unknown_fields_and_bad_filters_are_rejected(tmp_path: Path) -> None:
    client = _client(tmp_path)
    extra = {**REQUEST, "admin": True}
    assert client.post("/requests", headers=_h("alice"), json=extra).status_code == 422
    assert client.get("/requests?status=bogus", headers=_h("alice")).status_code == 422


def test_sweep_is_admin_only(tmp_path: Path) -> None:
    client = _client(tmp_path)
    assert client.post("/sweep", headers=_h("carol")).status_code == 400
    response = client.post("/sweep", headers=_h("arthur"))
    assert response.status_code == 200
    assert response.json() == {"expired": 0}


def test_audit_verify_detects_tampering(tmp_path: Path) -> None:
    client = _client(tmp_path)
    client.post("/requests", headers=_h("alice"), json=REQUEST)
    ok = client.get("/audit/verify", headers=_h("alice"))
    assert ok.status_code == 200
    assert ok.json()["entries"] == 1
    log = tmp_path / "audit.jsonl"
    log.write_text(
        log.read_text(encoding="utf-8").replace("db-readonly", "db-admin"), encoding="utf-8"
    )
    bad = client.get("/audit/verify", headers=_h("alice"))
    assert bad.status_code == 409
    assert "modified" in bad.json()["detail"]


def test_serve_rejects_privileged_ports() -> None:
    result = CliRunner().invoke(cli_app, ["serve", "--port", "80"])
    assert result.exit_code == 2
