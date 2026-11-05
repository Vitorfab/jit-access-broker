from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from jit_broker.api import create_app
from jit_broker.policy import load_policy
from jit_broker.ui import APP_JS, INDEX_HTML

EXAMPLE = Path(__file__).resolve().parents[1] / "policies" / "example.yaml"


def _client(tmp_path: Path) -> TestClient:
    api = create_app(load_policy(EXAMPLE), tmp_path / "state.db", tmp_path / "audit.jsonl", "k")
    return TestClient(api, base_url="http://127.0.0.1")


def test_index_is_served_with_security_headers(tmp_path: Path) -> None:
    response = _client(tmp_path).get("/")
    assert response.status_code == 200
    assert "jit-access-broker" in response.text
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["cache-control"] == "no-store"


def test_csp_is_strict(tmp_path: Path) -> None:
    csp = _client(tmp_path).get("/").headers["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "script-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "unsafe-inline" not in csp
    assert "unsafe-eval" not in csp


def test_assets_have_correct_content_types(tmp_path: Path) -> None:
    client = _client(tmp_path)
    assert "javascript" in client.get("/ui/app.js").headers["content-type"]
    assert "text/css" in client.get("/ui/app.css").headers["content-type"]


def test_security_headers_are_also_on_api_responses(tmp_path: Path) -> None:
    response = _client(tmp_path).get("/health")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "content-security-policy" in response.headers


def test_shell_holds_no_data_and_api_still_needs_the_token(tmp_path: Path) -> None:
    client = _client(tmp_path)
    assert client.get("/requests").status_code == 401
    assert client.get("/grants").status_code == 401
    assert "alice" not in INDEX_HTML.replace("for example: alice", "")


def test_index_has_no_inline_script_or_event_handlers() -> None:
    for segment in INDEX_HTML.split("<script")[1:]:
        assert segment.lstrip().startswith("src=")
    for attribute in ("onclick", "onload", "onerror", "onsubmit", "javascript:"):
        assert attribute not in INDEX_HTML.lower()


@pytest.mark.parametrize(
    "sink",
    ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"],
)
def test_app_js_never_uses_dangerous_sinks(sink: str) -> None:
    assert sink not in APP_JS


@pytest.mark.parametrize(
    "store", ["localStorage", "sessionStorage", "document.cookie", "indexedDB"]
)
def test_app_js_never_persists_the_token(store: str) -> None:
    assert store not in APP_JS


def test_foreign_host_is_rejected_for_the_dashboard(tmp_path: Path) -> None:
    assert _client(tmp_path).get("/", headers={"Host": "evil.example"}).status_code == 400
