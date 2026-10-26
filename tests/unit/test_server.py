"""S11: the local dashboard resists DNS rebinding, CSRF and script injection."""
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sightline.config import Settings
from sightline.engine import Bus
from sightline.policy import Policy
from sightline.server import create_app
from sightline.store import Call, Store

WEB = Path(__file__).resolve().parents[2] / "src" / "sightline" / "web"


@pytest.fixture
def client(tmp_path):
    s = Settings(home=tmp_path)
    store = Store(tmp_path / "t.db")
    store.insert(Call(provider="openai", model="gpt-5.5", prompt='<script>alert(1)</script><img src=x onerror=alert(2)>',
                      response="</textarea><svg onload=alert(3)>", status=200))
    app = create_app(s, store, Policy(), Bus())
    return TestClient(app, base_url=f"http://127.0.0.1:{s.ui_port}")


def test_rebinding_host_rejected(client):
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/health", headers={"Host": "evil.test"}).status_code == 421
    assert client.get("/api/health", headers={"Host": "127.0.0.1:9999"}).status_code == 421


def test_cross_origin_write_rejected(client):
    r = client.post("/api/calls", headers={"Origin": "http://evil.test"})
    assert r.status_code == 403


def test_security_headers_and_no_cors(client):
    r = client.get("/api/calls", headers={"Origin": "http://evil.test"})
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert not any(h.lower().startswith("access-control-") for h in r.headers)


def test_hostile_content_is_returned_as_data_not_markup(client):
    row = client.get("/api/calls").json()[0]
    assert row["provider"] == "openai"
    detail = client.get(f"/api/calls/{row['id']}").json()
    assert detail["prompt"].startswith("<script>")  # stored verbatim as text; rendering is the UI's job
    assert client.get(f"/api/calls/{row['id']}").headers["content-type"].startswith("application/json")


def test_ui_never_uses_html_sinks():
    js = (WEB / "app.js").read_text()
    code = "\n".join(ln for ln in js.splitlines() if not ln.strip().startswith("//"))
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
        assert sink not in code, sink
    html = (WEB / "index.html").read_text()
    assert "<script>" not in html and "onclick=" not in html  # no inline script (CSP would block it anyway)


def test_pac_routes_only_llm_hosts_with_direct_fallback(client):
    pac = client.get("/proxy.pac").text
    assert 'return "DIRECT";' in pac and "; DIRECT" in pac and "api.openai.com" in pac
