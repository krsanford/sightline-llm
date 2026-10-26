"""End-to-end through the mitmproxy addon with in-memory flows (no network)."""
from pathlib import Path

import pytest
from mitmproxy.test import tflow, tutils

from sightline.config import Settings
from sightline.engine import Bus, SightlineAddon
from sightline.policy import Policy
from sightline.pricing import load_table
from sightline.store import Store

FIX = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture
def addon(tmp_path):
    store = Store(tmp_path / "t.db")
    pol = Policy(blocks=[{"provider": "deepseek", "reason": "not approved"}])
    return SightlineAddon(Settings(home=tmp_path), store, pol, load_table(), Bus()), store


def flow(host, path, body, port=443, scheme="https"):
    f = tflow.tflow(req=tutils.treq(host=host, port=port, scheme=scheme.encode(), path=path.encode(), method=b"POST",
                                    content=body, headers=((b"content-type", b"application/json"),
                                                           (b"authorization", b"Bearer sk-test-123"),
                                                           (b"user-agent", b"OpenAI/Python 2.24.0"))))
    return f


def test_non_llm_host_is_ignored(addon):
    a, store = addon
    f = flow("example.com", "/x", b"{}")
    a.request(f)
    assert "sightline" not in f.metadata and f.response is None


def test_private_upstream_refused_in_proxy_mode(addon):
    a, _ = addon
    f = flow("127.0.0.1", "/api/chat", b"{}", port=11434, scheme="http")
    a.request(f)
    assert f.response is not None and f.response.status_code == 403


def test_blocked_provider_gets_provider_shaped_403_and_is_recorded(addon):
    a, store = addon
    f = flow("api.deepseek.com", "/chat/completions", b'{"model":"deepseek-chat","messages":[]}')
    a.request(f)
    assert f.response.status_code == 403 and b"not approved" in f.response.content
    a.response(f)
    row = store.list()[0]
    assert row["action"] == "blocked" and row["provider"] == "deepseek"


def test_credentials_are_fingerprinted_never_stored(addon, tmp_path):
    a, store = addon
    f = flow("api.deepseek.com", "/chat/completions", b'{"model":"x"}')
    a.request(f)
    a.response(f)
    detail = store.get(store.list()[0]["id"])
    assert detail["key_fp"] and len(detail["key_fp"]) == 12
    raw = (tmp_path / "t.db").read_bytes()
    assert b"sk-test-123" not in raw and b"Bearer" not in raw


def test_openai_stream_is_metered_when_parser_present(addon):
    pytest.importorskip("sightline.providers.openai")
    a, store = addon
    body = (FIX / "openai_chat_request.json").read_bytes()
    f = flow("api.openai.com", "/v1/chat/completions", body)
    a.request(f)
    f.response = tutils.tresp(content=b"", headers=((b"content-type", b"text/event-stream"),))
    a.responseheaders(f)
    data = (FIX / "openai_chat_stream.sse").read_bytes()
    for i in range(0, len(data), 97):
        f.response.stream(data[i:i + 97])
    a.response(f)
    row = store.list()[0]
    assert row["input_tokens"] == 24 and row["output_tokens"] == 112 and row["ttft_ms"] is not None
