import json

import pytest

from sightline.policy import Policy


def test_block_rules_match_provider_model_host():
    p = Policy(blocks=[{"provider": "deepseek", "reason": "no"}, {"model": "gpt-6-astra*", "reason": "too pricey"}])
    assert p.check_block("deepseek", "deepseek-chat", "api.deepseek.com") == "no"
    assert p.check_block("openai", "GPT-6-astra-2026", "api.openai.com") == "too pricey"
    assert p.check_block("openai", "gpt-6-sol", "api.openai.com") is None


def test_redaction_keeps_json_valid_and_masks_secret():
    pytest.importorskip("sightline.detect")
    body = json.dumps({"messages": [{"role": "user", "content": "key AKIAIOSFODNN7EXAMPLE mail a@b.co"}]}).encode()
    d = Policy().evaluate("openai", "gpt-5.5", "api.openai.com", body)
    assert d.action == "redacted"
    doc = json.loads(d.body)
    assert "AKIAIOSFODNN7EXAMPLE" not in doc["messages"][0]["content"]
    assert {f["kind"] for f in d.findings} >= {"aws_access_key", "email"}


def test_block_on_secret_mode():
    pytest.importorskip("sightline.detect")
    body = json.dumps({"input": "AKIAIOSFODNN7EXAMPLE"}).encode()
    d = Policy(on_secret="block").evaluate("openai", "m", "api.openai.com", body)
    assert d.action == "blocked" and "secret" in d.reasons[0]


def test_local_provider_is_observed_not_rewritten():
    pytest.importorskip("sightline.detect")
    body = json.dumps({"messages": [{"role": "user", "content": "key AKIAIOSFODNN7EXAMPLE"}]}).encode()
    d = Policy().evaluate("ollama", "qwen3.8:27b", "127.0.0.1", body)
    assert d.action == "allowed" and d.body is None and "local model" in d.reasons[0]
    assert {f["kind"] for f in d.findings} == {"aws_access_key"}


def test_ollama_cloud_models_are_not_exempt():
    pytest.importorskip("sightline.detect")
    body = json.dumps({"messages": [{"role": "user", "content": "key AKIAIOSFODNN7EXAMPLE"}]}).encode()
    for model in ("gpt-oss:120b-cloud", "qwen3-coder:480b-cloud", "deepseek-v3.1:671b:cloud"):
        d = Policy().evaluate("ollama", model, "127.0.0.1", body)
        assert d.action == "redacted", model
