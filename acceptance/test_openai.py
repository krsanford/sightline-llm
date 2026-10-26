from conftest import chunked
from sightline.providers import openai


def test_match():
    assert openai.match("api.openai.com", "/v1/chat/completions")
    assert openai.match("myres.openai.azure.com", "/openai/deployments/x/chat/completions")
    assert not openai.match("api.openai.com.evil.tld", "/v1/chat/completions")
    assert not openai.match("api.anthropic.com", "/v1/messages")


def test_chat_request(fx):
    r = openai.parse_request("/v1/chat/completions", fx("openai_chat_request.json"))
    assert r.provider == "openai" and r.endpoint == "chat"
    assert r.model == "gpt-5.5-mini" and r.stream is True
    assert r.system == "You are helpful."
    assert [m.role for m in r.messages] == ["user"]
    assert "AKIAIOSFODNN7EXAMPLE" in r.messages[0].text
    assert r.tool_count == 2 and r.max_tokens == 200


def test_chat_stream_usage_any_chunking(fx):
    data = fx("openai_chat_stream.sse")
    for size in (1, 7, 64, len(data)):
        p = openai.parse_stream(chunked(data, size))
        assert p.model == "gemma4:26b-mlx"
        assert p.usage.input_tokens == 24 and p.usage.output_tokens == 112
        assert p.usage.source == "reported"
        assert p.finish_reason == "stop"
        assert "red" in p.text.lower()


def test_chat_json(fx):
    p = openai.parse_response("/v1/chat/completions", fx("openai_chat.json"))
    assert p.text.startswith("Hi!")
    assert p.usage.input_tokens == 19 and p.usage.output_tokens == 50
    assert p.usage.cache_read_tokens == 6


def test_responses_api(fx):
    r = openai.parse_request("/v1/responses", fx("openai_responses_request.json"))
    assert r.endpoint == "responses" and r.model == "gpt-5.5" and r.system == "Be brief."
    assert "4111 1111 1111 1111" in r.prompt_text() and r.max_tokens == 100
    p = openai.parse_stream(chunked(fx("openai_responses_stream.sse"), 13))
    assert p.text == "Hello world" and p.model == "gpt-5.5-2026-08-01"
    assert (p.usage.input_tokens, p.usage.output_tokens) == (37, 11)
    assert p.usage.cache_read_tokens == 16 and p.usage.reasoning_tokens == 4


def test_garbage_never_raises():
    assert openai.parse_request("/v1/chat/completions", b"\x00not json").error
    p = openai.parse_stream([b"data: {broken\n\n", b"data: [DONE]\n\n"])
    assert p.usage.source == "none"
