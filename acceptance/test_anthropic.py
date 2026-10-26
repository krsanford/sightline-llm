from conftest import chunked
from sightline.providers import anthropic


def test_match():
    assert anthropic.match("api.anthropic.com", "/v1/messages")
    assert not anthropic.match("api.anthropic.com.attacker.io", "/v1/messages")
    assert not anthropic.match("api.openai.com", "/v1/messages")


def test_request(fx):
    r = anthropic.parse_request("/v1/messages", fx("anthropic_request.json"))
    assert r.provider == "anthropic" and r.endpoint == "messages"
    assert r.model == "claude-sonnet-5-5" and r.stream and r.max_tokens == 1024
    assert r.system == "You are a weather bot."
    assert [m.role for m in r.messages] == ["user", "assistant", "user"]
    assert "jane.doe@example.com" in r.messages[2].text and "[image]" in r.messages[2].text
    assert r.tool_count == 1


def test_stream(fx):
    data = fx("anthropic_messages_stream.sse")
    for size in (1, 5, 50, len(data)):
        p = anthropic.parse_stream(chunked(data, size))
        assert p.model == "claude-sonnet-5-5"
        assert p.text == "Red, yellow, and blue."
        assert p.usage.input_tokens == 472 + 1024 and p.usage.output_tokens == 89
        assert p.usage.cache_read_tokens == 1024 and p.usage.cache_write_tokens == 0
        assert p.finish_reason == "tool_use" and p.tool_calls == 1
        assert p.usage.source == "reported"


def test_json(fx):
    p = anthropic.parse_response("/v1/messages", fx("anthropic_messages.json"))
    assert p.text == "Hello! How can I help?" and p.model == "claude-opus-5-5"
    assert (p.usage.input_tokens, p.usage.output_tokens, p.usage.cache_write_tokens) == (212, 9, 200)
    assert p.finish_reason == "end_turn"


def test_error_body():
    p = anthropic.parse_response(
        "/v1/messages", b'{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}'
    )
    assert p.error and "invalid x-api-key" in p.error
