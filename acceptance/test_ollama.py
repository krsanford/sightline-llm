from conftest import chunked
from sightline.providers import ollama


def test_match():
    assert ollama.match("127.0.0.1:11434", "/api/chat")
    assert ollama.match("localhost:11434", "/v1/chat/completions")
    assert not ollama.match("api.openai.com", "/api/chat")


def test_native_chat_request():
    body = b'{"model":"qwen3.8:27b","messages":[{"role":"system","content":"S"},{"role":"user","content":"U"}]}'
    r = ollama.parse_request("/api/chat", body)
    assert r.provider == "ollama" and r.endpoint == "chat" and r.model == "qwen3.8:27b"
    assert r.stream is True  # Ollama native streams unless "stream": false
    assert r.system == "S" and r.messages[0].text == "U"


def test_native_stream(fx):
    p = ollama.parse_stream(chunked(fx("ollama_chat_stream.ndjson"), 11))
    assert p.model == "gemma4:26b-mlx"
    assert p.usage.input_tokens == 20 and p.usage.output_tokens == 81
    assert p.usage.cache_read_tokens == 11 and p.finish_reason == "stop"
    assert len(p.text) > 0


def test_generate_json(fx):
    r = ollama.parse_request("/api/generate", b'{"model":"m","prompt":"Say ok.","stream":false}')
    assert r.endpoint == "generate" and r.stream is False and r.messages[0].text == "Say ok."
    p = ollama.parse_response("/api/generate", fx("ollama_generate.json"))
    assert p.usage.output_tokens > 0 and p.usage.source == "reported"


def test_openai_compat_delegates(fx):
    p = ollama.parse_stream(chunked(fx("openai_chat_stream.sse"), 64))
    assert p.usage.output_tokens == 112
