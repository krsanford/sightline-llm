from conftest import chunked
from sightline.providers import gemini

PATH = "/v1beta/models/gemini-3.1-pro:streamGenerateContent"


def test_match():
    assert gemini.match("generativelanguage.googleapis.com", PATH)
    assert not gemini.match("generativelanguage.googleapis.com.evil.com", PATH)


def test_request_model_from_path(fx):
    r = gemini.parse_request(PATH, fx("gemini_request.json"))
    assert r.provider == "gemini" and r.endpoint == "generate"
    assert r.model == "gemini-3.1-pro" and r.stream is True
    assert r.system == "Answer like a physicist." and r.messages[0].text == "Why is the sky blue?"
    assert r.max_tokens == 256
    r2 = gemini.parse_request("/v1beta/models/gemini-3.1-flash:generateContent", fx("gemini_request.json"))
    assert r2.stream is False and r2.model == "gemini-3.1-flash"


def test_stream_takes_last_usage(fx):
    p = gemini.parse_stream(chunked(fx("gemini_stream.sse"), 9))
    assert p.text == "The sky is blue because of Rayleigh scattering."
    assert p.usage.input_tokens == 9 and p.usage.output_tokens == 12
    assert p.usage.reasoning_tokens == 40 and p.usage.cache_read_tokens == 4
    assert p.finish_reason == "STOP" and p.model == "gemini-3.1-pro"


def test_json(fx):
    p = gemini.parse_response("/v1beta/models/gemini-3.1-flash:generateContent", fx("gemini_response.json"))
    assert p.text == "Hi there." and (p.usage.input_tokens, p.usage.output_tokens) == (5, 3)
