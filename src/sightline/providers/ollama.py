"""Parser for the Ollama HTTP API.

Implements the provider contract documented in ``base.py``:

    match(host, path)
    parse_request(path, body)      -> ParsedRequest
    parse_response(path, body)     -> ParsedResponse   (non-streaming JSON)
    parse_stream(chunks)           -> ParsedResponse    (raw body, arbitrary chunking)

Ollama listens on ``127.0.0.1:11434`` (the host arrives as ``127.0.0.1:11434``).
The native API is newline-delimited JSON (``/api/chat``, ``/api/generate``); the
native ``/api/chat`` streams unless the request body carries ``"stream": false``.
Ollama also serves an OpenAI-compatible ``/v1/chat/completions`` endpoint that
streams server-sent-events, so ``parse_stream`` accepts both wire formats.

All four entry points are pure and never raise on malformed input.
"""

from __future__ import annotations

import json
from collections.abc import Iterable

from sightline.providers.base import (
    Message,
    ParsedRequest,
    ParsedResponse,
    Usage,
    content_to_text,
    iter_ndjson,
    iter_sse,
    load_json,
)

_PROVIDER = "ollama"
# Hosts that Ollama serves on. The port is stripped before comparing so that
# "127.0.0.1:11434" and "localhost:11434" both match, but "127.0.0.1:9999" does not.
_HOSTS = {"127.0.0.1", "localhost", "::1"}
_PORTS = {"11434"}
# Native endpoints map to their endpoint kind; the OpenAI-compatible endpoint too.
_ENDPOINTS = {
    "/api/chat": "chat",
    "/api/generate": "generate",
    "/v1/chat/completions": "chat",
    "/v1/completions": "generate",
}


def match(host: str, path: str) -> bool:
    """True when the request targets Ollama.

    The host is split on ``:`` and compared exactly (so a port of ``11434`` is
    required, and an attacker host such as ``127.0.0.1.attacker.io`` is rejected).
    """
    parts = host.split(":", 1)
    h = parts[0]
    port = parts[1] if len(parts) == 2 else ""
    if h not in _HOSTS:
        return False
    if port and port not in _PORTS:
        return False
    return path in _ENDPOINTS


def _usage_from(d: dict) -> Usage:
    """Build a normalized ``Usage`` from an Ollama object.

    Ollama reports the full prompt size in ``prompt_eval_count`` and the cached
    subset in ``prompt_eval_cached_count``. ``prompt_tokens_details.cached_tokens``
    (OpenAI-compatible responses) is the cache-read subset, and
    ``completion_tokens``/``eval_count`` is the output size.
    """
    input_tokens = int(d.get("prompt_eval_count") or 0)
    cache_read = int(d.get("prompt_eval_cached_count") or 0)
    output_tokens = int(d.get("eval_count") or 0)
    # OpenAI-compatible shape (no eval_count / prompt_eval_count).
    if not input_tokens:
        input_tokens = int(d.get("prompt_tokens") or 0)
    if not output_tokens:
        output_tokens = int(d.get("completion_tokens") or 0)
    # Cache reads reported the OpenAI-compatible way live under prompt_tokens_details.
    details = d.get("prompt_tokens_details")
    if isinstance(details, dict) and not cache_read:
        cache_read = int(details.get("cached_tokens") or 0)
    return Usage(
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cache_read_tokens=cache_read,
        source="reported" if (input_tokens or output_tokens) else "none",
    )


def _messages_from(obj: dict) -> tuple[str | None, list[Message]]:
    """Extract ``(system, messages)`` from an Ollama request body.

    For ``/api/chat`` the system prompt is the first ``system`` message and the
    remaining messages are kept. For ``/api/generate`` there is a bare ``prompt``
    that becomes a single user message.
    """
    messages: list[Message] = []
    system: str | None = None

    raw_messages = obj.get("messages")
    if isinstance(raw_messages, list):
        for m in raw_messages:
            if not isinstance(m, dict):
                continue
            role = str(m.get("role") or "user")
            text = content_to_text(m.get("content"))
            if role == "system" and system is None:
                system = text or None
            else:
                messages.append(Message(role=role, text=text))
    else:
        prompt = obj.get("prompt")
        if isinstance(prompt, str):
            messages.append(Message(role="user", text=prompt))

    return system, messages


def parse_request(path: str, body: bytes) -> ParsedRequest:
    obj = load_json(body)
    if obj is None:
        return ParsedRequest(provider=_PROVIDER, error="unparseable request body")

    endpoint = _ENDPOINTS.get(path, "other")
    system, messages = _messages_from(obj)

    tools = obj.get("tools")
    tool_count = len(tools) if isinstance(tools, list) else 0
    max_tokens = obj.get("options", {}).get("num_predict") if isinstance(obj.get("options"), dict) else None
    if max_tokens is None:
        max_tokens = obj.get("max_tokens")
        if max_tokens is None:
            max_tokens = obj.get("max_completion_tokens")

    # Native /api/chat streams unless the body explicitly disables it.
    if path in ("/api/chat", "/api/generate"):
        stream = obj.get("stream") is not False
    else:
        stream = bool(obj.get("stream"))

    return ParsedRequest(
        provider=_PROVIDER,
        endpoint=endpoint,
        model=obj.get("model"),
        stream=stream,
        system=system,
        messages=messages,
        tool_count=tool_count,
        max_tokens=int(max_tokens) if isinstance(max_tokens, int) else None,
    )


def parse_response(path: str, body: bytes) -> ParsedResponse:
    obj = load_json(body)
    if obj is None:
        return ParsedResponse(error="unparseable response body")

    if obj.get("error"):
        err = obj.get("error")
        return ParsedResponse(error=err if isinstance(err, str) else json.dumps(err))

    # Native /api/generate (and /api/chat non-streaming) shapes.
    text = content_to_text(obj.get("response"))
    finish_reason = obj.get("done_reason")
    usage = _usage_from(obj)
    tool_calls = 0
    raw = obj.get("message")
    if isinstance(raw, dict):
        tc = raw.get("tool_calls")
        if isinstance(tc, list):
            tool_calls = len(tc)

    # OpenAI-compatible /v1/chat/completions non-streaming shape.
    if text == "" and "choices" in obj:
        choices = obj.get("choices")
        if isinstance(choices, list) and choices:
            first = choices[0] or {}
            msg = first.get("message") or {}
            text = content_to_text(msg.get("content"))
            finish_reason = finish_reason or first.get("finish_reason")
            if isinstance(msg, dict) and isinstance(msg.get("tool_calls"), list):
                tool_calls = len(msg["tool_calls"])
        u = obj.get("usage")
        if isinstance(u, dict):
            usage = _usage_from(u)

    return ParsedResponse(
        model=obj.get("model"),
        text=text,
        usage=usage,
        finish_reason=finish_reason,
        tool_calls=tool_calls,
    )


def _looks_sse(chunks: Iterable[bytes]) -> tuple[bool, list[bytes]]:
    """Peek at the stream to decide between SSE (OpenAI compat) and NDJSON (native).

    Returns ``(is_sse, remaining)`` where ``remaining`` is the full list of chunks
    (the first, already-decoded, chunk is kept so framing stays consistent).
    """
    it = iter(chunks)
    first = next(it, b"")
    rest = list(it)
    head = b"".join([first, *rest[:1]])[:64].lstrip()
    # A leading "data:" (optionally with surrounding whitespace/CRLF) marks SSE.
    return head.startswith(b"data:") or head.startswith(b":") or head.startswith(b"event:"), [first, *rest]


def _parse_native_stream(chunks: Iterable[bytes]) -> ParsedResponse:
    model: str | None = None
    text_parts: list[str] = []
    finish_reason: str | None = None
    usage = Usage()

    for obj in iter_ndjson(chunks):
        if not isinstance(obj, dict):
            continue
        m = obj.get("model")
        if isinstance(m, str):
            model = m
        msg = obj.get("message")
        if isinstance(msg, dict):
            text = content_to_text(msg.get("content"))
            if text:
                text_parts.append(text)
            tc = msg.get("tool_calls")
            if isinstance(tc, list) and tc:
                # tool_calls are only populated on the final object; take the last.
                _ = tc
        if obj.get("done") is True:
            finish_reason = obj.get("done_reason")
            usage = _usage_from(obj)
            # A trailing content fragment can ride alongside done: true.
            if isinstance(msg, dict):
                text = content_to_text(msg.get("content"))
                if text:
                    text_parts.append(text)
            tc = msg.get("tool_calls") if isinstance(msg, dict) else None
            if isinstance(tc, list):
                _tool_calls = len(tc)
    return ParsedResponse(
        model=model,
        text="".join(text_parts),
        usage=usage,
        finish_reason=finish_reason,
        tool_calls=0,
    )


def _parse_sse_stream(chunks: Iterable[bytes]) -> ParsedResponse:
    model: str | None = None
    text_parts: list[str] = []
    finish_reason: str | None = None
    usage = Usage()

    for _event, data in iter_sse(chunks):
        if not data or data.strip() == "[DONE]":
            continue
        try:
            obj = json.loads(data)
        except (ValueError, UnicodeDecodeError):
            continue
        if not isinstance(obj, dict):
            continue

        m = obj.get("model")
        if isinstance(m, str):
            model = m

        choices = obj.get("choices")
        if isinstance(choices, list) and choices:
            first = choices[0] or {}
            delta = first.get("delta") or {}
            content = delta.get("content")
            if isinstance(content, str) and content:
                text_parts.append(content)
            if first.get("finish_reason") is not None:
                finish_reason = first.get("finish_reason")
            if isinstance(delta, dict) and isinstance(delta.get("tool_calls"), list):
                _tc = delta["tool_calls"]

        u = obj.get("usage")
        if isinstance(u, dict):
            # A final usage chunk (choices: []) carries the token counts.
            usage = _usage_from(u)

    return ParsedResponse(
        model=model,
        text="".join(text_parts),
        usage=usage,
        finish_reason=finish_reason,
        tool_calls=0,
    )


def parse_stream(chunks: Iterable[bytes]) -> ParsedResponse:
    """Parse an Ollama response body.

    Native Ollama streams are newline-delimited JSON; the OpenAI-compatible
    ``/v1/chat/completions`` streams server-sent-events. The two formats are
    distinguished by peeking at the first bytes: a leading ``data:`` line means
    SSE, otherwise NDJSON.
    """
    is_sse, remaining = _looks_sse(chunks)
    if is_sse:
        return _parse_sse_stream(remaining)
    return _parse_native_stream(remaining)
