"""Parser for the Anthropic Messages API.

Implements the provider contract documented in ``base.py``:

    match(host, path)
    parse_request(path, body)      -> ParsedRequest
    parse_response(path, body)     -> ParsedResponse   (non-streaming JSON)
    parse_stream(chunks)           -> ParsedResponse    (raw SSE body, arbitrary chunking)

Host is ``api.anthropic.com`` (exact host match, so ``api.anthropic.com.attacker.io``
does NOT match). All four entry points are pure and never raise on malformed input.
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
    iter_sse,
    load_json,
)

HOST = "api.anthropic.com"
PATH = "/v1/messages"


def match(host: str, path: str) -> bool:
    """True when the request targets the Anthropic Messages API.

    Host comparison is exact (after stripping ``:port``) so that an attacker host
    such as ``api.anthropic.com.attacker.io`` is not accepted.
    """
    h = host.split(":", 1)[0]
    return h == HOST and path == PATH


def _usage_from(d: dict) -> Usage:
    """Build a ``Usage`` from an Anthropic ``usage`` object.

    Anthropic reports the uncached prompt size in ``input_tokens`` and the cache
    subsets separately, so the normalized ``input_tokens`` must include both.
    """
    input_tokens = int(d.get("input_tokens") or 0)
    cache_read = int(d.get("cache_read_input_tokens") or 0)
    cache_write = int(d.get("cache_creation_input_tokens") or 0)
    return Usage(
        input_tokens=input_tokens + cache_read + cache_write,
        output_tokens=int(d.get("output_tokens") or 0),
        cache_read_tokens=cache_read,
        cache_write_tokens=cache_write,
        source="reported",
    )


def _system_text(system) -> str | None:
    """Flatten the request ``system`` field (string or list of blocks)."""
    if system is None:
        return None
    text = content_to_text(system)
    return text or None


def parse_request(path: str, body: bytes) -> ParsedRequest:
    obj = load_json(body)
    if obj is None:
        return ParsedRequest(provider="anthropic", error="unparseable request body")

    messages: list[Message] = []
    for m in obj.get("messages") or []:
        if not isinstance(m, dict):
            continue
        messages.append(Message(role=str(m.get("role") or ""), text=content_to_text(m.get("content"))))

    tools = obj.get("tools")
    tool_count = len(tools) if isinstance(tools, list) else 0
    max_tokens = obj.get("max_tokens")
    return ParsedRequest(
        provider="anthropic",
        endpoint="messages",
        model=obj.get("model"),
        stream=bool(obj.get("stream")),
        system=_system_text(obj.get("system")),
        messages=messages,
        tool_count=tool_count,
        max_tokens=int(max_tokens) if isinstance(max_tokens, int) else None,
    )


def parse_response(path: str, body: bytes) -> ParsedResponse:
    obj = load_json(body)
    if obj is None:
        return ParsedResponse(error="unparseable response body")

    if obj.get("type") == "error":
        err = obj.get("error")
        if isinstance(err, dict):
            msg = err.get("message")
            return ParsedResponse(error=msg if isinstance(msg, str) else json.dumps(err))
        return ParsedResponse(error=str(err))

    return ParsedResponse(
        model=obj.get("model"),
        text=content_to_text(obj.get("content")),
        usage=_usage_from(obj.get("usage") or {}),
        finish_reason=obj.get("stop_reason"),
    )


def parse_stream(chunks: Iterable[bytes]) -> ParsedResponse:
    model: str | None = None
    text_parts: list[str] = []
    tool_calls = 0
    finish_reason: str | None = None
    usage = Usage()

    for _event, data in iter_sse(chunks):
        try:
            obj = json.loads(data)
        except (ValueError, UnicodeDecodeError):
            continue
        if not isinstance(obj, dict):
            continue

        etype = obj.get("type")
        if etype == "message_start":
            msg = obj.get("message") or {}
            model = msg.get("model")
            u = msg.get("usage")
            if isinstance(u, dict):
                usage = _usage_from(u)
        elif etype == "content_block_start":
            block = obj.get("content_block") or {}
            if block.get("type") == "tool_use":
                tool_calls += 1
        elif etype == "content_block_delta":
            delta = obj.get("delta") or {}
            if delta.get("type") == "text_delta":
                text_parts.append(str(delta.get("text") or ""))
        elif etype == "message_delta":
            delta = obj.get("delta") or {}
            if delta.get("stop_reason") is not None:
                finish_reason = delta.get("stop_reason")
            u = obj.get("usage")
            if isinstance(u, dict):
                # ``output_tokens`` is cumulative; take the last value, not a sum.
                usage.output_tokens = int(u.get("output_tokens") or usage.output_tokens)

    return ParsedResponse(
        model=model,
        text="".join(text_parts),
        usage=usage,
        finish_reason=finish_reason,
        tool_calls=tool_calls,
    )
