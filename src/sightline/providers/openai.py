"""Parser for the OpenAI Chat Completions + Responses APIs.

Implements the provider contract documented in ``base.py``:

    match(host, path)
    parse_request(path, body)      -> ParsedRequest
    parse_response(path, body)     -> ParsedResponse   (non-streaming JSON)
    parse_stream(chunks)           -> ParsedResponse    (raw SSE body, arbitrary chunking)

Hosts are ``api.openai.com`` and Azure OpenAI deployments (``*.openai.azure.com``).
Endpoint kinds are ``/chat/completions`` -> ``chat``, ``/responses`` -> ``responses``,
``/embeddings`` -> ``embeddings`` and ``/models`` -> ``models`` (Azure prefixes the path
with ``/openai/deployments/<name>`` before the OpenAI resource). ``parse_stream`` auto-detects
Chat Completions chunks versus Responses API events. All entry points are pure and never raise
on malformed input.
"""

from __future__ import annotations

import json
from collections.abc import Iterable

from sightline.providers.base import (
    EndpointKind,
    Message,
    ParsedRequest,
    ParsedResponse,
    Usage,
    content_to_text,
    iter_sse,
    load_json,
)

PROVIDER = "openai"
HOST = "api.openai.com"
AZURE_SUFFIX = "openai.azure.com"


def _endpoint(path: str) -> EndpointKind:
    """Map a request path to an OpenAI endpoint kind.

    Azure OpenAI prefixes the resource with ``/openai/deployments/<name>``; the resource
    segment after it selects the kind, so matching on the path tail keeps both hosts working.
    """
    if "/responses" in path:
        return "responses"
    if "/embeddings" in path:
        return "embeddings"
    if "/chat/completions" in path:
        return "chat"
    if path.rstrip("/").endswith("/models"):
        return "models"
    return "other"


def match(host: str, path: str) -> bool:
    """True when the request targets the OpenAI API.

    Host comparison strips an optional ``:port`` then accepts an exact match for
    ``api.openai.com`` or any ``*.openai.azure.com`` Azure deployment. An attacker host
    such as ``api.openai.com.evil.tld`` does NOT match because the comparison is exact /
    suffix-anchored, never a substring.
    """
    h = host.split(":", 1)[0]
    if h == HOST:
        host_ok = True
    elif h.endswith("." + AZURE_SUFFIX) or h == AZURE_SUFFIX:
        host_ok = True
    else:
        host_ok = False
    if not host_ok:
        return False
    return _endpoint(path) in ("chat", "responses", "embeddings", "models")


def _usage_from(d: dict) -> Usage:
    """Build a normalized ``Usage`` from an OpenAI ``usage`` object.

    ``prompt_tokens`` / ``input_tokens`` is the full prompt size including cached tokens;
    the cache-read and reasoning subsets are pulled from the ``*_details`` sub-objects.
    """
    if not isinstance(d, dict):
        return Usage()
    details_in = d.get("input_tokens_details") or d.get("prompt_tokens_details")
    details_out = d.get("output_tokens_details")
    cache_read = 0
    reasoning = 0
    if isinstance(details_in, dict):
        cache_read = int(details_in.get("cached_tokens") or 0)
    if isinstance(details_out, dict):
        reasoning = int(details_out.get("reasoning_tokens") or 0)
    return Usage(
        input_tokens=int(d.get("input_tokens") or d.get("prompt_tokens") or 0),
        output_tokens=int(d.get("output_tokens") or d.get("completion_tokens") or 0),
        cache_read_tokens=cache_read,
        cache_write_tokens=int(d.get("cache_creation_input_tokens") or 0),
        reasoning_tokens=reasoning,
        source="reported",
    )


def _system_text(value) -> str | None:
    """Flatten the request system field (chat ``messages`` or responses ``instructions``)."""
    if value is None:
        return None
    text = content_to_text(value)
    return text or None


def _max_tokens(obj: dict) -> int | None:
    """Return the completion-token budget, whichever name the API uses."""
    for key in ("max_completion_tokens", "max_output_tokens", "max_tokens"):
        v = obj.get(key)
        if isinstance(v, int):
            return v
    return None


def parse_request(path: str, body: bytes) -> ParsedRequest:
    obj = load_json(body)
    if obj is None:
        return ParsedRequest(provider=PROVIDER, endpoint=_endpoint(path), error="unparseable request body")

    endpoint = _endpoint(path)
    messages: list[Message] = []
    system: str | None = None

    if endpoint == "responses":
        system = _system_text(obj.get("instructions"))
        for m in obj.get("input") or []:
            if isinstance(m, dict):
                messages.append(Message(role=str(m.get("role") or ""), text=content_to_text(m.get("content"))))
    else:
        for m in obj.get("messages") or []:
            if not isinstance(m, dict):
                continue
            role = str(m.get("role") or "")
            text = content_to_text(m.get("content"))
            if role == "system":
                system = text or system
            else:
                messages.append(Message(role=role, text=text))

    tools = obj.get("tools")
    tool_count = len(tools) if isinstance(tools, list) else 0
    model = obj.get("model")
    return ParsedRequest(
        provider=PROVIDER,
        endpoint=endpoint,
        model=model if isinstance(model, str) else None,
        stream=bool(obj.get("stream")),
        system=system,
        messages=messages,
        tool_count=tool_count,
        max_tokens=_max_tokens(obj),
    )


def parse_response(path: str, body: bytes) -> ParsedResponse:
    obj = load_json(body)
    if obj is None:
        return ParsedResponse(error="unparseable response body")

    if obj.get("type") == "error" or "error" in obj:
        err = obj.get("error")
        if isinstance(err, dict):
            msg = err.get("message")
            return ParsedResponse(error=msg if isinstance(msg, str) else json.dumps(err))
        return ParsedResponse(error=str(err))

    kind = _endpoint(path)
    if kind == "responses":
        return _responses_response(obj)

    return ParsedResponse(
        model=obj.get("model"),
        text=content_to_text(_chat_message(obj)),
        usage=_usage_from(obj.get("usage") or {}),
        finish_reason=_chat_finish(obj),
        tool_calls=_chat_tool_calls(obj),
    )


def _chat_message(obj: dict) -> object:
    """Extract the assistant message object from a Chat Completions response body."""
    choices = obj.get("choices")
    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
        msg = choices[0].get("message")
        return msg if msg is not None else ""
    return ""


def _chat_finish(obj: dict) -> str | None:
    choices = obj.get("choices")
    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
        return choices[0].get("finish_reason")
    return None


def _chat_tool_calls(obj: dict) -> int:
    choices = obj.get("choices")
    if not (isinstance(choices, list) and choices and isinstance(choices[0], dict)):
        return 0
    calls = choices[0].get("message", {}).get("tool_calls") if isinstance(choices[0].get("message"), dict) else None
    return len(calls) if isinstance(calls, list) else 0


def _responses_response(obj: dict) -> ParsedResponse:
    """Normalize a non-streaming Responses API response body."""
    model = obj.get("model")
    text_parts: list[str] = []
    tool_calls = 0
    for item in obj.get("output") or []:
        if not isinstance(item, dict):
            continue
        itype = item.get("type")
        if itype == "message":
            text_parts.append(content_to_text(item.get("content")))
        elif itype == "function_call":
            tool_calls += 1
    usage = _usage_from(obj.get("usage") or {})
    status = obj.get("status")
    return ParsedResponse(
        model=model if isinstance(model, str) else None,
        text="".join(text_parts),
        usage=usage,
        finish_reason=None if status == "completed" else status,
        tool_calls=tool_calls,
    )


def parse_stream(chunks: Iterable[bytes]) -> ParsedResponse:
    """Parse a streamed body, auto-detecting Chat Completions chunks vs Responses events.

    The two wire formats are distinguishable by the ``event:`` name (Responses only) and the
    JSON ``type`` field, so both are handled in a single pass. Usage arrives in a final frame
    for each format; for Responses it is cumulative, so the last value wins.
    """
    acc = _Accumulator()
    for event_name, data in iter_sse(chunks):
        obj = _loads(data)
        if not isinstance(obj, dict):
            continue

        name = event_name if isinstance(event_name, str) else None
        etype = obj.get("type")
        is_responses = bool((name and name.startswith("response.")) or (etype and etype.startswith("response.")))
        if is_responses:
            _apply_responses(acc, name or etype, obj)
        else:
            _apply_chat(acc, obj)
    return acc.as_response()


def _loads(raw: str) -> object:
    try:
        return json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return None


class _Accumulator:
    """Mutable per-stream state for the auto-detecting SSE parser."""

    __slots__ = ("model", "text_parts", "tool_calls", "finish_reason", "usage")

    def __init__(self) -> None:
        self.model: str | None = None
        self.text_parts: list[str] = []
        self.tool_calls = 0
        self.finish_reason: str | None = None
        self.usage = Usage()

    def text(self) -> str:
        return "".join(self.text_parts)

    def as_response(self) -> ParsedResponse:
        return ParsedResponse(
            model=self.model,
            text=self.text(),
            usage=self.usage,
            finish_reason=self.finish_reason,
            tool_calls=self.tool_calls,
        )


def _apply_chat(acc: _Accumulator, obj: dict) -> None:
    """Accumulate a Chat Completions streaming chunk into ``acc``."""
    model = obj.get("model")
    if isinstance(model, str):
        acc.model = model

    usage = obj.get("usage")
    if isinstance(usage, dict):
        acc.usage = _usage_from(usage)

    choices = obj.get("choices")
    if not (isinstance(choices, list) and choices and isinstance(choices[0], dict)):
        return
    choice = choices[0]
    delta = choice.get("delta")
    if isinstance(delta, dict):
        # Answer text only: an OpenAI/Ollama ``reasoning`` field is NOT part of the answer and
        # an empty ``content`` must not contribute.
        content = delta.get("content")
        if isinstance(content, str) and content:
            acc.text_parts.append(content)
        calls = delta.get("tool_calls")
        if isinstance(calls, list):
            acc.tool_calls += len(calls)
    fr = choice.get("finish_reason")
    if isinstance(fr, str) and fr:
        acc.finish_reason = fr


def _apply_responses(acc: _Accumulator, etype: str, obj: dict) -> None:
    """Accumulate a Responses API event into ``acc``."""
    if etype == "response.output_text.delta":
        delta = obj.get("delta")
        if isinstance(delta, str) and delta:
            acc.text_parts.append(delta)
        return

    if etype.startswith("response.output_item.added"):
        item = obj.get("item")
        if isinstance(item, dict) and item.get("type") == "function_call":
            acc.tool_calls += 1
        return

    if etype in ("response.completed", "response.incomplete", "response.failed"):
        resp = obj.get("response")
        if isinstance(resp, dict):
            model = resp.get("model")
            if isinstance(model, str):
                acc.model = model
            usage = resp.get("usage")
            if isinstance(usage, dict):
                acc.usage = _usage_from(usage)
            status = resp.get("status")
            acc.finish_reason = None if status == "completed" else status
        return
