"""Parser for Google's Gemini ``generateContent`` / ``streamGenerateContent`` API.

Implements the provider contract documented in ``base.py``:

    match(host, path)
    parse_request(path, body)      -> ParsedRequest
    parse_response(path, body)     -> ParsedResponse   (non-streaming JSON)
    parse_stream(chunks)           -> ParsedResponse    (raw SSE body, arbitrary chunking)

Host is ``generativelanguage.googleapis.com`` (exact host match after stripping
``:port``, so a look-alike such as ``generativelanguage.googleapis.com.evil.com``
does NOT match). The model and the streaming flag are derived from the URL path
segment ``models/<id>:<method>``: ``stream`` is true iff the method is
``streamGenerateContent``. All four entry points are pure and never raise on
malformed input.
"""

from __future__ import annotations

import json
import re
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

HOST = "generativelanguage.googleapis.com"
STREAM_METHOD = "streamGenerateContent"

# URL path segment:  /v1beta/models/<id>:<method>
_MODEL_RE = re.compile(r"/models/([^:]+):([A-Za-z]+)")


def match(host: str, path: str) -> bool:
    """True when the request targets the Gemini ``generateContent`` family.

    Host comparison is exact (after stripping ``:port``) so that an attacker host
    such as ``generativelanguage.googleapis.com.evil.com`` is not accepted. Any
    path of the ``models/<id>:<method>`` form is a Gemini generate endpoint.
    """
    h = host.split(":", 1)[0]
    return h == HOST and bool(_MODEL_RE.search(path))


def _model_and_stream(path: str) -> tuple[str | None, bool]:
    """Split ``models/<id>:<method>`` into ``(model, is_stream)``.

    ``is_stream`` is true iff the method is ``streamGenerateContent``.
    """
    m = _MODEL_RE.search(path)
    if m is None:
        return None, False
    model, method = m.group(1), m.group(2)
    return model, method == STREAM_METHOD


def _usage_from(d: dict) -> Usage:
    """Build a normalized ``Usage`` from a Gemini ``usageMetadata`` object.

    ``promptTokenCount`` is the full prompt size (already including cached tokens),
    so it maps straight onto ``input_tokens``; the cache and reasoning counts are
    subsets of the prompt/output totals.
    """
    return Usage(
        input_tokens=int(d.get("promptTokenCount") or 0),
        output_tokens=int(d.get("candidatesTokenCount") or 0),
        cache_read_tokens=int(d.get("cachedContentTokenCount") or 0),
        cache_write_tokens=0,
        reasoning_tokens=int(d.get("thoughtsTokenCount") or 0),
        source="reported",
    )


def _candidate_text(cand) -> str:
    """Flatten a candidate's ``content`` into plain text (skips non-text parts).

    Gemini content is ``{"role": ..., "parts": [...]}``; the shared
    ``content_to_text`` does not recurse into a ``parts`` key, so we feed it the
    parts list directly.
    """
    if not isinstance(cand, dict):
        return ""
    content = cand.get("content")
    if isinstance(content, dict):
        return content_to_text(content.get("parts"))
    return content_to_text(content)


def parse_request(path: str, body: bytes) -> ParsedRequest:
    model, stream = _model_and_stream(path)

    obj = load_json(body)
    if obj is None:
        return ParsedRequest(
            provider="gemini",
            endpoint="generate",
            model=model,
            stream=stream,
            error="unparseable request body",
        )

    system = _system_text(obj.get("systemInstruction"))

    messages: list[Message] = []
    for c in obj.get("contents") or []:
        if not isinstance(c, dict):
            continue
        role = c.get("role") or "user"
        messages.append(Message(role=str(role), text=content_to_text(c.get("parts"))))

    gen = obj.get("generationConfig")
    max_tokens = gen.get("maxOutputTokens") if isinstance(gen, dict) else None

    tools = obj.get("tools")
    tool_count = len(tools) if isinstance(tools, list) else 0

    return ParsedRequest(
        provider="gemini",
        endpoint="generate",
        model=model,
        stream=stream,
        system=system,
        messages=messages,
        tool_count=tool_count,
        max_tokens=int(max_tokens) if isinstance(max_tokens, int) else None,
    )


def _system_text(si) -> str | None:
    """Flatten the request ``systemInstruction`` (``{parts: [{text}]}``) to text."""
    if si is None:
        return None
    if isinstance(si, dict):
        si = si.get("parts")
    text = content_to_text(si)
    return text or None


def parse_response(path: str, body: bytes) -> ParsedResponse:
    obj = load_json(body)
    model, _ = _model_and_stream(path)
    if obj is None:
        return ParsedResponse(model=model, error="unparseable response body")

    # ``candidates`` is a list; prefer index 0 when present, else fall back to a
    # bare ``content`` / ``finishReason`` at the top level.
    candidates = obj.get("candidates")
    cand: dict | None = None
    if isinstance(candidates, list) and candidates:
        cand = candidates[0] if isinstance(candidates[0], dict) else None
    if cand is None and isinstance(obj.get("content"), dict):
        cand = obj

    text = ""
    finish_reason = obj.get("finishReason")
    model = obj.get("modelVersion") or model
    if cand is not None:
        text = _candidate_text(cand)
        fr = cand.get("finishReason")
        if fr is not None:
            finish_reason = fr

    usage_meta = obj.get("usageMetadata")
    usage = _usage_from(usage_meta) if isinstance(usage_meta, dict) else Usage()

    tool_calls = 0
    if cand is not None:
        for part in cand.get("content", {}).get("parts") or []:
            if isinstance(part, dict) and "functionCall" in part:
                tool_calls += 1

    return ParsedResponse(
        model=model,
        text=text,
        usage=usage,
        finish_reason=finish_reason,
        tool_calls=tool_calls,
    )


def parse_stream(chunks: Iterable[bytes]) -> ParsedResponse:
    model: str | None = None
    text_parts: list[str] = []
    finish_reason: str | None = None
    usage = Usage()
    tool_calls = 0

    for _event, data in iter_sse(chunks):
        try:
            obj = json.loads(data)
        except (ValueError, UnicodeDecodeError):
            continue
        if not isinstance(obj, dict):
            continue

        candidates = obj.get("candidates")
        if isinstance(candidates, list):
            for cand in candidates:
                if not isinstance(cand, dict):
                    continue
                text_parts.append(_candidate_text(cand))
                if cand.get("finishReason") is not None:
                    finish_reason = cand.get("finishReason")
                content = cand.get("content")
                if isinstance(content, dict):
                    for part in content.get("parts") or []:
                        if isinstance(part, dict) and "functionCall" in part:
                            tool_calls += 1

        # Take the LAST usageMetadata and LAST modelVersion seen in the stream.
        usage_meta = obj.get("usageMetadata")
        if isinstance(usage_meta, dict):
            usage = _usage_from(usage_meta)

        mv = obj.get("modelVersion")
        if isinstance(mv, str):
            model = mv

    return ParsedResponse(
        model=model,
        text="".join(text_parts),
        usage=usage,
        finish_reason=finish_reason,
        tool_calls=tool_calls,
    )
