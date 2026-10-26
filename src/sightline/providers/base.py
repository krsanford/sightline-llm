"""Provider contract shared by every parser module.

A provider module (``openai.py``, ``anthropic.py`` ...) exposes four functions:

    match(host: str, path: str) -> bool
    parse_request(path: str, body: bytes) -> ParsedRequest
    parse_response(path: str, body: bytes) -> ParsedResponse          # non-streaming JSON
    parse_stream(chunks: Iterable[bytes]) -> ParsedResponse           # streaming body, raw bytes

Parsers must never raise on malformed input: return a best-effort object and put a
short description in ``error``. They are pure functions (no I/O, no globals mutated),
which is what makes them safe to fuzz and cheap to test against recorded fixtures.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass, field
from typing import Literal

UsageSource = Literal["reported", "estimated", "none"]
EndpointKind = Literal["chat", "responses", "messages", "embeddings", "generate", "models", "other"]


@dataclass
class Usage:
    """Token counts, normalized across providers.

    ``input_tokens`` is the FULL prompt size including cached tokens (OpenAI/Gemini/Ollama
    semantics). Anthropic reports uncached input separately, so its parser must add
    ``cache_read_input_tokens`` and ``cache_creation_input_tokens`` into ``input_tokens``.
    ``cache_read_tokens``/``cache_write_tokens`` are the subsets of ``input_tokens`` served
    from / written to the prompt cache. ``reasoning_tokens`` is a subset of ``output_tokens``.
    """

    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    reasoning_tokens: int = 0
    source: UsageSource = "none"

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


@dataclass
class Message:
    role: str
    text: str


@dataclass
class ParsedRequest:
    provider: str
    endpoint: EndpointKind = "other"
    model: str | None = None
    stream: bool = False
    system: str | None = None
    messages: list[Message] = field(default_factory=list)
    tool_count: int = 0
    max_tokens: int | None = None
    error: str | None = None

    def prompt_text(self) -> str:
        """All human-authored text in the request, for scanning and display."""
        parts = [self.system] if self.system else []
        parts += [m.text for m in self.messages if m.text]
        return "\n\n".join(parts)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ParsedResponse:
    model: str | None = None
    text: str = ""
    usage: Usage = field(default_factory=Usage)
    finish_reason: str | None = None
    tool_calls: int = 0
    error: str | None = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["usage"]["total_tokens"] = self.usage.total_tokens
        return d


def iter_sse(chunks: Iterable[bytes]) -> Iterator[tuple[str | None, str]]:
    """Yield ``(event, data)`` pairs from a server-sent-events byte stream.

    Handles events split across arbitrary chunk boundaries, CRLF line endings and
    multi-line ``data:`` fields. Comment lines (``:``) are skipped.
    """
    buf = b""
    event: str | None = None
    data: list[str] = []
    for chunk in chunks:
        buf += chunk
        while True:
            nl = buf.find(b"\n")
            if nl < 0:
                break
            line = buf[:nl].rstrip(b"\r").decode("utf-8", "replace")
            buf = buf[nl + 1 :]
            if line == "":
                if data:
                    yield event, "\n".join(data)
                event, data = None, []
            elif line.startswith(":"):
                continue
            elif line.startswith("event:"):
                event = line[6:].strip()
            elif line.startswith("data:"):
                data.append(line[5:].lstrip(" "))
    tail = buf.decode("utf-8", "replace").strip()
    if tail.startswith("data:"):
        data.append(tail[5:].lstrip(" "))
    if data:
        yield event, "\n".join(data)


def iter_ndjson(chunks: Iterable[bytes]) -> Iterator[dict]:
    """Yield JSON objects from a newline-delimited JSON stream (Ollama native API)."""
    buf = b""
    for chunk in chunks:
        buf += chunk
        *lines, buf = buf.split(b"\n")
        for line in lines:
            obj = _loads(line)
            if isinstance(obj, dict):
                yield obj
    obj = _loads(buf)
    if isinstance(obj, dict):
        yield obj


def load_json(body: bytes) -> dict | None:
    obj = _loads(body)
    return obj if isinstance(obj, dict) else None


def _loads(raw: bytes):
    raw = raw.strip()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return None


def content_to_text(content) -> str:
    """Flatten the many shapes of message ``content`` into plain text.

    Accepts a string, a list of parts (``{"type": "text", "text": ...}``,
    ``{"type": "input_text", ...}``, Gemini ``{"text": ...}``), or None.
    Non-text parts (images, audio, tool results without text) become ``[image]`` etc.
    """
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, dict):
        content = [content]
    out: list[str] = []
    if isinstance(content, list):
        for part in content:
            if isinstance(part, str):
                out.append(part)
            elif isinstance(part, dict):
                if isinstance(part.get("text"), str):
                    out.append(part["text"])
                elif isinstance(part.get("content"), (str, list)):
                    out.append(content_to_text(part["content"]))
                elif "type" in part:
                    out.append(f"[{part['type']}]")
    return "\n".join(p for p in out if p)
