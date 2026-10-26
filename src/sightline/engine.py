"""The interception engine: a mitmproxy addon that classifies, polices, meters and records LLM calls.

Two listeners share this addon:
- **proxy mode** (``regular@proxy_port``): an explicit HTTPS proxy. mitmproxy only decrypts hosts
  matching ``ALLOW_HOSTS_RE``; everything else is tunneled untouched and never reaches these hooks.
- **gateway mode** (``reverse@gateway_port``): base-URL mode for clients that ignore proxies.
  ``http://127.0.0.1:8897/openai/v1/...`` is routed to ``https://api.openai.com/v1/...`` and so on.

Streaming responses are teed, not buffered: bytes go to the client as they arrive and a copy is
parsed when the stream ends, so Sightline adds no time-to-first-token.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import logging
import time
from urllib.parse import parse_qsl, urlencode, urlsplit

from mitmproxy import http

from . import providers
from .config import GATEWAY_ROUTES, Settings
from .policy import Policy, redact_text
from .pricing import PriceTable
from .providers.base import ParsedRequest, ParsedResponse, Usage, load_json
from .store import Call, Store

log = logging.getLogger("sightline.engine")

AUTH_HEADERS = ("authorization", "x-api-key", "x-goog-api-key", "api-key")
STREAM_TYPES = ("text/event-stream", "application/x-ndjson", "application/jsonl")
# Not LLM usage: model lists, metadata and health checks that harnesses poll between turns.
CONTROL_PATHS = ("/models", "/api/tags", "/api/show", "/api/version", "/api/ps", "/props", "/version")
MAX_TEXT = 20_000


class Bus:
    """In-process fan-out of new calls to live UI subscribers (same asyncio loop as the proxy)."""

    def __init__(self) -> None:
        self.subscribers: set[asyncio.Queue] = set()

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=500)
        self.subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self.subscribers.discard(q)

    def publish(self, item: dict) -> None:
        for q in list(self.subscribers):
            try:
                q.put_nowait(item)
            except asyncio.QueueFull:
                pass


def client_name(user_agent: str | None) -> str | None:
    if not user_agent:
        return None
    first = user_agent.split()[0]
    return first.split("/")[0][:40] or None


def _is_private(host: str) -> bool:
    if host in ("localhost", "localhost.localdomain"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private or ip.is_link_local


class SightlineAddon:
    def __init__(self, settings: Settings, store: Store, policy: Policy, prices: PriceTable, bus: Bus):
        self.settings = settings
        self.store = store
        self.policy = policy
        self.prices = prices
        self.bus = bus

    # ------------------------------------------------------------------ routing

    def _gateway_route(self, flow: http.HTTPFlow) -> bool:
        """Rewrite a gateway-mode request to its upstream. Returns False if the prefix is unknown."""
        parts = flow.request.path.split("/", 2)       # ["", "openai", "v1/chat/completions?..."]
        prefix = parts[1] if len(parts) > 1 else ""
        if prefix not in GATEWAY_ROUTES:
            return False
        scheme, host, port = GATEWAY_ROUTES[prefix]
        if prefix == "ollama":
            host, port = self.settings.ollama_upstream
        flow.request.scheme, flow.request.host, flow.request.port = scheme, host, port
        flow.request.path = "/" + (parts[2] if len(parts) > 2 else "")
        # Ollama rejects unfamiliar Host headers (DNS-rebinding guard); present as localhost.
        flow.request.headers["host"] = "localhost:11434" if prefix == "ollama" else host
        return True

    @staticmethod
    def _mode(flow: http.HTTPFlow) -> str:
        mode = getattr(flow.client_conn, "proxy_mode", None)
        return "gateway" if mode is not None and getattr(mode, "type_name", "") == "reverse" else "proxy"

    # ------------------------------------------------------------------ hooks

    def request(self, flow: http.HTTPFlow) -> None:
        mode = self._mode(flow)
        pm = getattr(flow.client_conn, "proxy_mode", None)
        log.debug("request mode=%s pm=%r host=%s port=%s path=%s", mode, pm, flow.request.host, flow.request.port,
                  flow.request.path)
        if mode == "gateway" and str(getattr(pm, "data", "")).endswith(f":{self.settings.ollama_upstream[1]}"):
            # Transparent Ollama listener: same paths as Ollama, so it can sit in front of Ollama for any client
            # (and an nginx `backup` upstream can fail over to Ollama directly if Sightline is down).
            flow.request.scheme = "http"
            flow.request.host, flow.request.port = self.settings.ollama_upstream
            flow.request.headers["host"] = "localhost:11434"
            if self.settings.allow_models and flow.request.method == "POST":
                # Fail closed: unparseable bodies, a missing model, or several case-variants of the key (Ollama's
                # JSON decoder matches keys case-insensitively, so {"Model": ...} would otherwise slip through).
                doc = load_json(flow.request.get_content(strict=False) or b"")
                models = [v for k, v in (doc or {}).items() if k.lower() == "model"]
                model = models[0] if len(models) == 1 and isinstance(models[0], str) else None
                if model not in self.settings.allow_models:
                    flow.response = http.Response.make(
                        403, json.dumps({"error": f"model {model!r} is not allowed on this listener"}),
                        {"content-type": "application/json", "x-sightline": "model-not-allowed"})
                    return
        elif mode == "gateway":
            if not self._gateway_route(flow):
                flow.response = http.Response.make(
                    404, json.dumps({"error": "unknown Sightline gateway route; use /openai, /anthropic, "
                                              "/gemini or /ollama"}), {"content-type": "application/json"})
                return
        elif _is_private(flow.request.host):
            # The explicit proxy must not become a bridge into local/private services.
            flow.response = http.Response.make(403, b"Sightline proxy refuses private upstreams",
                                               {"content-type": "text/plain"})
            return

        host = flow.request.host
        hostport = host if flow.request.port in (80, 443) else f"{host}:{flow.request.port}"
        path_only = urlsplit(flow.request.path).path
        name, mod = providers.resolve(hostport, path_only)
        if name is None:
            return  # not an LLM API: pass through unrecorded

        # Identify the credential without keeping it; strip key-in-query (Gemini) from what we store.
        secret = next((flow.request.headers.get(h) for h in AUTH_HEADERS if flow.request.headers.get(h)), None)
        query = dict(parse_qsl(urlsplit(flow.request.path).query))
        if not secret and "key" in query:
            secret = query["key"]
        safe_query = urlencode({k: ("***" if k == "key" else v) for k, v in query.items()})
        tag = flow.request.headers.pop("x-sightline-tag", None)
        flow.request.headers["accept-encoding"] = "identity"   # keep streamed bytes parseable

        body = flow.request.get_content(strict=False) or b""
        parsed = _safe(lambda: mod.parse_request(path_only, body), ParsedRequest(provider=name)) if mod \
            else ParsedRequest(provider=name)
        decision = self.policy.evaluate(name, parsed.model, host, body)

        call = Call(mode=mode, client=client_name(flow.request.headers.get("user-agent")), provider=name,
                    host=host, method=flow.request.method, path=path_only + (f"?{safe_query}" if safe_query else ""),
                    endpoint=parsed.endpoint, model=parsed.model, stream=parsed.stream, action=decision.action,
                    reasons=decision.reasons, findings=decision.findings,
                    key_fp=hashlib.sha256(secret.encode()).hexdigest()[:12] if secret else None,
                    tag=tag, req_bytes=len(body))
        call.prompt = _store_text(parsed.prompt_text())
        flow.metadata["sightline"] = {"call": call, "mod": mod, "parsed": parsed, "t0": time.monotonic(),
                                      "chunks": [], "first": None}

        if decision.action == "blocked":
            flow.response = _blocked_response(name, decision.reasons[0])
        elif decision.action == "redacted" and decision.body is not None:
            flow.request.set_content(decision.body)

    def responseheaders(self, flow: http.HTTPFlow) -> None:
        st = flow.metadata.get("sightline")
        if not st or flow.response is None:
            return
        ctype = flow.response.headers.get("content-type", "")
        if any(t in ctype for t in STREAM_TYPES):
            def tap(data: bytes) -> bytes:
                if data:
                    if st["first"] is None:
                        st["first"] = time.monotonic()
                    st["chunks"].append(data)
                return data
            flow.response.stream = tap

    def response(self, flow: http.HTTPFlow) -> None:
        st = flow.metadata.pop("sightline", None)
        if not st:
            return
        call: Call = st["call"]
        now = time.monotonic()
        call.status = flow.response.status_code if flow.response else None
        call.latency_ms = round((now - st["t0"]) * 1000, 1)
        mod = st["mod"]
        if st["chunks"]:
            call.ttft_ms = round((st["first"] - st["t0"]) * 1000, 1)
            call.resp_bytes = sum(len(c) for c in st["chunks"])
            parsed = _safe(lambda: mod.parse_stream(st["chunks"]), ParsedResponse()) if mod else ParsedResponse()
        else:
            content = (flow.response.get_content(strict=False) or b"") if flow.response else b""
            call.resp_bytes = len(content)
            path_only = urlsplit(flow.request.path).path
            parsed = _safe(lambda: mod.parse_response(path_only, content), ParsedResponse()) \
                if (mod and call.action != "blocked") else ParsedResponse()
        self._finish(call, st["parsed"], parsed, parsed=mod is not None)

    def error(self, flow: http.HTTPFlow) -> None:
        st = flow.metadata.pop("sightline", None)
        if not st:
            return
        call: Call = st["call"]
        call.latency_ms = round((time.monotonic() - st["t0"]) * 1000, 1)
        call.error = str(flow.error)[:500] if flow.error else "connection error"
        self._finish(call, st["parsed"], ParsedResponse(), parsed=st["mod"] is not None)

    # ------------------------------------------------------------------ bookkeeping

    def _finish(self, call: Call, req: ParsedRequest, resp: ParsedResponse, parsed: bool = True) -> None:
        # Control-plane calls (model lists, /api/show, version checks) are not LLM usage; keep them out of the
        # traffic table unless something notable happened (blocked, error, non-2xx).
        if ((call.path or "").split("?")[0].endswith(CONTROL_PATHS) and call.action == "allowed" and not call.error
                and (call.status or 0) < 400):
            return
        call.model = resp.model or call.model
        u: Usage = resp.usage
        if u.source != "none":
            call.input_tokens, call.output_tokens = u.input_tokens, u.output_tokens
            call.cache_read, call.cache_write, call.reasoning = u.cache_read_tokens, u.cache_write_tokens, \
                u.reasoning_tokens
            cost = self.prices.cost(call.provider or "", call.model, u)
            call.usd, call.shadow_usd = cost.usd, cost.shadow_usd
        call.usage_source = u.source
        call.response = _store_text(resp.text)
        if resp.error and not call.error:
            call.error = resp.error[:500]
        try:
            call_id = self.store.insert(call)
        except Exception:  # noqa: BLE001 - never break the client's request over bookkeeping
            log.exception("failed to store call")
            return
        row = self.store.list(limit=1, since_id=call_id - 1)
        if row:
            self.bus.publish(row[0])


def _safe(fn, default):
    try:
        return fn()
    except Exception:  # noqa: BLE001 - parsers are contractually non-raising; belt and braces
        log.exception("parser raised")
        return default


def _store_text(text: str | None) -> str | None:
    if not text:
        return None
    red = redact_text(text)
    if red is text and text:  # detector unavailable → never store raw text
        from .policy import _detector
        if _detector() is None:
            return "[withheld: detector unavailable]"
    return red[:MAX_TEXT]


def _blocked_response(provider: str, reason: str) -> http.Response:
    msg = f"Blocked by Sightline policy: {reason}"
    if provider == "anthropic":
        body = {"type": "error", "error": {"type": "permission_error", "message": msg}}
    else:
        body = {"error": {"message": msg, "type": "sightline_policy", "code": "blocked"}}
    return http.Response.make(403, json.dumps(body), {"content-type": "application/json",
                                                      "x-sightline": "blocked"})
