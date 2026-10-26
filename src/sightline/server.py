"""Local dashboard + JSON API + PAC file. Bound to 127.0.0.1 only.

Browser threats to a localhost dashboard are DNS rebinding and cross-site requests, so every
request must carry an expected Host header (421 otherwise), state-changing requests must come
from our own Origin, no CORS headers are ever sent, and a strict CSP forbids inline script.
The UI renders all captured content with textContent: prompts and responses are attacker data.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from . import __version__, providers
from .config import DECRYPT_HOSTS, Settings
from .engine import Bus
from .policy import Policy
from .store import Store

WEB = Path(__file__).with_name("web")
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
WINDOWS = {"1h": 3600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400}


def create_app(settings: Settings, store: Store, policy: Policy, bus: Bus) -> FastAPI:
    app = FastAPI(title="Sightline", docs_url=None, redoc_url=None, openapi_url=None)
    allowed_hosts = {f"127.0.0.1:{settings.ui_port}", f"localhost:{settings.ui_port}"}
    allowed_origins = {f"http://{h}" for h in allowed_hosts}
    started = time.time()

    @app.middleware("http")
    async def guard(request: Request, call_next):
        if request.headers.get("host") not in allowed_hosts:
            return PlainTextResponse("Misdirected request", status_code=421)
        origin = request.headers.get("origin")
        if request.method not in ("GET", "HEAD", "OPTIONS") and origin not in allowed_origins:
            return PlainTextResponse("Cross-origin request refused", status_code=403)
        if request.method == "OPTIONS":
            return Response(status_code=405)
        resp = await call_next(request)
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    app.mount("/static", StaticFiles(directory=WEB), name="static")

    @app.get("/")
    async def index():
        return FileResponse(WEB / "index.html")

    @app.get("/api/health")
    async def health():
        return {"ok": True, "version": __version__, "uptime_s": round(time.time() - started)}

    @app.get("/api/calls")
    async def calls(limit: int = 200, provider: str | None = None, since_id: int = 0):
        return store.list(limit=limit, provider=provider, since_id=since_id)

    @app.get("/api/calls/{call_id}")
    async def call(call_id: int):
        row = store.get(call_id)
        if not row:
            raise HTTPException(404)
        return row

    @app.get("/api/stats")
    async def stats(window: str = "24h"):
        return store.stats(time.time() - WINDOWS.get(window, 86400))

    @app.get("/api/insights")
    async def insights(window: str = "24h"):
        return store.insights(time.time() - WINDOWS.get(window, 86400))

    @app.get("/api/setup")
    async def setup():
        ca = settings.ca_cert
        return {
            "version": __version__,
            "ports": {"proxy": settings.proxy_port, "gateway": settings.gateway_port, "ui": settings.ui_port},
            "ca": {"path": str(ca), "exists": ca.exists(), "key_mode": _mode(settings.certs_dir / "mitmproxy-ca.pem")},
            "decrypt_hosts": [h.replace("\\", "") for h in DECRYPT_HOSTS],
            "parsers": providers.available(),
            "policy": policy.to_dict(),
            "capture_bodies": settings.capture_bodies,
            "retention": {"bodies_days": settings.body_retention_days,
                          "metadata_days": settings.metadata_retention_days},
            "db": {"path": str(settings.db_path), "mode": _mode(settings.db_path)},
            "never_stored": ["API keys and Authorization headers (only a 12-char SHA-256 fingerprint)",
                             "Unredacted prompt or response text",
                             "Traffic to any host outside the decrypt list (tunneled, never decrypted)"],
        }

    @app.get("/proxy.pac")
    async def pac():
        hosts = ["api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com", "api.mistral.ai",
                 "api.groq.com", "api.x.ai", "api.deepseek.com", "openrouter.ai", "api.together.xyz"]
        cond = " ||\n      ".join(f'host == "{h}"' for h in hosts)
        body = ("function FindProxyForURL(url, host) {\n"
                f"  if ({cond} ||\n      shExpMatch(host, \"*.openai.azure.com\"))\n"
                f"    return \"PROXY 127.0.0.1:{settings.proxy_port}; DIRECT\";\n"
                "  return \"DIRECT\";\n}\n")
        return Response(body, media_type="application/x-ns-proxy-autoconfig")

    @app.get("/api/events")
    async def events(request: Request):
        q = bus.subscribe()

        async def gen():
            try:
                yield "retry: 2000\n\n"
                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        item = await asyncio.wait_for(q.get(), timeout=15)
                        yield f"event: call\ndata: {json.dumps(item)}\n\n"
                    except TimeoutError:
                        yield ": keepalive\n\n"
            finally:
                bus.unsubscribe(q)

        return StreamingResponse(gen(), media_type="text/event-stream")

    @app.exception_handler(HTTPException)
    async def http_exc(_request, exc):
        return JSONResponse({"error": exc.detail or exc.status_code}, status_code=exc.status_code)

    return app


def _mode(path: Path) -> str | None:
    try:
        return oct(path.stat().st_mode & 0o777)
    except FileNotFoundError:
        return None
