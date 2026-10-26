"""`sightline demo`: real requests through every capture path, so the dashboard is never empty.

Uses local Ollama for genuine token counts (no API keys needed), and deliberately invalid keys
against hosted providers to show capture of real provider responses (401s) without spending money.
"""

from __future__ import annotations

import json
import os

import httpx

from . import macos
from .config import Settings

FAKE_AWS = "AKIAIOSFODNN7EXAMPLE"  # AWS's documented example key


def run_demo(s: Settings) -> int:
    model = os.environ.get("SIGHTLINE_DEMO_MODEL", "gemma4:26b-mlx")
    gw = f"http://127.0.0.1:{s.gateway_port}"
    proxy = f"http://127.0.0.1:{s.proxy_port}"
    bundle = str(macos.combined_bundle(s)) if s.ca_cert.exists() else None
    tag = {"X-Sightline-Tag": "demo"}
    results = []

    def step(label, fn):
        try:
            results.append((label, fn()))
        except Exception as exc:  # noqa: BLE001 - demo keeps going and reports
            results.append((label, f"error: {exc.__class__.__name__}: {exc}"[:120]))
        print(f"  {results[-1][0]:<58} {results[-1][1]}")

    print("Sending demo traffic through Sightline…\n")
    with httpx.Client(timeout=120) as c:
        def ollama_stream(prompt):
            body = {"model": model, "stream": True, "stream_options": {"include_usage": True},
                    "messages": [{"role": "user", "content": prompt}], "max_tokens": 600}
            text = ""
            with c.stream("POST", f"{gw}/ollama/v1/chat/completions", json=body, headers=tag) as r:
                for line in r.iter_lines():
                    if line.startswith("data: {"):
                        d = json.loads(line[6:])
                        if d.get("choices"):
                            text += d["choices"][0].get("delta", {}).get("content") or ""
            return f"{r.status_code} · {len(text)} chars streamed"

        step("gateway · Ollama (OpenAI-compatible, streaming)",
             lambda: ollama_stream("In one sentence: what does an HTTP proxy do?"))
        step("gateway · Ollama with a leaked AWS key in the prompt",
             lambda: ollama_stream(f"Is this an AWS key? {FAKE_AWS} Answer yes or no."))
        step("gateway · Ollama native /api/chat",
             lambda: str(c.post(f"{gw}/ollama/api/chat", headers=tag, json={
                 "model": model, "stream": False, "messages": [{"role": "user", "content": "Say 'ready'."}],
                 "options": {"num_predict": 20}}).status_code))
        step("gateway · Anthropic (invalid key → real provider 401)",
             lambda: str(c.post(f"{gw}/anthropic/v1/messages", headers={**tag, "x-api-key": "sk-demo-invalid",
                                "anthropic-version": "2023-06-01"},
                                json={"model": "claude-sonnet-5-5", "max_tokens": 16,
                                      "messages": [{"role": "user", "content": "hi"}]}).status_code))
        step("gateway · Gemini (invalid key → real provider error)",
             lambda: str(c.post(f"{gw}/gemini/v1beta/models/gemini-3.1-flash:generateContent?key=demo-invalid",
                                headers=tag, json={"contents": [{"parts": [{"text": "hi"}]}]}).status_code))
    if bundle:
        with httpx.Client(timeout=30, proxy=proxy, verify=bundle) as p:
            step("proxy · OpenAI over decrypted HTTPS (invalid key → 401)",
                 lambda: str(p.post("https://api.openai.com/v1/chat/completions",
                                    headers={**tag, "Authorization": "Bearer sk-demo-invalid"},
                                    json={"model": "gpt-5.5-mini", "messages": [
                                        {"role": "user", "content": f"email me at jane.doe@example.com {FAKE_AWS}"}]}
                                    ).status_code))
            step("proxy · DeepSeek (blocked by example policy)",
                 lambda: str(p.post("https://api.deepseek.com/chat/completions", headers=tag,
                                    json={"model": "deepseek-chat", "messages": [{"role": "user", "content": "hi"}]}
                                    ).status_code))
    print(f"\nOpen http://127.0.0.1:{s.ui_port} to see them.")
    return 0
