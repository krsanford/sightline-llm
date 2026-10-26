"""Provider registry.

Parser modules are discovered lazily so the engine keeps working (host-level capture with a
"usage unknown" badge) while a parser is missing or broken. Order matters: first match wins.
"""

from __future__ import annotations

import importlib
import logging
import time
from types import ModuleType

log = logging.getLogger("sightline.providers")

PROVIDER_MODULES = ["anthropic", "openai", "gemini", "ollama"]

# Hosts we know are LLM APIs even when no parser exists yet (metadata-only capture).
KNOWN_HOSTS = {
    "api.openai.com": "openai",
    "api.anthropic.com": "anthropic",
    "generativelanguage.googleapis.com": "gemini",
    "127.0.0.1:11434": "ollama",
    "localhost:11434": "ollama",
    "api.mistral.ai": "mistral",
    "api.groq.com": "groq",
    "api.x.ai": "xai",
    "api.deepseek.com": "deepseek",
    "openrouter.ai": "openrouter",
    "api.together.xyz": "together",
    "api.cohere.com": "cohere",
    "api.perplexity.ai": "perplexity",
}

RETRY_S = 30.0
_loaded: dict[str, tuple[ModuleType | None, float]] = {}


def _module(name: str) -> ModuleType | None:
    """Import a parser lazily. A missing one is retried every RETRY_S seconds, so a parser added while
    Sightline is running is picked up without a restart (restarts drop in-flight streams)."""
    mod, at = _loaded.get(name, (None, 0.0))
    if mod is not None or (name in _loaded and time.monotonic() - at < RETRY_S):
        return mod
    try:
        mod = importlib.import_module(f"sightline.providers.{name}")
        if name in _loaded:
            log.info("provider parser %s loaded", name)
    except Exception as exc:  # noqa: BLE001 - a broken parser must never take the proxy down
        if name not in _loaded:
            log.warning("provider parser %s unavailable: %s", name, exc)
        mod = None
    _loaded[name] = (mod, time.monotonic())
    return mod


def available() -> list[str]:
    return [n for n in PROVIDER_MODULES if _module(n) is not None]


def resolve(host: str, path: str) -> tuple[str | None, ModuleType | None]:
    """Return (provider name, parser module) for a request, or (None, None) if not an LLM API."""
    for name in PROVIDER_MODULES:
        mod = _module(name)
        try:
            if mod is not None and mod.match(host, path):
                return name, mod
        except Exception:  # noqa: BLE001, S112
            continue
    h = host.lower()
    for key in (h, h.split(":", 1)[0]):
        if key in KNOWN_HOSTS:
            return KNOWN_HOSTS[key], None
    return None, None
