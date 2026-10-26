"""Runtime configuration: where data lives, which ports, which hosts get decrypted."""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

# Only these hosts are ever decrypted. Everything else that reaches the proxy is tunneled
# byte-for-byte. Anchored on both ends: "api.openai.com.evil.tld" does NOT match.
DECRYPT_HOSTS = [
    r"api\.openai\.com",
    r"api\.anthropic\.com",
    r"generativelanguage\.googleapis\.com",
    r"[a-z0-9-]+\.openai\.azure\.com",
    r"api\.mistral\.ai",
    r"api\.groq\.com",
    r"api\.x\.ai",
    r"api\.deepseek\.com",
    r"openrouter\.ai",
    r"api\.together\.xyz",
]
ALLOW_HOSTS_RE = r"^(" + "|".join(DECRYPT_HOSTS) + r")(:443)?$"

# Gateway (base-URL) mode: http://127.0.0.1:<gateway_port>/<prefix>/... → upstream
GATEWAY_ROUTES = {
    "openai": ("https", "api.openai.com", 443),
    "anthropic": ("https", "api.anthropic.com", 443),
    "gemini": ("https", "generativelanguage.googleapis.com", 443),
    "ollama": ("http", "127.0.0.1", 11434),
}


def default_home() -> Path:
    if env := os.environ.get("SIGHTLINE_HOME"):
        return Path(env).expanduser()
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Sightline"
    return Path.home() / ".sightline"


@dataclass
class Settings:
    home: Path = field(default_factory=default_home)
    proxy_port: int = 8899      # explicit HTTPS proxy (HTTPS_PROXY / PAC)
    gateway_port: int = 8897    # base-URL mode, plain HTTP on loopback
    ui_port: int = 8898         # dashboard + API + proxy.pac
    ollama_port: int = 8896     # transparent Ollama passthrough (same paths as Ollama itself)
    capture_bodies: str = "redacted"   # "redacted" | "metadata" (no bodies at all)
    body_retention_days: int = 7
    metadata_retention_days: int = 30
    ollama_upstream: tuple[str, int] = ("127.0.0.1", 11434)
    # Models the transparent Ollama listener will forward. Empty = allow all. Anything else gets 403, so a sandboxed
    # agent can't load a third model (evicting the lanes' caches) or reach an Ollama cloud model.
    allow_models: list[str] = field(default_factory=list)

    @property
    def db_path(self) -> Path:
        return self.home / "sightline.db"

    @property
    def certs_dir(self) -> Path:
        return self.home / "certs"

    @property
    def ca_cert(self) -> Path:
        return self.certs_dir / "mitmproxy-ca-cert.pem"

    @property
    def policy_path(self) -> Path:
        return self.home / "policy.yaml"

    def ensure(self) -> Settings:
        self.home.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.certs_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        return self

    @classmethod
    def load(cls) -> Settings:
        s = cls()
        cfg = s.home / "config.yaml"
        if cfg.exists():
            data = yaml.safe_load(cfg.read_text()) or {}
            for k, v in data.items():
                if k in cls.__dataclass_fields__ and k != "home":
                    setattr(s, k, v)
        return s


def is_decrypt_host(host: str, port: int = 443) -> bool:
    return re.match(ALLOW_HOSTS_RE, f"{host}:{port}") is not None
