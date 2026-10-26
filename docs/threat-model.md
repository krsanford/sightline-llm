# Sightline threat model

Sightline is a local TLS-intercepting proxy with a web dashboard, installed on a company-owned Mac. That
makes it security-sensitive in two directions: it must not become a way to attack the machine, and the data it
collects (prompts sent to AI providers) must not become a liability. This document lists what we defend
against, how, and the test that proves it.

## Assets

| Asset | Why it matters |
|---|---|
| The per-install CA private key | Anyone holding it can impersonate any HTTPS site to this Mac while the CA is trusted |
| Captured prompts and responses | Routinely contain source code, customer data, credentials |
| API credentials in transit | Provider keys pass through the proxy on every call |
| The local dashboard | Reads all of the above |

## Threats and controls

| # | Threat | Control | Test |
|---|---|---|---|
| T1 | Interception spreads beyond LLM traffic (banking, health, personal sites decrypted) | mitmproxy `allow_hosts` is an anchored allowlist of LLM API hosts; everything else is tunneled byte-for-byte. The PAC file routes only those hosts to the proxy | `tests/unit/test_config.py` (lookalike hosts such as `api.openai.com.evil.tld` are not decrypted) |
| T2 | CA key theft | Generated per install, never shipped; key file `0600` inside a `0700` directory; trusted only in the *login* keychain with the SSL policy; `sightline uninstall` removes trust and deletes the key | `sightline doctor` reports key mode; uninstall path in `cli.py` |
| T3 | Credentials leak into storage | Authorization / `x-api-key` / `x-goog-api-key` headers and `?key=` parameters are reduced to a 12-character SHA-256 fingerprint; the stored path masks `key=` | `tests/unit/test_engine.py::test_credentials_are_fingerprinted_never_stored` scans the raw database file |
| T4 | Secrets and PII leak to the provider | Policy redacts secret and PII findings inside every JSON string value before the request is forwarded (or blocks, with `on_secret: block`) | `tests/unit/test_policy.py` |
| T5 | Captured text becomes a long-lived corpus | Only redacted text is stored; `capture_bodies: metadata` stores none; bodies purged after 7 days, rows after 30; DB `0600`. If the detector is unavailable, text is withheld rather than stored raw | `store.purge`, `engine._store_text` |
| T6 | A web page attacks the dashboard via DNS rebinding | Requests must carry `Host: 127.0.0.1:8898` or `localhost:8898`, else 421 | `tests/unit/test_server.py::test_rebinding_host_rejected` |
| T7 | Cross-site request forgery | Non-GET requests require our own `Origin`; no CORS headers are ever sent | `test_cross_origin_write_rejected`, `test_security_headers_and_no_cors` |
| T8 | Stored XSS via captured content (LLM output is attacker-controlled) | The UI builds DOM with `textContent` only; strict CSP (`script-src 'self'`, no inline script) | `test_ui_never_uses_html_sinks` |
| T9 | Proxy used as a pivot into local/private services | Explicit-proxy requests to loopback, private and link-local addresses are refused (403). The only private upstream is the configured Ollama, reachable solely through its dedicated listener | `test_private_upstream_refused_in_proxy_mode` |
| T10 | Network exposure | All listeners bind 127.0.0.1 | `lsof -iTCP -sTCP:LISTEN` during `sightline doctor` |
| T11 | Crash leaves the Mac without internet | PAC returns `PROXY 127.0.0.1:8899; DIRECT`; `proxy on` snapshots each network service's settings and `proxy off` / `uninstall` restore them | `test_pac_routes_only_llm_hosts_with_direct_fallback` |
| T12 | A broken parser takes down traffic | Parsers are pure and contractually non-raising; the engine wraps every parser call and stores what it can; a missing parser degrades to host-level capture | `providers/__init__.py`, `engine._safe` |
| T13 | Supply chain | Dependencies resolve with a 14-day `exclude-newer` cooldown; `mitmproxy>=12.2.3`; mitmweb is never shipped | `pyproject.toml` |

## Out of scope (tonight) and roadmap

- **Bypass by a determined user.** A local proxy is visibility, not enforcement. Enforcement needs a
  `NETransparentProxyProvider` system extension deployed by MDM, which users cannot disable.
- **Certificate-pinned or custom-root apps** cannot be decrypted. They are visible only via gateway mode.
- **Encryption at rest** for the database (Keychain-held key) is on the roadmap; tonight relies on file
  permissions, redaction-before-store and retention.
- **Name-constrained CA** (limiting the CA itself to LLM domains, so even a stolen key can't impersonate other
  sites) is on the roadmap.
- **Dashboard authentication** (token cookie) arrives with the first state-changing endpoint; today every
  endpoint is read-only and protected by T6–T8.

## Employee notice

Monitoring prompts on a company device can be regulated (for example New York Civil Rights Law §52-c requires
notice of electronic monitoring). Deploy Sightline with written notice, keep `capture_bodies` at `redacted` or
`metadata`, and keep retention short. The dashboard shows a persistent *Recording* indicator.
