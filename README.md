# Sightline

**See every LLM call your Mac makes: which app, which model, what it cost, and what leaked.**

Sightline is a local interceptor for LLM API traffic on macOS. It sits between the apps on a Mac and
hosted model APIs (OpenAI, Anthropic, Google Gemini, Azure OpenAI and more) and local Ollama. For each call it
records tokens, cost, latency and time-to-first-token, masks secrets and personal data *before* they leave
the machine, enforces simple block rules, and shows it all live in a local dashboard.

It is built for the engineer or IT lead who needs a straight answer to *"what is actually being sent to AI
providers from this company laptop, and what is it costing?"*

> **Visibility, not enforcement.** A local proxy can be bypassed by a determined user. Sightline is a
> governance and debugging tool for machines whose users have been told it is there. It is not covert monitoring.

---

## What it does

| | |
|---|---|
| **Intercept** | Explicit HTTPS proxy with selective TLS decryption (only LLM API hosts are decrypted; every other host is tunneled byte-for-byte), plus a base-URL gateway for tools that ignore proxies |
| **Meter** | Provider-reported token usage, including streaming, prompt-cache reads/writes and reasoning tokens. Cost from a local, dated price table; *shadow cost* for local models ("what this would have cost on a hosted model") |
| **Protect** | Detects API keys, tokens, private keys, JWTs, emails, phone numbers, SSNs and Luhn-valid card numbers. Masks them in the request before forwarding, and only ever stores the masked text |
| **Govern** | Block rules by provider, model or host, with reasons shown to the caller and in the UI |
| **Observe** | Live traffic table, per-call detail (conversation, usage and cost, findings, request metadata), insights by model, app and hour |

## Provider support

Generated from what is merged and passing its acceptance tests (recorded wire fixtures, streams split at every byte):

| Provider | Endpoints | Streaming usage | Cache / reasoning tokens |
|---|---|---|---|
| OpenAI (incl. Azure OpenAI) | Chat Completions, Responses, Embeddings, Models | final `usage` chunk (`stream_options.include_usage`) / `response.completed` | cached input, reasoning |
| Anthropic | Messages | `message_start` + cumulative `message_delta` | cache read and write |
| Google Gemini | `generateContent`, `streamGenerateContent` | last `usageMetadata` | cached content, thoughts |
| Ollama | `/api/chat`, `/api/generate`, OpenAI-compatible `/v1` | final NDJSON object / usage chunk | prompt cache hits; shadow cost |
| Mistral, Groq, xAI, DeepSeek, OpenRouter, Together, Cohere, Perplexity | recorded at host level (no usage yet) | | |

## Quick start

```bash
uv tool install git+https://github.com/krsanford/sightline-llm
sightline start --open            # dashboard on http://127.0.0.1:8898
```

In another terminal, pick a capture path:

```bash
# 1. Base-URL mode: no certificate needed
export OPENAI_BASE_URL=http://127.0.0.1:8897/openai/v1
export ANTHROPIC_BASE_URL=http://127.0.0.1:8897/anthropic

# 2. Proxy mode for a whole shell (Python, Node, curl, Go)
eval "$(sightline env)"

# 3. See it with real data (uses local Ollama + deliberately invalid keys, costs nothing)
sightline demo
```

For GUI and Electron apps, trust the CA and turn on the system PAC proxy. The PAC file routes *only* LLM
hosts to Sightline, and falls back to a direct connection if Sightline is not running:

```bash
sightline trust        # adds a per-install CA to your login keychain, SSL only (asks for your password)
sightline proxy on     # snapshots current proxy settings first; `sightline proxy off` restores them
sightline doctor       # sends a canary request through each client type and reports what is captured
```

Remove everything (proxy settings restored, CA untrusted and its key deleted, LaunchAgent removed, data optionally deleted):

```bash
sightline uninstall
uv tool uninstall sightline-llm
```

## How capture works on macOS

| Client | How Sightline sees it |
|---|---|
| Any SDK or CLI that accepts a base URL | Gateway mode: `http://127.0.0.1:8897/{openai,anthropic,gemini,ollama}/…` |
| Python (`httpx`, `requests`, OpenAI/Anthropic SDKs) | `HTTPS_PROXY` plus `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` pointing at a certifi + Sightline bundle (`sightline env`) |
| Node.js | `HTTPS_PROXY` + `NODE_USE_ENV_PROXY=1` + `NODE_EXTRA_CA_CERTS` (`sightline env`) |
| Safari, Chrome, Electron apps, Swift/Go clients | System PAC proxy + keychain trust (`sightline trust && sightline proxy on`) |
| Apps that pin certificates or bundle their own roots | Not decryptable. Use gateway mode if the app allows a base URL |

The fleet-grade path (a `NETransparentProxyProvider` system extension deployed by MDM) is on the roadmap.

## Privacy and security posture

- **Decrypts only an anchored allowlist of LLM API hosts.** `api.openai.com.evil.tld` does not match.
  Everything else that reaches the proxy is tunneled without decryption.
- **Never stores credentials.** Authorization headers and API keys are reduced to a 12-character SHA-256
  fingerprint, so you can tell keys apart without keeping them.
- **Redacts before storing, and before forwarding.** Prompts and responses are stored only after redaction.
  `capture_bodies: metadata` stores no text at all. Bodies are purged after 7 days, metadata after 30.
- **Per-install, name-constrained CA.** The certificate carries critical X.509 name constraints for the LLM API
  domains only, so even a stolen key can't impersonate your bank. Private key `0600`, trusted in the *login*
  keychain for SSL only. `uninstall` removes both.
- **Local-only dashboard.** Bound to 127.0.0.1. Requests with an unexpected `Host` get 421 (DNS-rebinding
  defence), cross-origin writes are refused, a strict CSP forbids inline script, and every captured string is
  rendered as text. Prompts and responses are treated as attacker-controlled content.
- **The proxy refuses private upstreams**, so it cannot be used as a bridge into local services.

See [docs/threat-model.md](docs/threat-model.md) for each threat, its control and the test that proves it.

## Configuration

`~/Library/Application Support/Sightline/` holds `config.yaml` (ports, capture mode, retention),
`policy.yaml` (redaction and block rules), the database and the CA.

```yaml
# policy.yaml
redact:
  categories: [secret, pii]
  on_secret: redact        # or: block
block:
  - {provider: deepseek, reason: "Provider not approved for company data"}
  - {model: "gpt-6-astra*", reason: "Use gpt-6-sol for routine work"}
```

Prices live in [`src/sightline/pricing.yaml`](src/sightline/pricing.yaml): USD per million tokens, first match
wins, dated and approximate. Edit it to match your contracts.

## Development

```bash
uv sync
uv run pytest                 # unit + acceptance tests
uv run sightline start
```

Provider parsers are pure functions behind one small contract ([`providers/base.py`](src/sightline/providers/base.py)),
tested against recorded wire fixtures, including streams split at every byte boundary.

## How this was built

Sightline was the first project of **foundry** (repository currently private), a sandboxed dev swarm of
local models running on Ollama. Leaf modules (price calculator, provider parsers, detectors, tests) were
implemented by local agents, held to read-only acceptance tests, and gated mechanically before an integrator
merged them. Commits carry `Swarm-Role` / `Swarm-Model` trailers so you can see exactly which code came from
the swarm.

## License

MIT
