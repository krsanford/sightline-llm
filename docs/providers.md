## OpenAI (including Azure)

Supports OpenAI Chat Completions, Responses API, and Azure OpenAI deployments.

| Feature | Details |
| --- | --- |
| **Hosts Matched** | `api.openai.com` or `*.openai.azure.com` |
| **Endpoints** | `chat` (/chat/completions), `responses` (/responses), `embeddings` (/embeddings), `models` (/models) |
| **Streaming** | Auto-detects Chat Completions vs. Responses API via event names and JSON `type`. |
| **Token Usage** | `input_tokens` is pulled from `prompt_tokens` or `input_tokens`. `cache_read_tokens` is from `input_tokens_details` or `prompt_tokens_details`. `reasoning_tokens` is pulled from `output_tokens_details`. |
| **Limitations** | |

## Anthropic

Supports the Anthropic Messages API.

| Feature | Details |
| --- | --- |
| **Hosts Matched** | `api.anthropic.com` |
| **Endpoints** | `messages` (/v1/messages) |
| **Streaming** | Parses SSE events like `message_start`, `content_block_delta`, and `message_delta`. |
| **Token Usage** | `input_tokens` is a sum of `input_tokens` + `cache_read_input_tokens` + `cache_creation_input_tokens`. `output_tokens` is extracted from `message_delta` events. |
| **Limitations** | |

## Adding a Provider

New providers must implement the contract defined in `src/sightline/providers/base.py`. Every provider module must expose these four functions:

1. `match(host: str, path: str) -> bool`: Returns `True` if the host and request path belong to this provider.
2. `parse_request(path: str, body: bytes) -> ParsedRequest`: Converts a raw request body into a structured `ParsedRequest`.
3. `parse_response(path: str, body: bytes) -> ParsedResponse`: Converts a non-streaming JSON response into a `ParsedResponse`.
4. `parse_stream(chunks: Iterable[bytes]) -> ParsedResponse`: Processes a stream of raw bytes (e.g., SSE) into a complete `ParsedResponse`.

Parsers should be pure functions and must handle malformed input gracefully by returning a `ParsedResponse` or `ParsedRequest` with a descriptive `error` field rather than raising exceptions.
