"""S9: decryption scope is an anchored allowlist."""
import pytest

from sightline.config import is_decrypt_host


@pytest.mark.parametrize("host", ["api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com",
                                  "myco-eastus.openai.azure.com", "api.mistral.ai", "openrouter.ai"])
def test_llm_hosts_are_decrypted(host):
    assert is_decrypt_host(host)


@pytest.mark.parametrize("host", ["api.openai.com.evil.tld", "evilapi.openai.com.attacker.io", "xapi.openai.com",
                                  "openai.com", "www.google.com", "chatgpt.com", "claude.ai", "bank.example.com",
                                  "a.b.openai.azure.com.evil", "api.anthropic.com:8443"])
def test_everything_else_is_tunneled(host):
    h, _, p = host.partition(":")
    assert not is_decrypt_host(h, int(p) if p else 443)
