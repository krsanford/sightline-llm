"""Acceptance for the provider reference: it exists and covers each provider and the parser contract."""
from pathlib import Path

DOC = Path(__file__).resolve().parent.parent / "docs" / "providers.md"


def text():
    return DOC.read_text().lower()


def test_doc_exists_and_is_substantial():
    assert DOC.exists() and len(DOC.read_text()) > 1500


def test_covers_each_provider():
    for name in ("openai", "azure", "anthropic", "gemini"):
        assert name in text(), name


def test_explains_the_parser_contract():
    for fn in ("match", "parse_request", "parse_response", "parse_stream"):
        assert fn in text(), fn
