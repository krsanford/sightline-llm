from sightline.detect import redact, scan

TEXT = (
    "Contact jane.doe@example.com or (415) 555-0132. SSN 123-45-6789. "
    "Card 4111 1111 1111 1111, bad card 4111 1111 1111 1112. "
    "AWS AKIAIOSFODNN7EXAMPLE, gh ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij, "
    "openai sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCD, "
    "anthropic sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789-ABCDEFG, "
    "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U "
    "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----"
)


def kinds(findings):
    return sorted({f.kind for f in findings})


def test_detects_all_kinds():
    k = kinds(scan(TEXT))
    for want in ["aws_access_key", "credit_card", "email", "github_token", "jwt", "openai_key",
                 "anthropic_key", "phone", "private_key", "ssn"]:
        assert want in k, want


def test_luhn_rejects_invalid_card():
    cards = [f for f in scan(TEXT) if f.kind == "credit_card"]
    assert len(cards) == 1 and cards[0].value.replace(" ", "") == "4111111111111111"


def test_findings_have_spans_and_categories():
    for f in scan(TEXT):
        assert TEXT[f.start:f.end] == f.value
        assert f.category in ("pii", "secret")
    assert {f.category for f in scan("AKIAIOSFODNN7EXAMPLE")} == {"secret"}
    assert {f.category for f in scan("bob@corp.io")} == {"pii"}


def test_redact_masks_but_keeps_hint():
    out, findings = redact(TEXT)
    assert "AKIAIOSFODNN7EXAMPLE" not in out and "jane.doe@example.com" not in out
    assert "4111 1111 1111 1111" not in out
    assert "[REDACTED:aws_access_key]" in out and "[REDACTED:email]" in out
    assert "4111 1111 1111 1112" in out  # invalid Luhn untouched
    assert len(findings) >= 10


def test_redact_categories_filter():
    out, findings = redact(TEXT, categories={"secret"})
    assert "jane.doe@example.com" in out and "AKIAIOSFODNN7EXAMPLE" not in out
    assert all(f.category == "secret" for f in findings)


def test_clean_text_and_no_false_positive_on_versions():
    assert scan("Upgrade to version 1.2.3.4 on port 8080, build 20261026.") == []
    out, f = redact("nothing here")
    assert out == "nothing here" and f == []
