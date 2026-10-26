"""Follow-up (dogfooding finding): Unix timestamps and other bare 10-digit numbers are not phone numbers."""
from sightline.detect import scan


def kinds(text):
    return [f.kind for f in scan(text)]


def test_formatted_phones_still_detected():
    for text in ["call (415) 555-0132", "415-555-0132", "415.555.0132", "+1 415 555 0132"]:
        assert "phone" in kinds(text), text


def test_bare_ten_digit_numbers_are_not_phones():
    for text in ['"created":1792988618', "ts=1792988618", "order 4155550132", "id 1234567890 done"]:
        assert "phone" not in kinds(text), text


def test_other_detectors_unchanged():
    assert "email" in kinds("mail jane.doe@example.com")
    assert "ssn" in kinds("SSN 123-45-6789")


def test_whole_phone_number_is_redacted():
    from sightline.detect import redact
    for text in ["call (415) 555-0132 now", "call (415)555-0132 now", "call 415-555-0132 now",
                 "call +1 415 555 0132 now", "call 415.555.0132 now", "call +1 (415) 555-0132 now"]:
        out, _ = redact(text)
        assert out == "call [REDACTED:phone] now", (text, out)
