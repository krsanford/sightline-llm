"""Follow-up: bare 9-digit numbers (order ids, ticket numbers) must not be flagged as SSNs."""
from sightline.detect import scan


def kinds(text):
    return [f.kind for f in scan(text)]


def test_formatted_ssn_still_detected():
    assert "ssn" in kinds("SSN 123-45-6789 on file")
    assert "ssn" in kinds("ssn: 123 45 6789")


def test_bare_nine_digit_numbers_are_not_ssns():
    for text in ["order 123456789 shipped", "ticket #987654321", "id=555443333", "build 202610261"]:
        assert "ssn" not in kinds(text), text


def test_invalid_ssn_groups_rejected():
    for text in ["000-12-3456", "666-12-3456", "900-12-3456", "123-00-4567", "123-45-0000"]:
        assert "ssn" not in kinds(text), text


def test_valid_groups_with_zero_digits_still_detected():
    # Only group 00 and serial 0000 are invalid; 10, 20, 1000, 0001 etc. are valid.
    for text in ["123-10-4567", "123-20-4567", "123-45-1000", "123-45-0001", "234 50 6789"]:
        assert "ssn" in kinds(text), text
