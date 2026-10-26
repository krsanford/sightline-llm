from pathlib import Path

import pytest

FIX = Path(__file__).resolve().parent.parent / "tests" / "fixtures"


@pytest.fixture
def fx():
    def load(name: str) -> bytes:
        return (FIX / name).read_bytes()
    return load


def chunked(data: bytes, size: int = 7):
    """Split bytes at awkward boundaries to prove parsers buffer correctly."""
    return [data[i : i + size] for i in range(0, len(data), size)]
