"""Secret and PII detector with redaction.

Scans free text for secrets (API keys, tokens, private keys, JWTs) and PII
(emails, US phone numbers, US SSNs, credit card numbers) and masks each hit with
a ``[REDACTED:<kind>]`` placeholder. This is what lets Sightline mask a leaked
AWS key before a prompt reaches a model provider or the local database.

The module is pure: it does no I/O, holds no global state, and uses only the
standard-library ``re`` module for matching.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #

# Kinds grouped by category so callers can redact, say, only secrets.
_SECRET_KINDS = frozenset(
    {"aws_access_key", "github_token", "openai_key", "anthropic_key", "jwt", "private_key"}
)
_PII_KINDS = frozenset({"email", "phone", "ssn", "credit_card"})


@dataclass(frozen=True)
class Finding:
    """One detected secret or PII span.

    ``start``/``end`` are offsets in the scanned text such that
    ``text[start:end] == value``.
    """

    kind: str
    category: str
    start: int
    end: int
    value: str


# --------------------------------------------------------------------------- #
# Patterns
#
# The regexes below are deliberately conservative. They err toward false
# negatives (missing a secret) rather than false positives (flagging a version
# string, a port or a date), because a false positive erodes trust faster than a
# miss. Order matters: more specific patterns are tried before more general ones.
# --------------------------------------------------------------------------- #

# AWS access key id: literal "AKIA" followed by 16 uppercase alphanumerics.
_AWS = re.compile(r"AKIA[0-9A-Z]{16}")

# GitHub token: "gh" + one of p/o/u/r + "_" + >=36 alphanumerics.
_GITHUB = re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")

# Anthropic key: "sk-ant-" + >=20 mixed alphanumerics/hyphens. Checked *before*
# OpenAI because both start "sk-" and the OpenAI pattern is a strict prefix.
_ANTHROPIC = re.compile(r"sk-ant-[a-z0-9]+-[A-Za-z0-9_-]{20,}")

# OpenAI key: "sk-" + optional "proj-" + >=20 mixed alphanumerics/underscores.
_OPENAI = re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}")

# JWT: three base64url segments separated by dots, header starting "eyJ".
_B64URL = r"[A-Za-z0-9_\-]+"
_JWT = re.compile(rf"eyJ{_B64URL}\.{_B64URL}\.{_B64URL}")

# Private key material. OpenSSH blocks start with the documented base64 preamble;
# PEM blocks are matched by their "PRIVATE KEY" header line.
_OPENSSH = re.compile(
    r"b3BlbnNzaC1rZXktdjE[A-Za-z0-9+/=]{8,}"
    r"(?:[A-Za-z0-9+/=]{4}\n?)*[A-Za-z0-9+/=]*"
)
_PEM = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")

# Email address (RFC-5322-ish, deliberately simple).
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

# US phone in common formats, e.g. (415) 555-0132 / 415-555-0132 / +1 415 555 0132.
# A match is only accepted when the 10-digit number is *structured*: it must carry
# at least one separator (hyphen, space, dot, or parentheses) or a leading "+1"
# prefix. This keeps Unix timestamps and other bare 10-digit numbers
# (``1792988618``, ``4155550132``) from being mistaken for phone numbers. The
# separator/prefix check lives in ``_phone_ok`` because it needs to inspect the
# matched span as a whole; the regex below simply captures every candidate shape.
_PHONE = re.compile(
    r"(?<!\d)(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)"
)

# US SSN. A separator (``-`` or whitespace) is mandatory so bare 9-digit
# numbers -- order ids, ticket numbers, dates -- are not mistaken for SSNs.
# The reserved 000/666/9xx area numbers are excluded here; the ``00`` group and
# ``0000`` serial are rejected in ``_passes_filters``.
_SSN = re.compile(r"(?<!\d)(?!000|666|9\d\d)\d{3}(?:[-\s]\d{2}[-\s]\d{4})(?!\d)")

# Credit card: 13-19 digits in groups separated by a single space or dash.
_CC = re.compile(
    r"(?<![\d-])\d{2,5}(?:[ \-]\d{2,5})*(?:[ \-]\d{1,4})(?![\d-])"
)


# Ordered list of (kind, category, compiled-regex). Secret/PII specific patterns
# come first so the overlap resolver keeps the longer, more specific match.
_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("private_key", "secret", _OPENSSH),
    ("private_key", "secret", _PEM),
    ("jwt", "secret", _JWT),
    ("anthropic_key", "secret", _ANTHROPIC),
    ("openai_key", "secret", _OPENAI),
    ("github_token", "secret", _GITHUB),
    ("aws_access_key", "secret", _AWS),
    ("email", "pii", _EMAIL),
    ("credit_card", "pii", _CC),
    ("ssn", "pii", _SSN),
    ("phone", "pii", _PHONE),
)


# --------------------------------------------------------------------------- #
# Luhn check
# --------------------------------------------------------------------------- #


def _luhn_ok(digits: str) -> bool:
    """Return True when ``digits`` (a string of digits) passes the Luhn test."""
    total = 0
    double = False
    for ch in reversed(digits):
        digit = ord(ch) - 48
        if double:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
        double = not double
    return total % 10 == 0


def _passes_filters(kind: str, value: str) -> bool:
    """Reject matches that fail kind-specific validation (e.g. Luhn)."""
    if kind == "credit_card":
        digits = re.sub(r"[ \-]", "", value)
        return 13 <= len(digits) <= 19 and _luhn_ok(digits)
    if kind == "ssn":
        return _ssn_ok(value)
    if kind == "phone":
        return _phone_ok(value)
    return True


def _phone_ok(value: str) -> bool:
    """Return True when ``value`` is a *structured* US phone number.

    A bare 10-digit run (no separators, no country code) is rejected so that Unix
    timestamps and other numeric ids are not mistaken for phone numbers. A valid
    match must contain at least one separator (``-``, space, ``.`` or parentheses)
    inside the number, or begin with a ``+1`` country-code prefix. The full span
    -- area code included -- is kept as the single finding.
    """
    stripped = value.lstrip("+")
    has_parens = "(" in stripped
    has_separator = any(ch in stripped for ch in "-. \t")
    has_country_code = value.startswith("+1")
    return has_parens or has_separator or has_country_code


def _ssn_ok(value: str) -> bool:
    """Return True when ``value`` has a valid SSN group and serial.

    The regex already enforces the separator shape and excludes the 000/666/9xx
    area numbers; here we reject a ``00`` group number and a ``0000`` serial
    number, which are not valid SSN components.
    """
    m = re.fullmatch(r"(\d{3})[-\s](\d{2})[-\s](\d{4})", value)
    if not m:
        return False
    area, group, serial = m.group(1), m.group(2), m.group(3)
    if group == "00" or serial == "0000":
        return False
    return area not in ("000", "666") and not area.startswith("9")


# --------------------------------------------------------------------------- #
# Scanning
# --------------------------------------------------------------------------- #


def scan(text: str) -> list[Finding]:
    """Scan ``text`` and return non-overlapping findings sorted by ``start``.

    When two patterns match overlapping spans, the longer match wins. If two
    matches of equal length overlap, the one starting earlier wins.
    """
    if not text:
        return []

    candidates: list[tuple[int, int, str, str]] = []
    for kind, _category, regex in _PATTERNS:
        for match in regex.finditer(text):
            value = match.group(0)
            if not _passes_filters(kind, value):
                continue
            candidates.append((match.start(), match.end(), kind, value))

    # Resolve overlaps: longest span first, then earliest start.
    candidates.sort(key=lambda c: (c[1] - c[0], c[0]), reverse=True)

    accepted: list[Finding] = []
    covered: list[tuple[int, int]] = []
    for start, end, kind, value in candidates:
        if any(not (end <= s or start >= e) for s, e in covered):
            continue  # overlaps an already-accepted span
        accepted.append(Finding(kind, _category_of(kind), start, end, value))
        covered.append((start, end))

    accepted.sort(key=lambda f: f.start)
    return accepted


def _category_of(kind: str) -> str:
    return "secret" if kind in _SECRET_KINDS else "pii"


def redact(text: str, categories: set[str] | None = None) -> tuple[str, list[Finding]]:
    """Return ``(redacted_text, findings)`` for ``text``.

    Each finding is replaced with ``[REDACTED:<kind>]``. When ``categories`` is
    given (e.g. ``{"secret"}`` or ``{"pii"}``), only findings in those
    categories are redacted; the returned findings list is likewise filtered.
    """
    findings = [f for f in scan(text) if categories is None or f.category in categories]

    if not findings:
        return text, findings

    parts: list[str] = []
    cursor = 0
    for finding in findings:
        parts.append(text[cursor:finding.start])
        parts.append(f"[REDACTED:{finding.kind}]")
        cursor = finding.end
    parts.append(text[cursor:])
    return "".join(parts), findings
