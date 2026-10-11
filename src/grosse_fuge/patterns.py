"""PII pattern catalogue for GROSSE FUGUE.

The catalogue is regex + structural checks only: no lookups, no network,
nothing that amplifies the data it is asked to hide.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Pattern:
    name: str
    regex: re.Pattern[str]
    luhn: bool = False


EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_RE = re.compile(
    r"(?<!\d)(?:\+?\d{1,3}[\s.-]?)?(?:\(\d{1,4}\)[\s.-]?)?"
    r"(?:\d{3}[\s.-]?\d{3}[\s.-]?\d{2,4}|\d{3}[\s.-]?\d{4})(?!\d)"
)
CARD_RE = re.compile(r"(?<!\d)\d{13,19}(?!\d)")
IPV4_RE = re.compile(
    r"\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b"
)
IPV6_RE = re.compile(
    r"\b(?:(?:[0-9a-fA-F]{1,4}:){1,7}|:):"
    r"(?:(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})?\b"
)
UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"
)
TOKEN_RE = re.compile(
    r"\b(?:ghp_|gho_|github_pat_|xox[baprs]-|sk_live_|sk-[A-Za-z0-9]{4,}|AKIA)"
    r"[A-Za-z0-9_\-]{10,}\b"
)

DEFAULT_PATTERNS = (
    Pattern("email", EMAIL_RE),
    Pattern("phone", PHONE_RE),
    Pattern("card", CARD_RE, luhn=True),
    Pattern("ipv4", IPV4_RE),
    Pattern("ipv6", IPV6_RE),
    Pattern("uuid", UUID_RE),
    Pattern("token", TOKEN_RE),
)

PATTERN_BY_NAME = {p.name: p for p in DEFAULT_PATTERNS}

ALL_TYPES = tuple(PATTERN_BY_NAME)


@dataclass(frozen=True)
class Span:
    """One identified fragment: ``text[start:end]`` is a ``kind`` value."""

    start: int
    end: int
    kind: str


def luhn_valid(number: str) -> bool:
    """Return True when *number* (digits only) passes the Luhn check."""
    digits = [int(ch) for ch in number if ch.isdigit()]
    if len(digits) < 13:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def dedupe_spans(spans: list[Span]) -> list[Span]:
    """Return non-overlapping spans, longest-first on ties.

    Kept spans never overlap, so redaction can apply them in any order.
    """
    ordered = sorted(spans, key=lambda s: (s.start, -s.end))
    kept: list[Span] = []
    last_end = -1
    for span in ordered:
        if span.start >= last_end:
            kept.append(span)
            last_end = span.end
    return kept


def find_pii(
    text: str,
    types: tuple[str, ...] = ALL_TYPES,
    names: tuple[str, ...] = (),
) -> list[Span]:
    """Locate every PII fragment of the requested types in *text*."""
    spans: list[Span] = []
    for type_name in types:
        pat = PATTERN_BY_NAME.get(type_name)
        if pat is None:
            continue
        for match in pat.regex.finditer(text):
            if pat.luhn and not luhn_valid(match.group(0)):
                continue
            spans.append(Span(match.start(), match.end(), pat.name))
    for name in names:
        if not name.strip():
            continue
        rx = re.compile(rf"(?<!\w){re.escape(name.strip())}(?!\w)", re.IGNORECASE)
        for match in rx.finditer(text):
            spans.append(Span(match.start(), match.end(), "named"))
    return dedupe_spans(spans)
