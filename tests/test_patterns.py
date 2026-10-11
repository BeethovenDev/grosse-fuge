"""Tests for the GROSSE FUGUE pattern catalogue."""

from __future__ import annotations

from grosse_fuge.patterns import (
    Span,
    dedupe_spans,
    find_pii,
    luhn_valid,
)


def test_luhn_accepts_valid_card() -> None:
    assert luhn_valid("4111111111111111") is True


def test_luhn_rejects_bad_checksum() -> None:
    assert luhn_valid("4111111111111112") is False
    assert luhn_valid("79927398710") is False  # too short as well


def test_email_found() -> None:
    spans = find_pii("contact me at ann.b@example.org today")
    assert [(s.kind, s.start, s.end) for s in spans] == [
        ("email", 14, 31),
    ]


def test_email_not_match_within_word() -> None:
    assert find_pii("a@b") == []
    assert find_pii("plain text, no addresses") == []


def test_phone_found() -> None:
    spans = find_pii("tel: +1 (555) 123-4567 reachable 9-5")
    assert any(s.kind == "phone" for s in spans)


def test_ipv4_and_ipv6_found() -> None:
    text = "server 192.168.1.10 and fallback 2001:db8::1"
    kinds = {s.kind for s in find_pii(text)}
    assert {"ipv4", "ipv6"} <= kinds


def test_uuid_found() -> None:
    uid = "a681ca8e-7f1a-4b2e-9c3d-0f0f0f0f0f0f"
    found = find_pii(f"row {uid} committed")
    assert [(s.kind, s.start, s.end) for s in found] == [("uuid", 4, 4 + len(uid))]


def test_token_found() -> None:
    token = "ghp_abcdef0123456789abcdef"
    found = find_pii(f"key={token}")
    assert [(s.kind, s.end - s.start) for s in found] == [("token", len(token))]


def test_card_only_valid_luhn() -> None:
    assert [s.kind for s in find_pii("4111111111111111")] == ["card"]
    assert [s.kind for s in find_pii("4111111111111112")] == []


def test_named_person_case_insensitive_whole_word() -> None:
    found = find_pii("anna stayed in", names=("Anna",))
    assert [(s.kind, s.start, s.end) for s in found] == [("named", 0, 4)]


def test_named_no_partial_hit() -> None:
    # "Annabelle" must not trigger the name "Anna"
    assert find_pii("Annabelle left", names=("Anna",)) == []


def test_dedupe_spans_keeps_first_longest() -> None:
    spans = [Span(0, 10, "long"), Span(2, 5, "short"), Span(10, 14, "next")]
    kept = dedupe_spans(spans)
    assert kept == [Span(0, 10, "long"), Span(10, 14, "next")]
    assert [s.kind for s in kept] == ["long", "next"]
