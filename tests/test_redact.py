"""Tests for the GROSSE FUGUE redaction engine."""

from __future__ import annotations

import json

from grosse_fuge.patterns import Span
from grosse_fuge.redact import (
    MODE_PSEUDONYM,
    column_hints,
    pseudonym_for,
    redact_csv,
    redact_json,
    redact_spans,
)


def test_mask_replaces_span_cleanly() -> None:
    text = "mail me at a@b.org please"
    spans = [Span(11, 18, "email")]
    out, counts = redact_spans(text, spans)
    assert out == "mail me at [R:email] please"
    assert dict(counts) == {"email": 1}


def test_mask_keeps_everything_else() -> None:
    text = "nothing sensitive here"
    assert redact_spans(text, []) == (text, {})
    assert dict(redact_spans(text, [])[1]) == {}


def test_pseudonym_mode_is_deterministic_per_salt() -> None:
    one = pseudonym_for("email", "a@b.org", "salt-value")
    again = pseudonym_for("email", "a@b.org", "salt-value")
    other = pseudonym_for("email", "b@c.org", "salt-value")
    other_salt = pseudonym_for("email", "a@b.org", "different")
    assert one == again
    assert one != other
    assert one != other_salt
    assert one.startswith("emai-")


def test_pseudonym_redaction_preserves_mapping() -> None:
    text = "to a@b.org then to a@b.org again"
    spans = [Span(3, 10, "email"), Span(19, 26, "email")]
    out, _counts = redact_spans(text, spans, mode=MODE_PSEUDONYM, salt="s")
    parts = out.split()
    assert parts[1] == parts[4]  # same value, same pseudonym


def test_csv_shape_preserved_and_emails_masked() -> None:
    csv_text = "id,name,email\n1,Anna,a@b.com\n2,Bob,b@c.com\n"
    out, counts = redact_csv(csv_text)
    rows = [line.split(",") for line in out.strip().splitlines()]
    assert len(rows) == 3 and all(len(row) == 3 for row in rows)
    assert rows[0] == ["id", "name", "email"]
    assert rows[1][2] == "[R:email]"
    assert dict(counts) == {"email": 2}


def test_csv_names_only_when_requested() -> None:
    csv_text = "name,email\nAnna,a@b.com\n"
    out, _counts = redact_csv(csv_text, names=("Anna",))
    rows = [line.split(",") for line in out.strip().splitlines()]
    assert rows[1][0] == "[R:named]"
    assert rows[1][1] == "[R:email]"


def test_json_values_redacted_keys_kept() -> None:
    payload = json.dumps(
        {"user": "ann.b@example.org", "role": "admin", "meta": {"phone": "+1 555 123 4567"}}
    )
    out, counts = redact_json(payload)
    parsed = json.loads(out)  # must stay valid JSON
    assert parsed["user"] == "[R:email]"
    assert parsed["role"] == "admin"
    assert parsed["meta"]["phone"] == "[R:phone]"
    assert dict(counts) == {"email": 1, "phone": 1}


def test_json_numbers_and_bools_untouched() -> None:
    payload = json.dumps({"amount": 42, "ok": True, "note": "call 5551234567"})
    out, _counts = redact_json(payload)
    parsed = json.loads(out)
    assert parsed["amount"] == 42
    assert parsed["ok"] is True
    assert parsed["note"] == "call [R:phone]"


def test_column_hints_unique_and_dominated() -> None:
    rows = [
        ["u1", "x", "north"],
        ["u2", "y", "north"],
        ["u3", "y", "south"],
        ["u4", "y", "south"],
        ["u5", "y", "east"],
    ]
    hints = column_hints(rows, k=5)
    unique = [h for h in hints if int(h["column"]) == 0]
    dominated = [h for h in hints if int(h["column"]) == 1]
    assert unique and unique[0]["hint"] == "every value is unique — likely an identifier"
    assert dominated and "shared by more than" in str(dominated[0]["hint"])
