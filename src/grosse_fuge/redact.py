"""Redaction engine: span masking and stable pseudonyms.

Masking replaces every fragment with a fixed, shape-preserving token such as
``[R:email]``. Pseudonym mode binds each fragment to a salted SHA-256 digest
so the *same* original value always maps to the *same* pseudonym — re-joining
the data later works without revealing anything.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
from collections import Counter

from grosse_fuge.patterns import ALL_TYPES, Span, find_pii

MODE_MASK = "mask"
MODE_PSEUDONYM = "pseudonym"

_PSEUDO_LENGTH = 10


def mask_for(kind: str) -> str:
    return f"[R:{kind}]"


def pseudonym_for(kind: str, value: str, salt: str) -> str:
    digest = hashlib.sha256(f"{salt}|{kind}|{value}".encode()).hexdigest()
    return f"{kind[:4]}-{digest[:_PSEUDO_LENGTH]}"


def redact_spans(
    text: str,
    spans: list[Span],
    mode: str = MODE_MASK,
    salt: str = "",
) -> tuple[str, Counter[str]]:
    """Replace *spans* in *text*; returns ``(out_text, counts_by_kind)``.

    Spans must not overlap (see :func:`~grosse_fuge.patterns.dedupe_spans`).
    """
    counts: Counter[str] = Counter()
    if not spans:
        return text, counts
    parts: list[str] = []
    cursor = 0
    for span in sorted(spans, key=lambda s: s.start):
        parts.append(text[cursor : span.start])
        value = text[span.start : span.end]
        if mode == MODE_PSEUDONYM:
            parts.append(pseudonym_for(span.kind, value, salt))
        else:
            parts.append(mask_for(span.kind))
        counts[span.kind] += 1
        cursor = span.end
    parts.append(text[cursor:])
    return "".join(parts), counts


def split_csv(text: str) -> list[list[str]]:
    return list(csv.reader(io.StringIO(text)))


def join_csv(rows: list[list[str]]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerows(rows)
    return buffer.getvalue()


def redact_csv(
    text: str,
    mode: str = MODE_MASK,
    salt: str = "",
    types: tuple[str, ...] | None = None,
    names: tuple[str, ...] = (),
) -> tuple[str, Counter[str]]:
    """Redact cell-by-cell so the table shape is always preserved."""
    if types is None:
        types = ALL_TYPES
    rows = split_csv(text)
    counts: Counter[str] = Counter()
    out_rows: list[list[str]] = []
    for row in rows:
        new_row: list[str] = []
        for cell in row:
            cell_out, cell_counts = redact_spans(
                cell, find_pii(cell, types, names), mode, salt
            )
            new_row.append(cell_out)
            counts.update(cell_counts)
        out_rows.append(new_row)
    return join_csv(out_rows), counts


def redact_json(
    text: str,
    mode: str = MODE_MASK,
    salt: str = "",
    types: tuple[str, ...] | None = None,
    names: tuple[str, ...] = (),
) -> tuple[str, Counter[str]]:
    """Redact string *values* (never keys) so the document stays valid JSON."""
    if types is None:
        types = ALL_TYPES
    payload = json.loads(text)
    counts: Counter[str] = Counter()
    redacted = _redact_json_value(payload, mode, salt, types, names, counts)
    return json.dumps(redacted, indent=2, ensure_ascii=False) + "\n", counts


def _redact_json_value(
    value: object,
    mode: str,
    salt: str,
    types: tuple[str, ...],
    names: tuple[str, ...],
    counts: Counter[str],
) -> object:
    if isinstance(value, str):
        out, found = redact_spans(value, find_pii(value, types, names), mode, salt)
        counts.update(found)
        return out
    if isinstance(value, list):
        return [_redact_json_value(item, mode, salt, types, names, counts) for item in value]
    if isinstance(value, dict):
        return {
            str(key): _redact_json_value(item, mode, salt, types, names, counts)
            for key, item in value.items()
        }
    return value


def column_hints(rows: list[list[str]], k: int = 5) -> list[dict[str, object]]:
    """Honest k-anonymity hints per CSV column.

    This is a *hint radar*, not a guarantee: it reports single-value dominance
    and all-unique columns, and leaves quasi-identifier selection to you.
    """
    if not rows:
        return []
    k = max(1, k)
    width = max(len(row) for row in rows)
    hints: list[dict[str, object]] = []
    for column in range(width):
        values = [row[column] for row in rows if column < len(row)]
        if not values:
            continue
        frequencies = Counter(values)
        max_frequency = frequencies.most_common(1)[0][1]
        record: dict[str, object] = {
            "column": column,
            "rows": len(values),
            "distinct": len(frequencies),
            "max_frequency": max_frequency,
        }
        if max_frequency > len(values) // k:
            record["hint"] = f"a single value is shared by more than 1/{k} of rows"
        elif len(frequencies) == len(values) and len(values) > 1:
            record["hint"] = "every value is unique — likely an identifier"
        hints.append(record)
    return hints
