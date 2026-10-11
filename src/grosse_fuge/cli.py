"""Command-line interface for GROSSE FUGUE."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from collections.abc import Sequence

from grosse_fuge.patterns import ALL_TYPES, find_pii
from grosse_fuge.redact import (
    MODE_MASK,
    MODE_PSEUDONYM,
    column_hints,
    redact_csv,
    redact_json,
    redact_spans,
    split_csv,
)

SUPPORTED_TYPES = ", ".join(ALL_TYPES)


def _parse_types(value: str) -> tuple[str, ...]:
    requested = tuple(part.strip() for part in value.split(",") if part.strip())
    unknown = [name for name in requested if name not in ALL_TYPES]
    if unknown:
        raise SystemExit(f"error: unknown type(s): {', '.join(unknown)} "
                         f"(available: {SUPPORTED_TYPES})")
    return requested


def _load_names(path: str) -> tuple[str, ...]:
    names: list[str] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            name = line.strip()
            if name and not name.startswith("#"):
                names.append(name)
    return tuple(names)


def _counts_to_dict(counts: Counter[str]) -> dict[str, int]:
    return dict(sorted(counts.items()))


def _format_for(path: str) -> str:
    lower = path.lower()
    if lower.endswith(".csv"):
        return "csv"
    if lower.endswith(".json"):
        return "json"
    return "text"


def _read_input(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except UnicodeDecodeError:
        raise SystemExit(f"error: {path} is not valid UTF-8 text") from None


def _redact_payload(
    payload: str, fmt: str, types: tuple[str, ...] | None,
    names: tuple[str, ...], mode: str, salt: str,
) -> tuple[str, Counter[str]]:
    if fmt == "csv":
        return redact_csv(payload, mode=mode, salt=salt, types=types, names=names)
    if fmt == "json":
        return redact_json(payload, mode=mode, salt=salt, types=types, names=names)
    if types is None:
        types = ALL_TYPES
    spans = find_pii(payload, types, names)
    return redact_spans(payload, spans, mode, salt)


def _cmd_redact(args: argparse.Namespace) -> int:
    out_target = args.out
    if out_target is None and args.in_place:
        out_target = args.input
    if out_target is None:
        raise SystemExit("error: give --out FILE or --in-place")

    types: tuple[str, ...] | None = None
    names = tuple(_load_names(args.names)) if args.names else ()
    payload = _read_input(args.input)
    fmt = _format_for(args.input)
    redacted, counts = _redact_payload(payload, fmt, types, names, args.mode, args.salt)

    if out_target == "-":
        sys.stdout.write(redacted)
    else:
        with open(out_target, "w", encoding="utf-8", newline="") as fh:
            fh.write(redacted)
        print(f"redacted {args.input} → {out_target} ({sum(counts.values())} fragments)",
              file=sys.stderr)

    if args.json:
        report = {"matched": sum(counts.values()), "by_type": _counts_to_dict(counts)}
        print(json.dumps(report, indent=2))
    return 0


def _cmd_check(args: argparse.Namespace) -> int:
    types = args.types if args.types is not None else ALL_TYPES
    names = tuple(_load_names(args.names)) if args.names else ()
    payload = _read_input(args.input)
    fmt = _format_for(args.input)

    if fmt == "csv":
        counts: Counter[str] = Counter()
        rows = split_csv(payload)
        for row in rows:
            for cell in row:
                counts.update(
                    {span.kind: 1 for span in find_pii(cell, types, names)}
                )
        hints = column_hints(rows, args.k)
    else:
        counts = Counter({span.kind: 1 for span in find_pii(payload, types, names)})
        hints = []

    found = sum(counts.values())
    if args.json:
        report = {
            "input": args.input,
            "format": fmt,
            "matched": found,
            "by_type": _counts_to_dict(counts),
            "column_hints": hints,
        }
        print(json.dumps(report, indent=2))
    else:
        if not counts:
            print(f"no PII fragments found in {args.input}")
        for kind, amount in sorted(counts.items()):
            print(f"{kind:>8}  {amount}")
        for hint in hints:
            hint_text = str(hint.get("hint", ""))
            if hint_text:
                print(f"column {hint['column']}: {hint_text}")
    return 1 if found else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="grosse-fuge",
        description="PII redaction pipeline — mask or pseudonymise personal "
        "data before it leaves the room.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    redact = sub.add_parser("redact", help="redact a text/CSV/JSON file")
    redact.add_argument("input", metavar="INPUT", help="file to redact")
    out = redact.add_mutually_exclusive_group(required=True)
    out.add_argument("--out", metavar="FILE", default=None,
                     help="write result here ('-' for stdout)")
    out.add_argument("--in-place", action="store_true",
                     help="overwrite INPUT (use --mode pseudonym + --salt to stay reversible)")
    redact.add_argument("--types", metavar="A,B", default=None, type=_parse_types,
                        help=f"which types to search (default: all of {SUPPORTED_TYPES})")
    redact.add_argument("--mode", choices=(MODE_MASK, MODE_PSEUDONYM), default=MODE_MASK,
                        help="mask with [R:type] tokens or bind salted stable pseudonyms")
    redact.add_argument("--salt", default="", metavar="S",
                        help="salt for pseudonym mode; keep it secret and stable")
    redact.add_argument("--names", metavar="FILE", default=None,
                        help="one name per line to redact as whole words (type 'named')")
    redact.add_argument("--json", action="store_true", help="also emit a JSON count report")

    check = sub.add_parser("check", help="risk-scan without rewriting")
    check.add_argument("input", metavar="INPUT", help="file to inspect")
    check.add_argument("--types", metavar="A,B", default=None, type=_parse_types,
                       help=f"which types to search (default: all of {SUPPORTED_TYPES})")
    check.add_argument("--names", metavar="FILE", default=None,
                       help="one name per line to scan for as whole words")
    check.add_argument("--k", type=int, default=5, metavar="N",
                       help="k for the k-anonymity hint radar (default: 5)")
    check.add_argument("--json", action="store_true", help="emit a JSON report")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "redact":
        return _cmd_redact(args)
    if args.command == "check":
        return _cmd_check(args)
    parser.error(f"unknown command: {args.command}")
    return 2  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
