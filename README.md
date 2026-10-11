# GROSSE FUGUE

> **PII redaction pipeline** — *mask and pseudonymise personal data before it
> leaves the room.*

Named after Beethoven's *Große Fuge, Op. 133*: one theme fractured into six
voices that never let go of each other. Personal data does the same thing —
one phone number drags an email address, which drags a name, which drags a
street. GROSSE FUGUE finds the fragments and binds them.

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-263238?style=flat&labelColor=0d1117)](https://www.python.org/)
[![Zero dependencies](https://img.shields.io/badge/dependencies-none-263238?style=flat&labelColor=0d1117)](https://github.com/BeethovenDev/grosse-fuge/blob/main/pyproject.toml)
[![License: MIT](https://img.shields.io/badge/License-MIT-263238?style=flat&labelColor=0d1117)](https://github.com/BeethovenDev/grosse-fuge/blob/main/LICENSE)

## What it is

A *cleansing* tool, not a surveillance one. It scans a file for PII
fragments — **emails, phone numbers, payment-card numbers (Luhn-validated),
IP addresses, UUIDs, secrets/access tokens**, plus you-supplied names — and
either **masks** them (`[R:email]`, `[R:phone]`, …) or binds them to
**stable, salted pseudonyms** that keep relationships joinable without
revealing anything.

- Never looks anything up, never compares against other data.
- **CSV stays a table** — redaction is done cell-by-cell, so structure and
  row/column counts are always preserved.
- **JSON stays valid** — only string *values* are touched, never keys,
  numbers, or booleans.
- Ships with an honest **k-anonymity hint radar** for release decisions.

## Install

```bash
python -m pip install -e .      # from the repository root (src layout)
```

Requires Python 3.10+; zero runtime dependencies.

## Usage

```bash
# Mask every recognised fragment, writing to a new file
grosse-fuge redact export.csv --out export.clean.csv

# In-place
grosse-fuge redact notes.txt --in-place

# Treat names as sensitive (whole words, case-insensitive)
grosse-fuge redact roster.x.csv --out roster.csv --names ./team-names.txt

# Reversible, joinable pseudonyms (keep --salt secret and stable!)
grosse-fuge redact probe-data.json --out p.json --mode pseudonym --salt "$SECRET"

# Risk-scan without touching anything (exit 1 when PII is present)
grosse-fuge check export.csv
grosse-fuge check notes.txt --names ./names.txt --json
```

## Types

| type | shape | extra |
| --- | --- | --- |
| `email` | `x@y.zz` | — |
| `phone` | international / spaced / dashed | — |
| `card` | 13–19 digit number | must pass the **Luhn** check |
| `ipv4` | dotted quad | validated per-octet |
| `ipv6` | colon groups | validated shape |
| `uuid` | 8-4-4-4-12 | version 1–5, variant 8/9/a/b |
| `token` | `ghp_…`, `github_pat_…`, `xox…`, `sk_…`, `AKIA…` | platform prefixes |
| `named` | whole words you supply | via `--names FILE` |

Limit analysis with `--types email,card` if a file legitimately contains
IPs or dialing codes.

## K-anonymity hints

`grosse-fuge check data.csv` reports, per column:

- a value shared by more than `1/k` of rows (`--k 5` by default), or
- a column where every value is unique — a likely identifier.

These are **hints, not guarantees**: selecting quasi-identifiers and
achieving true k-anonymity still requires your judgement. The tool never
claims more than it does.

## Layout

```
src/grosse_fuge/
    __init__.py   # version + manifesto
    __main__.py   # python -m entry
    cli.py        # redact / check commands
    patterns.py   # pattern catalogue, Luhn, span finding
    redact.py     # masking, pseudonyms, CSV/JSON engines, hints
```

## Development

```bash
python -m pip install -e . pytest ruff mypy
ruff check . --fix
mypy src/grosse_fuge
pytest -q
```

---

*“Fugue: a flight from the subject and return to it.”* — κ.τ.λ.