# Changelog

All notable changes to GROSSE FUGUE are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-10-11

### Added

- Pattern catalogue: email, phone, payment-card (Luhn-validated), IPv4,
  IPv6, UUID, and platform access-token variants (`ghp_`, `github_pat_`,
  `xox…`, `sk_`, `AKIA`).
- Whole-word named-entity redaction via `--names FILE` (case-insensitive,
  never substring).
- Two redaction modes: deterministic masking (`[R:type]`) and salted stable
  pseudonyms bound by SHA-256.
- CSV cell-aware redaction that preserves the table shape; JSON redaction
  that only touches string values.
- `check` risk-scan: per-type counts and an honest k-anonymity hint radar
  per CSV column.
- `--json` machine-readable reports on both `redact` and `check`.
- Zero runtime dependencies, Python 3.10+ `src` layout; ruff + mypy strict
  clean test suite.