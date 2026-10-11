# Security Policy

## Scope

GROSSE FUGUE is a **cleansing** tool. It scans local files for PII
fragments, masks them, or binds them to salted pseudonyms. It performs **no
network requests, no lookups, and no cross-file comparisons** — it cannot
amplify the data it is given.

## Reporting a vulnerability

Please **do not** open a public issue. Write to the maintainers privately
through a GitHub security advisory at:

<https://github.com/BeethovenDev/grosse-fuge/security/advisories/new>

Advisories are acknowledged within 72 hours. A fix is released under the next
patch or minor version depending on severity.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | ✅ |
| < 0.1 | ❌ |

## Pseudonym salt handling

`--mode pseudonym` binds fragments through a salted hash. The salt must be
kept secret and stable: anyone who knows it can re-derive pseudonyms for
values they can guess, and changing it breaks every previously computed
mapping.

## Responsible use

Run GROSSE FUGUE only on data you are authorised to process. K-anonymity
hints are advisory: achieving real anonymity remains a human judgement call.