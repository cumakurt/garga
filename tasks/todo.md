# Credential detection module (auth-detect)

## Status

Complete.

## Scope

Complete `garga auth-detect` so authorized Elasticsearch assessments can detect accepted
username/password combinations using four bounded techniques. Keep the GET-only authenticate
contract, isolation from `scan`, and secret-safe input/output.

## Analysis (baseline)

Existing isolation:

- `auth-check`: one credential
- `auth-audit`: at most 32 mixed basic/API-key lines, 20 attempts
- `auth-detect` first cut: four named modes, stdin only, dictionary identical to brute-force

Gaps closed in this change: leak-style stuffing, file wordlists, distinct brute-force charset
generation, spraying round delay, 429 stop, valid-identity summary, documentation, and tests.

## Acceptance

- [x] Stuffing: leak-style pairs plus `basic USER PASS`; stdin or `--credentials-file`
- [x] Spraying: password-outer loop; structured stdin or `--users-file` + password list; optional `--spray-delay`; stop on exhausted 429
- [x] Brute-force: one username; password list or bounded charset generation (max 256 candidates)
- [x] Dictionary: one username; `--wordlist` or `--passwords-stdin`
- [x] Safety: no `--password` flag; no scan-path import; secrets redacted; GET `/_security/_authenticate` only
- [x] Tests for all four modes, file input, leak formats, charset bounds, isolation
- [x] README, credentials, detect, SECURITY, configuration, master plan, ADR 0026, CHANGELOG

## Review

- Short charset candidates no longer substring-redact report lines; tokens shorter than 4 bytes
  redact only on exact match. Authorization headers remain redacted.
- Charset generation is rejected when the cartesian product exceeds 256. This is not unbounded
  brute force.
- `scan` / `fingerprint` / `vuln` / `health` / `report` still cannot import the detect engine.
