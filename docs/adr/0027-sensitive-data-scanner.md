# ADR 0027: Elasticsearch sensitive-data scanner

- Status: Accepted
- Date: 2026-08-28

## Context

Authorized operators need to discover whether Elasticsearch indices contain
credentials, tokens, private keys, or similar secrets. Existing commands either
stay on GET-only metadata APIs (`scan`, `health`, `assess`) or test whether a
supplied credential is accepted (`auth-check`, `auth-audit`, `auth-detect`).
None inspects document values.

Document sampling requires Elasticsearch `_search`. The shared transport (ADR
0022) rejects every non-GET method, which is the correct default for anonymous
assessment. Point-in-time search would also require `DELETE` to close the PIT.

Operators need consistent console, JSON, and PDF reports that can be retained
without copying recovered plaintext secrets into another artifact.

## Decision

- Sensitive-data discovery lives in `internal/secrets` and is invoked only by
  `garga secrets`.
- The engine is isolated from `scan`, `fingerprint`, `vuln`, `health`, and
  `internal/report`.
- A dedicated HTTP client allowlists GET metadata APIs and `POST /{index}/_search`.
  All other methods and write APIs are rejected. PIT is not used.
- Authentication reuses `internal/credential`. Secrets enter through environment
  variables named by `--password-env`, `--api-key-env`, or `--bearer-token-env`.
  There is no `--password` flag.
- Two-stage analysis: mapping field-name scoring, then bounded document sampling
  with `_source` filters, `sort: ["_doc"]`, `search_after`, and small batches.
  Sampling does not sort on `_id` because Elasticsearch 8+/9 disable `_id`
  fielddata by default.
- `--deep-scan` selects a central `DeepScanProfile` (higher sample/depth/field
  limits, generic searchable fields, broader correlation aliases). It is still
  capped and paginated. PIT is not used because closing a PIT requires `DELETE`.
- Same-object credential correlation runs after per-field detectors. Pairs are
  document-local (one object or one array element). Cross-document matching is
  not performed.
- A single canonical `ScanReport` / `Finding` model feeds table, JSON, JSONL, SARIF,
  stderr summary, and PDF output. Raw values are discarded before this model is
  finalized; every format contains only masked previews.
- A pre-render validation gate rejects missing or duplicate finding IDs, invalid
  enums and timestamps, invalid occurrence counts, and summaries that disagree
  with canonical targets or findings.
- Deduplication uses a per-run HMAC-SHA256 key. Plaintext secrets are not stored
  in the dedup index. Target identity participates in deduplication so equivalent
  paths on separate clusters cannot merge.
- Canonical finding retention is capped at 10 000. Hitting the cap is explicit in
  the report and produces a partial-failure result.
- System indices are excluded by default. A readable `.security*` index is a
  critical finding; its authentication material is not dumped.
- `garga secrets generate` may write only to `garga-sensitive-test` with clearly
  fake fixtures.

## Consequences

`garga secrets` is an explicit, authorized mode. It is heavier than GET-only
health collection and must keep production-safe concurrency, rate limits, and
HTTP 429 backoff. All output formats stay secret-free. PDF and explicit output
files remain owner-only confidential assessment artifacts.
