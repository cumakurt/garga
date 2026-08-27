# Complete garga health and align docs

## Status

Complete.

## Scope

Make the uncommitted `garga health` stack production-ready: fix failing tests,
evidence-based anonymous access, collector contracts, profile semantics,
markdown/report ops, and documentation alignment.

## Acceptance

- [x] helpers_test compiles; AnonymousAccess is evidence-based; fail-on fixture has masters
- [x] `--allow-plaintext-auth` emits a dedicated CRITICAL finding
- [x] Collector rejects <7.17 and OpenSearch; snapshot history capped at 20/repo; cancel coverage recorded
- [x] All eight profiles have distinct checker behavior
- [x] Markdown reports include correlations, actions, collector coverage
- [x] `GARGA_HEALTH_MAX_RESPONSE_BYTES` and `--max-response-bytes`; Makefile formats `brand.go`
- [x] Tests for collector/normalize/correlation/redact/engine/CLI contracts
- [x] Docs, CHANGELOG, example YAML, master plan WP 13.1, ADR 0002 aligned

## Review

Anonymous access is now based on authenticate evidence rather than "no credential was sent".
`Write` clones report slices before redaction so concurrent format writers cannot race.
