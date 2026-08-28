# Deep-scan and credential correlation

## Status

Complete.

## Scope

- [x] Central `ScanProfile` (`NormalProfile` / `DeepScanProfile`) and `--deep-scan` CLI flags
- [x] Deep-scan sampling, source includes, and hard safety limits
- [x] Credential correlation engine (roles, same-object/array scope, config/URL/header)
- [x] Report metadata: scan mode, stats, correlation summary, related fields
- [x] Unit tests, CLI tests, benchmarks
- [x] Docs and CHANGELOG

## Review

Normal scan defaults are unchanged. `--deep-scan` applies `DeepScanProfile` unless the operator
overrides a limit. Correlation is document-local (same object or same array element), buckets
fields by role, and stores only masked metadata. PIT is not used (ADR 0027).

Tests: `go test ./internal/secrets ./internal/cli` and `go test -race ./internal/secrets` passed.
Benchmarks: `BenchmarkCorrelateLargeDocument` ~7.3ms/op; `BenchmarkCorrelateWideObject` ~1.1ms/op.
