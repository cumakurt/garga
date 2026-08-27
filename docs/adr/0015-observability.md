# ADR 0015: Structured logs and bounded scan statistics

- Status: Accepted
- Date: 2026-08-26

## Context

Operators need to see whether a scan is bounded and whether it finished, without turning every
HTTP probe into a log line or attaching user-controlled hosts to metrics. Credentials already
have a redaction helper; logs still need a single handler that cannot echo secrets by attribute
name. Prometheus was not added: there is no scrape endpoint in v1.

## Decision

- `internal/logging` wraps `log/slog` JSON on stderr. It redacts sensitive keys and caller-supplied
  secret tokens. It does not import credential, scanner, or Cobra.
- Default level is `warn`: stderr stays quiet on a successful run. `info` emits scanner start
  (worker/queue limits) and scanner finish (counter summary). Per-attempt records exist only at
  `debug` and carry sequence, attempt, and a bounded `error_kind`.
- `scanner.Stats.Summary()` is schema `0.1` with fixed numeric fields. Label helpers map unknown
  enum values to `other`.
- CLI commands construct the logger from `logging.level` and wrap stderr with credential redaction
  when a secret is in scope.

## Consequences

`garga scan` attaches the logger to scanner options without changing the summary
schema. Adding host or URL attributes to info logs or using them as metric labels is a contract
break. Info summaries and debug volume on large scans are explicit operator choices. A TTY
progress bar is a separate stderr UI, not a log record, and must stay host-free.
