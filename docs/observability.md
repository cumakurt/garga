# Observability

WP 9.1 adds structured JSON logs and a bounded-cardinality scanner summary. Logs go to stderr so
stdout remains findings and command results. The default level is `info` (`GARGA_LOG_LEVEL` /
`logging.level`).

## Log contract

- Records are JSON objects from `log/slog`. Source file paths are omitted.
- Default `info` emits scanner start and finish only. Per-probe lines are `debug`.
- Sensitive attribute names (`authorization`, `cookie`, `password`, `token`, `api_key`, and
  related keys) are replaced with `[redacted]`. Known secret substrings are stripped from messages
  and string values. `Bearer` / `Basic` / `ApiKey` header values are dropped entirely.
- Hosts, URLs, and other user-controlled strings are not used as metric labels. Closed enumerations
  (error kind, outcome, format) go through `logging.Bounded` and unknown values become `other`.

## Scanner summary `0.1`

The finish record and `scanner.Stats.Summary()` share these fields:

`schema_version`, `event` (`scanner.summary`), `submitted`, `started`, `attempts`, `retries`,
`completed`, `succeeded`, `failed`, `emitted`, `peak_queue_depth`, `peak_active_workers`,
`peak_reorder_buffer`, `queue_capacity`, `outstanding_window`.

There is no host, URL, path, or error-text field.
