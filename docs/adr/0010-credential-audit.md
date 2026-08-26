# ADR 0010: Isolated credential audit

- Status: Accepted
- Date: 2026-08-26

## Context

Operators sometimes need to try a short, authorized list of credentials against one Elasticsearch
endpoint. Putting that behavior on the normal scan path would make implicit spraying the default.
Reusing the scanner engine would inherit scan rates, worker concurrency, and retry amplification.
A `--password` flag or YAML credential list would leak secrets through process listings and
configuration dumps.

## Decision

- Credential audit lives in `internal/credential/audit` and is invoked only by `garga auth-audit`.
- The engine is sequential, rate-limited to 1 request/second by default, and capped at 5
  authenticate requests per host (configurable up to 20).
- Every HTTP request, including transient retries, waits for the limiter and increments the
  attempt counter. 401/403 are not retried.
- The run stops on success, missing security APIs, the attempt ceiling, or cancellation.
- Scanner, fingerprint, capability, and check packages must not import the audit engine.
- Events are redacted. Secrets stay on stdin and in `internal/credential.Secret`.

## Consequences

A future `scan` command must keep this isolation. Adding scan must fail the dedicated source-level
isolation tests until it is proven not to call the audit engine. Authenticated scan, if added
later, is a separate explicit mode and must not reuse this spraying engine.
