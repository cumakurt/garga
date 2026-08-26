# ADR 0002: Internal package boundaries

- Status: Accepted
- Date: 2026-08-26

## Context

The application needs independent target ingestion, transport, fingerprinting, security checks,
vulnerability knowledge, and reporting. Allowing CLI or network details to cross these concerns
would make safety review and deterministic testing difficult.

## Decision

Application code lives under `internal/`; garga does not expose a library API in v1.

- `internal/model` is a leaf package and performs no I/O.
- `internal/target` parses and streams target input.
- `internal/config` resolves non-secret operational settings.
- `internal/transport` owns HTTP/TLS policy and resource limits, not product semantics.
- `internal/ratelimit` owns goroutine-free global and per-host request pacing.
- `internal/probe` converts transport responses into bounded product-neutral input.
- `internal/fingerprint` evaluates product-neutral probe results without I/O.
- `internal/capability` discovers read-only Elasticsearch API and authentication-mechanism availability.
- `internal/checks` evaluates capability-gated security checks and emits `model.Finding` values.
- `internal/credential` verifies one explicit Basic Auth or API key secret and redacts it.
- `internal/credential/audit` is the isolated opt-in credential audit engine and is not used by scan.
- `internal/vulnerability` owns signature loading, version matching, and potential finding conversion.
- `internal/update` fetches, verifies, stages, and atomically activates signed signature bundles.
- `internal/logging` emits structured JSON logs with secret redaction and closed-enum labels.
- `internal/report` streams findings to console, JSON, JSONL, CSV, and standalone HTML without depending on scanner implementations.
- `internal/integration` holds opt-in Elasticsearch container tests. It is not imported by the CLI or scanner.
- `scripts/release` builds distribution archives. It is not part of the CLI and must not import Cobra.
- scanner orchestration must not implement fingerprint, check, vulnerability, or report semantics.
- reporters consume domain results and must not depend on scanner implementations.
- only `internal/cli` and `cmd/garga` may import Cobra.

New packages are introduced only for an implemented work package. Import cycles are prohibited.

## Consequences

Some small conversion code is preferable to coupling layers through implementation-specific
types. Cross-layer contracts require focused tests, and public compatibility applies to CLI,
configuration, and output schemas rather than Go symbols under `internal/`.
