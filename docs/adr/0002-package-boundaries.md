# ADR 0002: Internal package boundaries

- Status: Accepted
- Date: 2026-08-26

## Context

The application needs independent target ingestion, transport, fingerprinting, security checks,
vulnerability knowledge, and reporting. Allowing CLI or network details to cross these concerns
would make safety review and deterministic testing difficult.

## Decision

Application code lives under `internal/`; garga does not expose a library API in v1.

- `internal/app` orchestrates anonymous `scan`, `fingerprint`, and `vuln` runs.
- `internal/model` is a leaf package and performs no I/O.
- `internal/target` parses and streams target input.
- `internal/config` resolves non-secret operational settings.
- `internal/transport` owns HTTP/TLS policy, resource limits, and the GET-only request method
  default. It does not own Elasticsearch path catalogs.
- `internal/ratelimit` owns goroutine-free global and per-host request pacing.
- `internal/probe` converts transport responses into bounded product-neutral input.
- `internal/fingerprint` evaluates product-neutral probe results without I/O.
- `internal/capability` discovers read-only Elasticsearch API and authentication-mechanism availability.
- `internal/checks` evaluates capability-gated security checks and emits `model.Finding` values.
- `internal/credential` holds one explicit Basic Auth, API key, or Bearer secret and redacts it.
  `garga auth-check` uses Basic Auth or API key with `capability.PathAuthenticate`. `garga health`
  may attach the same secret type to GET collectors.
- `internal/credential/audit` is the isolated opt-in credential audit engine and is not used by scan.
- `internal/vulnerability` owns signature loading, version matching, and potential finding conversion.
- `internal/update` fetches, verifies, stages, and atomically activates signed signature bundles.
- `internal/logging` emits structured JSON logs with secret redaction and closed-enum labels.
- `internal/report` streams findings to console, JSON, JSONL, CSV, and standalone HTML without depending on scanner implementations.
- `internal/health` is the isolated read-only cluster assessment engine used only by `garga health`.
  Collectors own Elasticsearch I/O; checkers receive a normalized snapshot and perform no network
  requests. It does not import Cobra or `internal/app`.
- `internal/integration` holds opt-in Elasticsearch container tests. It is not imported by the CLI or scanner.
- `scripts/release` builds distribution archives. It is not part of the CLI and must not import Cobra.
- `scripts/validate-signatures` loads YAML fixtures through `internal/vulnerability`. It is not
  part of the CLI and must not import Cobra.
- scanner orchestration must not implement fingerprint, check, vulnerability, or report semantics.
- reporters consume domain results and must not depend on scanner implementations.
- only `internal/cli` and `cmd/garga` may import Cobra.
- `internal/app` must not import Cobra, `internal/credential`, `internal/credential/audit`, or
  `internal/update`.

New packages are introduced only for an implemented work package. Import cycles are prohibited.

## Consequences

Some small conversion code is preferable to coupling layers through implementation-specific
types. Cross-layer contracts require focused tests, and public compatibility applies to CLI,
configuration, and output schemas rather than Go symbols under `internal/`.
