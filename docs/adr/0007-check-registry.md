# ADR 0007: Capability-gated check registry

- Status: Accepted
- Date: 2026-08-26

## Context

Fingerprint and capability discovery identify Elasticsearch and which read-only APIs exist.
Security evaluation still needs stable check identifiers, applicability rules, evidence-backed
findings, and deduplication so later reporters and vulnerability matching do not invent a
parallel model. Embedding check logic in the scanner or CLI would mix orchestration with
security semantics. Claiming schema `1.0` before reporters and golden fixtures exist would freeze
an unfinished contract.

## Decision

- Finding, evidence, severity, and confidence types live in `internal/model`.
- Check implementations live in `internal/checks` and evaluate collected fingerprint, capability,
  and endpoint data.
- Each check has a stable ID that is never reused for different semantics.
- A check runs only when it applies. Capability `unsupported` suppresses dependent checks.
- Deduplication keys are endpoint, check ID, and normalized resource. Unique evidence is merged.
- The finding schema version is `0.1` until the first public tag. WP 8.1 publishes streaming
  reporters against this pre-release schema and must not claim `1.0`.
- WP 5.1 checks perform no additional I/O. Any future check request must be GET-only and
  allowlisted.
- Signature evaluation is added through `WithSignatures`. CVE ranges stay in YAML.

## Consequences

Reporters can consume `model.Finding` without importing check implementations. Adding a check
requires a new stable ID, applicability tests, redaction tests, and an active-safe request
declaration. Schema `0.1` may still change before the first public tag.
