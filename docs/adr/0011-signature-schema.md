# ADR 0011: Signature schema and semantic version matching

- Status: Accepted
- Date: 2026-08-26

## Context

Vulnerability knowledge must not be hard-coded into scanner or check implementations. Matching
must compare Elasticsearch versions semantically so `8.11.10` is not treated as less than
`8.11.2`. A version string alone is weak evidence: it can identify a potentially affected build
but cannot confirm that a vulnerability is reachable.

## Decision

- Signatures are YAML documents with schema `0.1`, loaded by `internal/vulnerability`.
- Version expressions use explicit comparators and integer component order, including
  fingerprint-compatible prerelease suffixes.
- The version matcher emits `potential` or `unmatched` only. Finding conversion in WP 7.2 may
  attach low or medium confidence but still must not confirm a vulnerability from version alone.
- Invalid files fail closed with the signature file name and a sanitized line location.
- Scanner and CLI packages do not import this package. The check registry may evaluate loaded
  signatures without embedding CVE ranges in Go.

## Consequences

Capability-aware matching and finding conversion are implemented in ADR 0012. Signature updates
use the Ed25519 trust root in ADR 0014. `make signatures-validate` loads committed fixtures with
the same `LoadDir` used at scan time. Mapping version-only evidence to a confirmed finding
remains a contract break.
