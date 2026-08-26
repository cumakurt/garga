# ADR 0003: Machine-output schema versioning

- Status: Accepted
- Date: 2026-08-26

## Context

Security findings are consumed by both people and automation. Silent field changes can break
pipelines or, worse, cause findings to be misinterpreted.

## Decision

Every JSON document, JSONL record, CSV finding row, and structured finding embedded in HTML
carries a required `schema_version`. The first public finding schema is `1.0`.

Schema versions use `major.minor` semantics:

- a major increment is required for removed fields, renamed fields, changed field meaning, or
  incompatible enum/value changes;
- a minor increment is required for additive optional fields or enum values;
- serialization-only fixes that do not change the schema do not change the version.

Consumers must reject unsupported major versions and ignore unknown optional fields within a
supported major version. Stable check identifiers are versioned independently and are never
reused for different semantics. JSONL records remain individually self-describing. Console
output is human-oriented and is not a machine schema contract.

## Consequences

Reporter tests require golden compatibility fixtures. A schema change requires migration notes
and explicit review. Pre-release implementation may refine fields until the first public schema
artifact, but it must not claim `1.0` compatibility before the corresponding tests and reference
documentation exist. WP 8.1 publishes streaming reporters for schema `0.1`; the public `1.0`
artifact remains reserved for the first public tag.
