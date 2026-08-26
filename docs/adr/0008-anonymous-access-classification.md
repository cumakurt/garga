# ADR 0008: Anonymous access classification

- Status: Accepted
- Date: 2026-08-26

## Context

WP 5.1 reports that unauthenticated access exists. Operators still need to know whether that
access is metadata, index listing, write, or cluster administration. Proving write or admin by
sending a document, index, user, or cluster-settings change would violate the safe-by-default
scan path.

## Decision

Anonymous access is classified from GET-only capability evidence into exactly one class:
`none`, `metadata`, `read`, `write`, or `admin`.

- `none` when no catalogued API succeeded without credentials.
- `metadata` when unauthenticated success is limited to identity or monitoring APIs.
- `read` when `GET /_cat/indices` succeeds without credentials.
- `write` when security APIs are unsupported; this class is always inferred.
- `admin` when a passive authenticate response contains the built-in `superuser` role, or when
  security APIs are unsupported and cluster state or nodes APIs are anonymously available.

Write and inferred admin findings are tagged `inferred` and use medium confidence. They must not
be described as confirmed. Confirmed admin requires the superuser role observation. garga never
sends `PUT`, `POST`, `DELETE`, `PATCH`, or a request that changes cluster state to refine this
classification.

## Consequences

The existing `garga.exposure.anonymous_access` check emits the classified finding rather than a
second check ID. Adding a new GET to refine `read` or `admin` requires an allowlist change under
ADR 0006 and an active-safe test.
