# ADR 0023: Shared Elasticsearch GET path catalog

- Status: Accepted
- Date: 2026-08-27

## Context

Capability discovery and credential verification both need Elasticsearch Authenticate. Duplicating
`/_security/_authenticate` next to a parallel allowlist map lets the two drift. The Get User path
`/_security/user/_authenticate` returns 404 on a valid session and must never be probed as
Authenticate.

## Decision

- `internal/capability` owns the extra-probe catalog. The GET allowlist is derived from it.
- `capability.PathAuthenticate` is the only security API suffix.
- `internal/credential` joins only that path onto a target base path.

## Consequences

Adding a product GET still requires a catalog entry and an active-safe test. Method safety remains
ADR 0022. Transport does not own Elasticsearch paths.
