# ADR 0006: GET-only capability discovery

- Status: Accepted
- Date: 2026-08-26

## Context

Fingerprint classification identifies Elasticsearch. Security checks still need to know whether
root, cluster, nodes, cat, and security APIs exist, and whether anonymous access, Basic Auth, or
API keys are in play. Inferring those facts from a version string would skip APIs that a
deployment actually exposes, or probe APIs that a distribution does not implement. Sending
cluster-state or index writes to "see what happens" would violate the safe-by-default scan path.

## Decision

Capability discovery is a separate package that observes allowlisted read-only endpoints through
the existing probe and transport boundary.

- Discovery runs only for `likely` and `confirmed` fingerprints.
- The extra request catalog is an explicit GET allowlist: `/_cluster/health`,
  `/_cluster/state/version`, `/_nodes/_local/http`, `/_cat/health`, `/_cat/indices`, and
  `/_security/_authenticate`.
- Availability is classified from HTTP status and `WWW-Authenticate` challenges. The authenticate
  body is parsed only for a boolean built-in `superuser` role match; usernames and custom roles
  are discarded.
- `unsupported` is the only state that suppresses dependent checks. Transient and transport
  failures remain `unknown` or `error` so a missing-API skip is never inferred from a timeout.
- The detector issues extra probes sequentially and does not add workers, retries, or rate
  limiters of its own.

## Consequences

Checks introduced after this decision must consult capability availability before they request an
API. Adding a new discovery request requires expanding the extra-probe catalog; the GET allowlist
is derived from that catalog. `capability.PathAuthenticate` is the only security path; credential
verification reuses it. `GET /_security/user/_authenticate` is Get User and must not be added.
Version support changes remain in ADR 0005; they do not grant capability presence by themselves.
