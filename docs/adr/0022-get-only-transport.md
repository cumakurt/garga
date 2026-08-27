# ADR 0022: GET-only transport requests

- Status: Accepted
- Date: 2026-08-27

## Context

Product probes, credential verification, and signature-database fetches already send `GET`
without a body. `transport.NewRequest` still accepted any method, so a later caller could send
`POST`, `PUT`, `PATCH`, or `DELETE` through the shared client without failing the constructor.

## Decision

- `NewRequest` accepts only `GET` and a nil body.
- `Client.Do` rejects any other method and any request body, including bodies attached after
  construction.
- Redirects that would change the method or attach a body are rejected as invalid requests.

## Consequences

Read-only `HEAD` is also rejected until a later work package expands the method allowlist with
tests. Signature updates remain `GET`. Transport stays product-neutral; the constraint is an
operational safety default, not an Elasticsearch path catalog.
