# ADR 0017: Opt-in Elasticsearch container matrix

- Status: Accepted
- Date: 2026-08-26

## Context

Fixture and `httptest` coverage cannot prove that fingerprint, capability, check, and credential
code match live Elasticsearch HTTP, authentication, and TLS behavior. The matrix must stay out of
default unit tests: images are large, clusters need Docker, and pulls use the public internet.

Build tags would hide compile errors from `go test ./...`. Extra frameworks such as Testcontainers
would add a dependency for a job the Docker CLI already performs.

## Decision

- Container tests live in `internal/integration` and compile during ordinary `go test`.
- They **run** only when `GARGA_INTEGRATION=1`. Missing Docker in that mode is a failure, not a
  skip. Unset, the matrix test skips.
- Images are the official `docker.elastic.co/elasticsearch/elasticsearch` tags pinned to the
  fixture versions in ADR 0005. Fully supported lines cover anonymous HTTP, authenticated HTTP,
  and authenticated HTTPS. 7.17.23 is a single anonymous-HTTP smoke lane.
- Clusters bind to `127.0.0.1`, use ephemeral passwords in a `0600` env file, and mount
  test-generated TLS material for HTTPS lanes. Diagnostics run through secret redaction.
- `make integration` and a `workflow_dispatch` GitHub Actions workflow are the supported runners.
  Pull-request CI stays Docker-free.

## Consequences

A developer without Docker can still merge. A broken live fingerprint or capability path is
caught when someone runs the matrix, not on every unit-test job. Refresh image pins together with
ADR 0005 and the fingerprint fixtures.
