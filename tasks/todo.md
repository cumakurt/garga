# WP 10.1 — Elasticsearch integration matrix

## Status

Complete.

## Scope

- Opt-in Docker tests for pinned fully supported lines (8.19.19, 9.3.8, 9.4.4) with
  anonymous HTTP, authenticated HTTP, and authenticated HTTPS.
- One 7.17.23 legacy anonymous-HTTP smoke lane.
- Default `go test ./...` stays Docker-free and internet-free (skip unless `GARGA_INTEGRATION=1`).
- Failures dump container/image/status and `docker logs` after secret redaction.
- No new dependencies; Docker CLI only. No `scan` CLI.

## Acceptance

- [x] Unit tests remain independent of Docker and the public internet.
- [x] Integration failures preserve diagnostics without secrets.
- [x] Auth and TLS on/off covered for fully supported pins.
- [x] Docs, ADR, master plan, Makefile, optional workflow.
- [x] `make check` and `make test-race` pass.

## Review

Live matrix passed all 10 lanes (`GARGA_INTEGRATION=1 go test -count=1 -timeout 45m -v
./internal/integration -run TestElasticsearchIntegrationMatrix`, ~201s).

Product credential/capability probes use `GET /_security/_authenticate` (Authenticate API).
`GET /_security/user/_authenticate` is Get User and 404s for username `_authenticate`.
Auth lanes wait for an accepted `elastic` password and yellow/green cluster health, not HTTP 401.
HTTPS lanes mount test-generated PEMs and trust that CA. Invalid-credential checks run after
authenticated fingerprinting so a failed Basic attempt cannot race the valid session.

Next queue item is WP 10.2.
