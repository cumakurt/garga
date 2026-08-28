# Elasticsearch integration matrix

WP 10.1 adds opt-in container tests against real Elasticsearch images. They are not part of
`make check` or pull-request CI. Default unit tests never start Docker and never contact the
public internet.

## When to run

Run the matrix when changing fingerprint, capability, check, credential, or transport behavior
that depends on live Elasticsearch HTTP/TLS responses.

```sh
make integration
```

That sets `GARGA_INTEGRATION=1` and runs `go test -count=1 -timeout 45m ./internal/integration`.
The first run pulls images from `docker.elastic.co`.

Narrow a run:

```sh
GARGA_INTEGRATION=1 GARGA_INTEGRATION_VERSION=9.5.2 go test -count=1 -timeout 20m ./internal/integration
GARGA_INTEGRATION=1 GARGA_INTEGRATION_FILTER=anon/http go test -count=1 -timeout 20m ./internal/integration
```

Requirements: Docker Engine, about 2 GiB memory per cluster, and `vm.max_map_count` high enough
for Elasticsearch (the tests also set `node.store.allow_mmap=false`).

## Matrix

Pinned to the fixture versions in [ADR 0005](adr/0005-elasticsearch-version-support.md):

| Version | Tier | Anonymous HTTP | Authenticated HTTP | Authenticated HTTPS |
|---|---|---|---|---|
| 8.19.20 | Fully supported | yes | yes | yes |
| 9.4.5 | Fully supported | yes | yes | yes |
| 9.5.2 | Fully supported | yes | yes | yes |
| 7.17.23 | Legacy detection | smoke | — | — |

Anonymous HTTPS is omitted: it is not a realistic Elasticsearch operator profile. TLS on/off and
authentication on/off are covered by the three fully supported lanes.

Live Elasticsearch 8+/9 401 responses to anonymous `GET /` typically omit `X-Elastic-Product`.
garga therefore does not treat that 401 JSON error as a confirmed fingerprint. Authenticated
lanes verify credentials first, then fingerprint the authenticated `GET /` 200 body.
HTTPS lanes mount test-generated PEM material and trust that CA. Images disable GeoIP downloads.
Tests never send `PUT`, `POST`, `DELETE`, or `PATCH`. Credential and security probes use
`GET /_security/_authenticate` (the Elasticsearch Authenticate API, not Get User). Auth lanes
are not ready on HTTP 401; they wait until the `elastic` credential is accepted and cluster
health is green, including the `.security` primary shard. Every lane also runs the deep contextual assessment engine with the
bundled corpus, verifies all 39 checks/evaluators are registered, confirms node runtime inventory,
and checks that serialized reports contain no credential material.

## Failures

On failure the test prints image, container name, port, auth/TLS flags, container status, and
the last 20 lines of `docker logs`. Passwords, Basic headers, and env-file values are replaced
with `[redacted]`. Response bodies and cluster identifiers are not dumped.

## Isolation

`internal/integration` may import transport, probe, fingerprint, capability, checks, credential,
health, config, model, and target. It must not import Cobra, `internal/cli`, `internal/app`, the scanner,
reporters, or the signature updater. Live matrix tests exercise packages directly rather than
spawning `garga scan`.

## Operator CLI demo against Docker

`scripts/docker-feature-demo.sh` drives the installed `bin/garga` binary against local
Elasticsearch 8.19.20 containers:

- `127.0.0.1:19201` — security disabled (anonymous `fingerprint`, `scan`, `vuln`)
- `127.0.0.1:19200` — security enabled (credentials, `health`, `assess`, `secrets`)

It captures terminal screenshots under `docs/screenshots/` and copies example PDFs to
`sample/`. Set `GARGA_DEMO_PASSWORD` to the secured container `elastic` password before
running it. The script redacts that password from logs and screenshots.
