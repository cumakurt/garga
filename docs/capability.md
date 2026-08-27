# Elasticsearch capability contract

Capability discovery runs only after a fingerprint classifies an endpoint as `likely` or
`confirmed`. It decides which read-only Elasticsearch APIs and authentication mechanisms are
present so later checks can skip missing APIs instead of emitting operational noise.

Discovery reuses the fingerprint root probe and the shared probe/transport stack. It does not
create its own client, retry policy, or worker pool. Callers that need scan-wide pacing must wrap
the prober they pass to the detector.

Availability is taken from HTTP status codes and `WWW-Authenticate` challenges. The authenticate
response body is inspected only for a boolean match of the built-in `superuser` role; usernames,
custom roles, and other fields are discarded. Version numbers never substitute for these
observations.

## Catalog

Every result contains these identifiers in this order, including when discovery is skipped:

| Capability | Evidence |
|---|---|
| `root` | Reused fingerprint probe |
| `health` | `GET /_cluster/health` |
| `state` | `GET /_cluster/state/version` |
| `nodes` | `GET /_nodes/_local/http` |
| `cat` | `GET /_cat/health` |
| `indices` | `GET /_cat/indices` |
| `security` | `GET /_security/_authenticate` |
| `anonymous` | Derived: any catalogued API returned `2xx` without credentials |
| `basic_auth` | Derived: a `401`/`403` advertised `Basic realm="security"` |
| `api_key` | Derived: a `401`/`403` advertised `ApiKey` |

A reverse-proxy base path from the target is preserved. Allowlisted suffixes come from the extra
probe catalog (`capability.AllowlistedAPIPaths`); query parameters and fragments are rejected.
Root is never requested a second time. `GET /_security/user/_authenticate` is Get User and is not
in the catalog.

## Availability

| HTTP outcome | Availability | Dependent checks |
|---|---|---|
| `2xx` | `available` | May run anonymous checks |
| `401`, `403` | `auth_required` | API exists; anonymous checks skip, authenticated checks may run |
| `400`, `404`, `405`, `406`, `410`, `501` | `unsupported` | Dependent checks must skip |
| Timeout, `429`, `5xx`, transport failure | `error` or `unknown` | Do not treat as missing |
| Fingerprint below `likely` | `unknown` | No extra requests are issued |

`Exists` is true for `available` and `auth_required`. `Suppresses` is true only for
`unsupported`. Probe failures on one API do not fail the rest of discovery and do not mark that
API unsupported.

## Safety

Every extra request is `GET`, has no body, and has no query string. The detector never sends
`PUT`, `POST`, `DELETE`, `PATCH`, or bulk/index APIs. Response bodies and non-allowlisted headers
are discarded after status and authentication-challenge classification. Results retain only the capability name, availability, status code, a fixed detail token, and a
boolean `AnonymousSuperuser` flag. Cluster names, node names, UUIDs, usernames, custom roles,
raw headers, and server error text are not copied.

Cancellation is checked before each extra probe. An in-flight canceled probe stops the remaining
catalog and returns a cancellation error together with the capabilities already observed.
