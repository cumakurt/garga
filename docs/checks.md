# Check registry and finding contract

WP 5.1 introduces the first security checks. WP 5.2 classifies anonymous access depth from the
same fingerprint and capability results. These checks do not perform additional network I/O.

## Registry

`internal/checks.DefaultRegistry` evaluates these stable identifiers:

| Check ID | Finding | Applies when |
|---|---|---|
| `garga.tls.not_enabled` | Elasticsearch was reached over HTTP | Fingerprint is `likely` or `confirmed` and the endpoint scheme is `http` |
| `garga.exposure.anonymous_access` | Unauthenticated access, classified as metadata/read/write/admin | The `anonymous` capability is `available` |
| `garga.exposure.security_unconfigured` | Security APIs are missing | The `security` capability is `unsupported` |
| `garga.exposure.public_network` | The target is a public IP address | The host is a public unicast IP; hostnames are not resolved |

`checks.WithSignatures` adds `garga.vuln.signatures`, which emits one finding per matching
signature ID (`garga.vuln.*`). CVE ranges stay in YAML. Version-only matches are low-confidence
`potential` findings. Capability `requires` must already be `available`; those findings stay
medium confidence and are still not confirmed.

A check that does not apply produces no finding. Unsupported or missing capabilities therefore
suppress dependent checks without operational errors. `unknown` and `error` capabilities also
suppress the corresponding exposure finding; they are not treated as proof that security is
absent.

Anonymous access is a single class per endpoint. `write` and `admin` are inferred from missing
security APIs unless a passive `superuser` role is observed. Those inferred findings carry an
`inferred` tag and medium confidence. garga does not send a mutation to confirm them.

## Findings

Findings use schema version `1.0`, the public contract in
[ADR 0003](adr/0003-output-versioning.md). Streaming reporters for this schema
are documented in [reports.md](reports.md).

Each finding has a deterministic `id` derived from check ID, canonical endpoint, and resource.
Deduplication uses that same key and merges unique evidence by `code`. Output is ordered by
check ID, endpoint, then resource.

Evidence contains only fixed codes and short summaries. Response bodies, `WWW-Authenticate`
realms, cluster names, node names, UUIDs, and arbitrary headers are never copied. `first_seen`
is omitted until a scan runner records observation time.

Severity and confidence are independent. Default exposure checks do not emit CVE or CVSS values.
Signature findings copy those fields from YAML and remain unconfirmed. Console and HTML listings
may mark a subset as `exploitable` (unauthenticated read/write/admin, or a remote-compromise
advisory class). That mark does not raise confidence or confirm exploitation.

## Active-safe contract

The WP 5.1 and WP 5.2 checks declare an empty request list. They reuse capability discovery
already performed over the GET allowlist in [capability.md](capability.md). Signature evaluation
may declare the same GET catalog paths when a signature `requires` a probed capability. It never
sends `PUT`, `POST`, `DELETE`, `PATCH`, or a request body, and it does not issue those GETs
itself.
