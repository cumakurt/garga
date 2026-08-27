# garga — Engineering Delivery Plan

## Document control

| Field | Value |
|---|---|
| Version | 3.7 |
| Status | Active |
| Last updated | 2026-08-27 |
| Product | Elasticsearch security assessment CLI |
| Implementation language | Go |
| Primary audience | Maintainers, reviewers, security engineers, and coding agents |

This document is the implementation and release contract for garga. It defines scope,
architecture, work sequencing, acceptance criteria, quality gates, and release readiness.
Detailed task decisions that materially affect the architecture must be recorded under
`docs/adr/` once that decision is implemented.

## 1. Product outcome

garga will be a safe-by-default command-line tool for authorized Elasticsearch security
assessments. It will accept IP addresses, CIDRs, hostnames, URLs, and target files; discover
reachable services; identify Elasticsearch using multiple independent signals; assess
authentication and exposure; match validated vulnerability signatures; and emit deterministic,
evidence-backed reports.

The v1 release is successful when an operator can run a bounded, cancellable scan against an
authorized target set and obtain reproducible findings without garga changing remote state.

### 1.1 v1 capabilities

- Canonical and streaming target ingestion.
- Bounded scheduling, global and per-host rate control, and graceful cancellation.
- Reusable HTTP/TLS transport with explicit timeouts and response limits.
- Multi-signal Elasticsearch fingerprinting with a negative-response corpus.
- Capability-aware, non-destructive exposure and authentication checks.
- Explicit single-credential verification with secret-safe input and output handling.
- Isolated, explicit, rate- and attempt-limited credential audit mode.
- Signature-driven vulnerability matching and safe signature updates.
- Console, JSON, JSONL, CSV, and standalone HTML reports.
- Versioned output schemas, stable check identifiers, and deterministic ordering.

### 1.2 Non-goals for v1

- Exploitation, remote code execution, shell access, or destructive payloads.
- Creating, updating, or deleting indices, documents, users, or cluster settings.
- Implicit credential spraying from the normal scan path.
- Distributed scanning, a web UI, or support for products other than Elasticsearch.
- A generic plugin framework before a second product proves the abstraction necessary.

## 2. Non-negotiable engineering principles

1. **Safe by default:** normal scans are read-only and non-destructive.
2. **Evidence first:** findings carry structured, redacted evidence and remediation.
3. **Product detection is separate from security evaluation:** scanners discover; checks assess.
4. **Bounded resource use:** workers, queues, response bodies, retries, and rates have limits.
5. **Cancellation is end-to-end:** network-facing APIs accept `context.Context`.
6. **Deterministic behavior:** equivalent normalized inputs produce stable results and ordering.
7. **Signatures own vulnerability knowledge:** CVE ranges are not hard-coded into scanner logic.
8. **Secrets never become telemetry:** credentials and authorization material are not logged,
   serialized, or included in errors.
9. **Compatibility is deliberate:** CLI, config, and output schema changes require migration review.
10. **No speculative architecture:** abstractions are introduced only for an implemented use case.

## 3. Current baseline and explicit decisions

The repository started with only planning and agent instructions. Work Packages 0.1 and 0.2
established the buildable CLI, public module/license, and development governance. Work Packages
1.1 through 1.3 added canonical streaming target input and typed, layered, secret-free
configuration. Work Packages 2.1 and 2.2 added the reusable, bounded HTTP/TLS transport and
deterministic, sanitized probe results. Work Package 3.1 added bounded scheduling, ordered
backpressure, global/per-host pacing, transient retries, and graceful cancellation. Remaining
decisions are resolved at their documented blocking points. Work Package 4.1 added the
multi-signal Elasticsearch fingerprint engine and D-003 positive/negative fixture corpus. Work
Package 4.2 added GET-only capability discovery on confirmed and likely Elasticsearch endpoints.
Work Package 5.1 added the capability-gated check registry and TLS/public-exposure findings.
Work Package 5.2 added GET-only anonymous access classification (`none`/`metadata`/`read`/`write`/`admin`).
Work Package 6.1 added explicit single-credential verification with stdin secrets and centralized redaction.
Work Package 6.2 added the isolated, opt-in credential audit engine with rate and attempt ceilings.
Work Package 7.1 added YAML vulnerability signatures and a semantic version matcher with potential-only detection.
Work Package 7.2 added capability-aware signature evaluation and finding conversion through the check registry.
Work Package 8.1 added streaming console, JSON, JSONL, CSV, and standalone HTML reporters with schema `0.1`.
Work Package 8.2 added signed signature-database updates with Ed25519 verification, staging, and rollback.
Work Package 9.1 added structured redacted JSON logs and a bounded-cardinality scanner summary.
Work Package 9.2 added captured performance baselines. Work Package 10.1 added the opt-in
Elasticsearch container matrix. Work Package 10.2 added reproducible cross-platform release
archives, checksums, SBOMs, and the tag-triggered publish workflow. Work Package 11.1 added the
public `garga scan` command and `internal/app` orchestration. Work Package 11.2 added
`garga fingerprint` for GET-only product identity. Work Package 11.3 added `garga vuln` for
signature-only matching. Work Package 12.1 added the committed golangci-lint configuration and
pull-request `govulncheck`. Work Package 12.2 made the shared HTTP transport reject non-GET
methods and request bodies. Work Package 12.3 made the Elasticsearch GET path catalog the single
source for Authenticate and extra probes. Work Package 12.4 added `make signatures-validate` for
committed YAML fixtures. Work Package 13.1 added `garga health`, a GET-only cluster assessment
engine with centralized collection, 37 checkers, and an independent health-report schema.

### 3.1 Decisions in force

| Decision | Rationale |
|---|---|
| Minimum Go version is 1.26 | It is one of the two supported Go release lines as of this revision. CI also tests Go 1.27. |
| Cobra is the only bootstrap runtime dependency | Stable subcommand and flag behavior is central to the product; other dependencies require separate justification. |
| The canonical module is `github.com/cumakurt/garga` | Public imports and release metadata require one stable repository identity. |
| The project license is `AGPL-3.0-only` | Reciprocal source availability applies to redistribution and modified network-accessible deployments. |
| Internal packages are used for application code | garga is an application, not a library API. This limits accidental public contracts. |
| CLI output is English in v1 | Localization is deferred until output contracts stabilize. |
| CI has read-only repository permissions | The validation workflow does not need write access. |
| Scanner behavior is absent from bootstrap | Network behavior begins only after target and transport contracts are tested. |

### 3.2 Tracked product decisions

| ID | Decision | Status | Resolution or blocking point |
|---|---|---|---|
| D-001 | Canonical VCS/module path | Resolved | `github.com/cumakurt/garga`; ADR 0004 |
| D-002 | Open-source or proprietary license | Resolved | `AGPL-3.0-only`; ADR 0004 |
| D-003 | Supported Elasticsearch version matrix | Resolved | Current 8.19.x/9.3.x/9.4.x plus legacy detection; ADR 0005 |
| D-004 | Signature trust root and signing mechanism | Resolved | Embedded Ed25519 public key; ADR 0014 |
| D-005 | Default scan rate and concurrency | Resolved | 20 workers, 50 global req/s, 5 per-host req/s; ADR 0001 |

No CLI, configuration, or output compatibility promise exists before the first public tag.

## 4. Architecture and dependency direction

```text
cmd/garga
    |
    v
internal/cli ---> internal/app ---> internal/scanner ---> internal/transport
                       |                    |
                       |                    +------> internal/fingerprint
                       |                    +------> internal/capability
                       |                    +------> internal/checks
                       |                    +------> internal/vulnerability
                       |
                       +---------------------------> internal/report

internal/cli ---> internal/credential ---> internal/transport
internal/cli ---> internal/credential/audit ---> internal/credential
                                           ---> internal/ratelimit
                                           ---> internal/transport
internal/cli ---> internal/report
internal/cli ---> internal/update ---> internal/vulnerability
                                  ---> internal/transport
internal/cli ---> internal/logging
internal/cli ---> internal/health ---> internal/transport
                                 ---> internal/credential
                                 ---> internal/config
internal/scanner ---> internal/logging

internal/model is a leaf package and performs no I/O.
```

Dependency rules:

- `internal/model` must not import transport, scanner, CLI, or report packages.
- `internal/report` must not depend on scanner implementations.
- `internal/vulnerability` must not know Cobra flags or CLI concepts.
- Only `internal/cli` and `cmd/garga` may depend on Cobra.
- Transport code owns network limits, redirect policy, and connection reuse.
- Check implementations own security semantics; the scanner only orchestrates them.
- `internal/credential` is used by explicit `auth-check` verification and optional `garga health`
  authentication, not by scanner orchestration.
- `internal/credential/audit` is used only by explicit `auth-audit` and has no call path from scan.
- `internal/vulnerability` loads signatures, matches versions, and converts potential findings.
  It does not confirm exploits from version evidence.
- `internal/update` fetches and activates signed signature bundles. It is not on the scan path.
- `internal/logging` emits structured, redacted JSON logs. It must not import scanner or Cobra.
- `internal/health` checkers must not perform Elasticsearch I/O; the collector owns GET requests.
- Import cycles are release-blocking defects.

The target repository shape is introduced incrementally. Empty placeholder packages are not
created merely to match this diagram.

## 5. Stable domain contracts

These models describe intent. They become code only when their work package starts, and may be
refined before the first public schema release.

### 5.1 Target and endpoint

```go
type Target struct {
    Host       string
    Port       int
    SchemeHint Scheme
    Path       string
    Source     string
}

type Endpoint struct {
    Scheme string `json:"scheme"`
    Host   string `json:"host"`
    Port   int    `json:"port"`
    Path   string `json:"path,omitempty"`
}
```

Supported input forms include IPv4, IPv6, CIDR, hostname, host with port, and HTTP(S) URL.
Canonicalization preserves meaningful URL paths, handles IPv6 correctly, emits deterministic
validation errors, and streams CIDR expansion with bounded memory.

### 5.2 Probe and fingerprint

```go
type Prober interface {
    Probe(ctx context.Context, endpoint Endpoint) (ProbeResult, error)
}

type Signal struct {
    Name   string
    Weight int
    Match  bool
    Detail string
}
```

Elasticsearch identification must combine independent response-body, header, authentication,
and endpoint-semantics signals. Port 9200 alone is never a product signal. OpenSearch and generic
JSON APIs belong in the negative corpus.

Fingerprint classifications:

| Score | Classification |
|---:|---|
| 0–39 | Unknown |
| 40–69 | Possible |
| 70–89 | Likely |
| 90–100 | Confirmed |

The threshold is configurable, but the score and matched signals remain visible.

### 5.3 Findings and evidence

```go
type Finding struct {
    SchemaVersion string     `json:"schema_version"`
    ID            string     `json:"id"`
    CheckID       string     `json:"check_id"`
    Title         string     `json:"title"`
    Description   string     `json:"description,omitempty"`
    Target        Endpoint   `json:"target"`
    Product       string     `json:"product"`
    Version       string     `json:"version,omitempty"`
    Severity      Severity   `json:"severity"`
    Confidence    Confidence `json:"confidence"`
    CVSS          *float64   `json:"cvss,omitempty"`
    CVE           []string   `json:"cve,omitempty"`
    Evidence      []Evidence `json:"evidence,omitempty"`
    Remediation   string     `json:"remediation,omitempty"`
    References    []string   `json:"references,omitempty"`
    FirstSeen     time.Time  `json:"first_seen"`
    Tags          []string   `json:"tags,omitempty"`
}
```

Severity and confidence are independent. A critical, version-only match remains potentially
vulnerable; it is not reported as confirmed. Finding deduplication uses endpoint, stable check ID,
and normalized resource, while merging unique evidence.

### 5.4 Active-safe check contract

An active-safe check:

- sends the minimum request needed;
- does not write, delete, exploit, or change cluster state;
- obeys the same timeout, response-limit, rate, and cancellation policies as other requests;
- declares its prerequisites and evidence semantics;
- has a test proving the HTTP method and request path are non-state-changing.

## 6. CLI and process contract

```text
garga
├── scan
├── fingerprint
├── health
├── auth-check
├── auth-audit
├── vuln
├── update
├── report
└── version
```

Commands are added with the work package that implements their behavior. A command must not be
advertised before it has a complete execution path and tests.

Planned exit codes:

| Code | Meaning |
|---:|---|
| 0 | Success, regardless of whether findings exist |
| 1 | Unexpected internal or operational failure |
| 2 | Invalid CLI, configuration, or target input |
| 3 | Scan completed with partial operational failures |
| 4 | Signature update or validation failure |
| 5 | `garga health` collection, connection, authentication, product, or timeout failure |
| 10 | `garga health --fail-on`: highest finding is medium/warning |
| 11 | `garga health --fail-on`: highest finding is high |
| 12 | `garga health --fail-on`: highest finding is critical |
| 130 | Interrupted by the user |

`garga health --fail-on` uses 10/11/12 after a completed assessment. Invalid health flags and
configuration use 2, matching other commands. Collection failures use 5 so they cannot be
confused with signature-update failures (4).

Global configuration precedence is `CLI > environment > config file > built-in defaults`.
`--insecure` disables only TLS certificate verification; it never disables other safety controls.

## 7. Delivery roadmap

### Status legend

- `[ ]` Not started
- `[~]` In progress
- `[x]` Complete and validated

Work packages are completed in dependency order. Parallel work is allowed only when package
boundaries and acceptance tests are already stable.

### Milestone 0 — Repository foundation

#### [x] WP 0.1: Buildable CLI bootstrap

**Depends on:** none

**Deliverables**

- Go module and pinned Cobra dependency.
- `cmd/garga` entry point and testable root command.
- `version` command with linker-injectable version metadata.
- Focused unit tests for help, version output, and invalid arguments.
- Make targets for format checking, vetting, testing, race testing, and building.
- Idempotent `install.sh` installer with OS detection, dependency checks, atomic builds, install
  to `PREFIX/bin`, and actionable setup failures. It does not run garga commands.
- Read-only GitHub Actions CI on supported Go versions.
- README and security policy with explicit authorized-use boundaries.

**Acceptance criteria**

- `go build ./...`, `go test ./...`, and `go vet ./...` pass.
- `go test -race ./...` passes.
- `garga --help` and `garga version` return exit code 0.
- `install.sh` skips installation/build work for a current binary and copies it to `PREFIX/bin`.
- `garga version unexpected` fails and does not print a credential or environment value.
- No scanner, network, configuration, or placeholder domain abstraction is introduced.

#### [x] WP 0.2: Development governance

**Depends on:** WP 0.1

**Deliverables**

- Initial ADRs for safe defaults, package boundaries, and output versioning.
- Contribution guide, issue templates, dependency update policy, and release ownership.
- D-001 and D-002 resolved.

**Acceptance criteria**

- Public module path and license are consistent in module metadata and documentation.
- Contributor instructions reproduce all local validation commands.

### Milestone 1 — Input and configuration foundation

#### [x] WP 1.1: Canonical target parser

**Depends on:** WP 0.1

**Deliverables**

- Target model, parser, normalization, and port-list parsing.
- IPv4, IPv6, hostname, host:port, and URL support.
- Table-driven unit tests and parser fuzz target.

**Acceptance criteria**

- Malformed input never panics and returns deterministic, actionable errors.
- Equivalent target spellings normalize to one canonical endpoint.
- IPv6 zone and bracket behavior is explicitly tested.

#### [x] WP 1.2: Streaming target sources

**Depends on:** WP 1.1

**Deliverables**

- CIDR iterator, line-based file source, bounded deduplication policy, and source attribution.

**Acceptance criteria**

- CIDR expansion does not materialize the entire range.
- Cancellation stops production promptly.
- Scanner backpressure can stop the producer without a goroutine leak.
- Empty lines and comments have documented behavior.

#### [x] WP 1.3: Typed configuration

**Depends on:** WP 0.1

**Deliverables**

- Defaults, file loading, environment mapping, CLI overrides, and validation.
- Duration, rate, concurrency, retry, response-limit, and output settings.

**Acceptance criteria**

- Precedence is covered by tests.
- Invalid values fail before network activity.
- No credential value appears in formatted configuration or errors.

### Milestone 2 — Network execution core

#### [x] WP 2.1: HTTP/TLS transport

**Depends on:** WP 1.1, WP 1.3

**Deliverables**

- Shared transport/client factory, proxy support, TLS policy, explicit timeouts, redirect limit,
  response-body cap, user agent, and typed error classification.

**Acceptance criteria**

- `httptest` covers success, TLS, timeout, redirect, malformed response, and body-limit paths.
- Response bodies and idle connections are handled correctly.
- One transport is reused per compatible configuration, not per target.

#### [x] WP 2.2: Probe contract

**Depends on:** WP 2.1

**Deliverables**

- Probe result model that retains only bounded, fingerprint-relevant data.
- TCP/TLS/HTTP error taxonomy and sanitized request metadata.

**Acceptance criteria**

- Errors preserve causes without leaking headers or credentials.
- Probe results are deterministic for equivalent server responses.

#### [x] WP 3.1: Bounded scanner engine

**Depends on:** WP 1.2, WP 2.2, D-005

**Deliverables**

- Scheduler, bounded queue, worker pool, global/per-host limiter, transient retry policy, stats,
  and graceful cancellation.

**Acceptance criteria**

- Race detector passes.
- A 10,000-task synthetic test proves bounded goroutine and queue growth.
- Cancellation stops producers and requests, drains completed results, and closes output cleanly.
- Retries exclude authentication failures and deterministic parse failures.

### Milestone 3 — Elasticsearch assessment

#### [x] WP 4.1: Multi-signal fingerprint engine

**Depends on:** WP 2.2, D-003

**Deliverables**

- Elasticsearch root parser, weighted signals, score explanation, product/version extraction,
  and sanitized positive/negative response corpus.

**Acceptance criteria**

- Supported Elasticsearch fixtures reach the documented classification.
- Generic JSON, Kibana, nginx, Apache, and OpenSearch fixtures are not confirmed as Elasticsearch.
- Malformed and truncated responses do not panic.

#### [x] WP 4.2: Capability detection

**Depends on:** WP 4.1

**Deliverables**

- Capability model and version/response-aware discovery for root, health, state, nodes, cat,
  security, anonymous, Basic Auth, and API key behaviors.

**Acceptance criteria**

- Unsupported APIs suppress dependent checks without generating noisy failures.
- Capability discovery remains non-state-changing.

#### [x] WP 5.1: Exposure and TLS checks

**Depends on:** WP 4.2

**Deliverables**

- Check registry, TLS and public exposure findings, stable check IDs, evidence, and remediation.

**Acceptance criteria**

- Check applicability and finding deduplication are covered by tests.
- Findings contain no raw sensitive response body.

#### [x] WP 5.2: Anonymous access classification

**Depends on:** WP 4.2, WP 5.1

**Deliverables**

- `none`, `metadata`, `read`, `write`, and `admin` classifications based on safe evidence.

**Acceptance criteria**

- Normal execution sends no write or state-changing request.
- Write/admin classifications are clearly labeled as inferred unless passive evidence confirms them.

#### [x] WP 6.1: Explicit credential verification

**Depends on:** WP 4.2

**Deliverables**

- Basic Auth, API key, and `--password-stdin` support with centralized redaction.

**Acceptance criteria**

- Credentials do not appear in logs, errors, scan metadata, or reports.
- Command-line password leakage risk is documented if a password flag is retained.

#### [x] WP 6.2: Controlled credential audit

**Depends on:** WP 3.1, WP 6.1

**Deliverables**

- Isolated opt-in engine, per-host attempt ceiling, low default rate, backoff, cancellation,
  stop-on-success, and redacted audit events.

**Acceptance criteria**

- The `scan` command has no call path to the audit engine.
- Tests prove rate and attempt ceilings cannot be bypassed through retries.

### Milestone 4 — Vulnerabilities and reporting

#### [x] WP 7.1: Signature schema and version matcher

**Depends on:** WP 4.1

**Deliverables**

- Version-aware matcher, signature loader/validator, passive detection states, fixtures, and fuzzing.

**Acceptance criteria**

- Version comparison is semantic, not lexical.
- Invalid signatures are rejected without panic and include file-level context.
- Version-only matches never become confirmed findings.

#### [x] WP 7.2: Vulnerability evaluation

**Depends on:** WP 4.2, WP 5.1, WP 7.1

**Deliverables**

- Capability-aware matcher, finding conversion, active-safe contract, and registry integration.

**Acceptance criteria**

- Vulnerability knowledge remains outside compiled Go scanner logic.
- Active-safe requests are individually reviewed and tested for method/path safety.

#### [x] WP 8.1: Streaming reporters

**Depends on:** WP 5.1

**Deliverables**

- Console, JSON, JSONL, CSV, and standalone HTML writers with schema versioning.

**Acceptance criteria**

- JSON and JSONL parse successfully and use stable field names.
- JSONL can emit without retaining the complete scan.
- HTML uses contextual escaping and has no network dependency.
- Deterministic formats have stable ordering under repeated tests.

#### [x] WP 8.2: Secure signature updates

**Depends on:** WP 7.1, D-004

**Deliverables**

- Manifest client, checksum/signature verification, traversal-safe extraction, staging,
  atomic replacement, and rollback.

**Acceptance criteria**

- Interrupted or invalid updates leave the active database unchanged.
- Archive entries cannot escape staging or exploit symlinks.
- Every staged signature is validated before activation.

### Milestone 5 — Hardening and release

#### [x] WP 9.1: Observability and operational summary

**Depends on:** WP 3.1, WP 8.1

**Deliverables**

- Structured, redacted logs and bounded-cardinality scan statistics.

**Acceptance criteria**

- Hot paths avoid per-request debug noise by default.
- User-controlled values are not used as unbounded metric labels.

#### [x] WP 9.2: Performance baseline

**Depends on:** WP 3.1, WP 4.1, WP 8.1

**Deliverables**

- Parser, fingerprint, version, JSONL, and worker-pool benchmarks; 1k/10k/100k synthetic loads;
  documented CPU, allocation, memory, goroutine, throughput, and latency baselines.

**Acceptance criteria**

- No unbounded result accumulation or goroutine growth.
- Performance claims cite captured benchmark data and environment details.

#### [x] WP 10.1: Elasticsearch integration matrix

**Depends on:** WP 5.2, WP 6.1, WP 7.2

**Deliverables**

- Opt-in container tests for supported versions with authentication and TLS on/off.

**Acceptance criteria**

- Unit tests remain independent of Docker and the public internet.
- Integration failures preserve container and tool diagnostics without secrets.

#### [x] WP 10.2: Release engineering

**Depends on:** all previous work packages

**Deliverables**

- Cross-platform builds, checksums, SBOM, signed artifacts where available, release notes,
  responsible-use documentation, and reproducible release workflow.

**Acceptance criteria**

- Linux amd64/arm64, macOS amd64/arm64, and Windows amd64 builds pass.
- Release archives contain the expected license, documentation, and version metadata.
- All release gates in Section 11 pass from a clean checkout.

#### [x] WP 11.1: Product scan command

**Depends on:** WP 10.2

**Deliverables**

- Public `garga scan` command with target arguments and `--file`.
- `internal/app` orchestration from targets through fingerprint, capability discovery, checks,
  optional signatures, and streaming reports.
- GET-only product requests, no credentials, no credential-audit call path.
- Exit code `3` for completed scans with operational probe failures.
- CLI, httptest, isolation, and documentation coverage.

**Acceptance criteria**

- An operator can run a bounded, cancellable scan and obtain findings without changing remote state.
- Invalid targets and empty input exit `2`. Findings never fail the run.
- Isolation tests prove scan does not import the credential audit engine or signature updater.
- `make check` and `make test-race` pass.

#### [x] WP 11.2: Fingerprint command

**Depends on:** WP 11.1

**Deliverables**

- Public `garga fingerprint` command with the same target ingestion as scan.
- GET `/` only; streamed identity records (console, JSON, JSONL).
- No capability follow-ups, checks, signatures, or credentials.

**Acceptance criteria**

- Confirmed Elasticsearch identities are emitted without extra API probes.
- Non-Elasticsearch endpoints emit undetected identities rather than findings.
- Invalid formats, empty input, partial probe failures, and cancellation match the documented
  exit codes.
- `make check` and `make test-race` pass.

#### [x] WP 11.3: Vulnerability command

**Depends on:** WP 11.2

**Deliverables**

- Public `garga vuln` command with bundled signatures (optional `--signatures` override).
- Signature-only findings through capability-aware evaluation. No TLS/exposure checks.
- GET-only product requests; potential-only detection.

**Acceptance criteria**

- Matching versions emit `garga.vuln.*` findings without exposure check IDs.
- Missing or empty signature directories exit `2`.
- Isolation tests prove the command has no credential-audit call path.
- `make check` and `make test-race` pass.

#### [x] WP 12.1: Static analysis and vulnerability-scan CI gates

**Depends on:** WP 11.3

**Deliverables**

- Committed golangci-lint v2 configuration and `make lint` with a pinned analyzer version.
- Pull-request CI jobs for `make lint` and `make vulncheck`.
- Analyzer and vulnerability tools stay outside the runtime module graph.

**Acceptance criteria**

- `make lint` exits non-zero when the committed configuration reports issues.
- CI does not add a third-party GitHub Action for linting.
- `make check` and `make test-race` still pass.

#### [x] WP 12.2: GET-only transport request contract

**Depends on:** WP 12.1

**Deliverables**

- `transport.NewRequest` and `Client.Do` accept only `GET` with no request body.
- Redirects that would change the method or attach a body are rejected.
- Tests prove non-GET methods never reach a test server.

**Acceptance criteria**

- POST, PUT, PATCH, DELETE, HEAD, empty method, and GET bodies fail as `invalid_request`.
- GET probe, credential, update, and scan paths remain successful.
- `make check` and `make test-race` pass.

#### [x] WP 12.3: Shared Elasticsearch GET path catalog

**Depends on:** WP 12.2

**Deliverables**

- Extra-probe catalog is the single source of GET API suffixes.
- Credential verification uses `capability.PathAuthenticate`.
- Tests reject Get User `/_security/user/_authenticate`.

**Acceptance criteria**

- The allowlist cannot drift from the extra-probe catalog.
- `auth-check` and capability discovery share the Authenticate path.
- `make check` and `make test-race` pass.

#### [x] WP 12.4: Signature fixture validation in CI

**Depends on:** WP 12.3

**Deliverables**

- `scripts/validate-signatures` loads a directory through `vulnerability.LoadDir`.
- `make signatures-validate` and a pull-request CI step against committed fixtures.

**Acceptance criteria**

- Valid fixtures load; invalid YAML exits `2` with file context.
- The validator does not import Cobra or the CLI.
- `make check` and `make test-race` pass.

#### [x] WP 13.1: Read-only health assessment command

**Depends on:** WP 12.4

**Deliverables**

- Public `garga health TARGET` command for one Elasticsearch cluster.
- Centralized GET-only collector, version-tolerant snapshot, 37 I/O-free checkers, scoring,
  correlation, and terminal/JSON/HTML/Markdown reports with a timestamped HTML artifact.
- Optional authentication via stdin or `ESHEALTH_*`, refused over HTTP unless
  `--allow-plaintext-auth` is set and reported as critical.
- Secret-free baseline/delta snapshots, profiles, thresholds, and `--deep` high-cost collectors.

**Acceptance criteria**

- Product identification rejects OpenSearch and Elasticsearch before 7.17.
- Checkers never perform network I/O; missing collectors skip affected checks.
- Credentials never appear in reports, logs, or baseline files.
- `--fail-on` uses dedicated codes 10/11/12; collection failures use 5; invalid input uses 2.
- `make check` and `make test-race` pass.

## 8. Testing strategy

| Layer | Purpose | Required tools |
|---|---|---|
| Unit | Deterministic business and parsing behavior | Go `testing`, table-driven tests |
| HTTP contract | Transport and product response behavior | `httptest.Server` / `httptest.NewTLSServer` |
| Fuzz | Untrusted parsers and version expressions | Native Go fuzzing |
| Race | Worker pools, cancellation, reporters | `go test -race ./...` |
| Integration | Real supported Elasticsearch behavior | Opt-in container matrix |
| Load/benchmark | Resource bounds and regression baseline | Go benchmarks and synthetic endpoints |

Every bug fix should add a regression test when practical. Tests must avoid the public internet,
wall-clock timing assumptions, machine-specific paths, execution-order dependence, and shared
mutable state.

Required fixture categories:

- Elasticsearch supported-major root responses.
- Authentication required and forbidden responses.
- TLS and reverse-proxy behavior.
- OpenSearch, Kibana, generic JSON, nginx, and Apache negatives.
- Malformed JSON, truncated bodies, slow responses, redirects, and oversized bodies.
- Valid and invalid signatures, including prerelease/build version cases.

## 9. CI and validation policy

Pull-request CI runs:

1. formatting check;
2. `go vet ./...`;
3. `go test ./...` on Go 1.26 and Go 1.27;
4. `go test -race ./...` on the primary CI version;
5. `go build ./...`;
6. `make signatures-validate` against committed YAML fixtures;
7. `make lint` with the committed `.golangci.yml`;
8. `make vulncheck`.

Integration and fuzz campaigns run separately because their resource and time profiles differ.
The Elasticsearch container matrix is `make integration` / `workflow_dispatch` on
`.github/workflows/integration.yml`. No task is reported complete when an applicable required
command fails. A skipped command must be reported with its reason.

## 10. Delivery controls

### 10.1 Definition of Ready

A work package is ready when:

- its dependencies and blocking decisions are complete;
- input/output contracts and safety boundaries are understood;
- test fixtures can be created without production access;
- acceptance criteria are observable;
- the change can be reviewed as one coherent increment.

### 10.2 Definition of Done

A work package is done when:

- requested behavior and error paths are implemented;
- tests cover normal, boundary, invalid-input, and relevant failure cases;
- applicable format, vet, test, race, lint, and build commands pass;
- public behavior/configuration changes are documented;
- compatibility, security, performance, and resource cleanup were reviewed;
- the final diff contains no unrelated edits, secrets, debug code, stale comments, or vague TODOs;
- roadmap status and implemented ADRs are updated.

### 10.3 Change review priorities

Review findings are handled in this order:

1. P0 — compromise, data loss/corruption, authorization bypass, unusable application;
2. P1 — major correctness, reliability, concurrency, or severe performance defect;
3. P2 — moderate defect, incomplete validation, or maintainability concern;
4. P3 — cleanup, naming, and cosmetic improvement.

## 11. v1 release gates

### Functional

- All work packages through WP 13.1 are complete.
- Target parsing, scanning, fingerprinting, health assessment, checks, vulnerability matching, updates, and reporters
  meet their acceptance criteria.
- Exit codes and machine-output schemas are documented and regression-tested.

### Safety and security

- Default scans are demonstrably non-state-changing.
- Credential audit is isolated, explicit, bounded, cancellable, and secret-safe.
- Signature updates verify authenticity/integrity and are atomic.
- HTML output is escaped; archives reject traversal and unsafe symlinks.
- Dependency and binary vulnerability scans have no unresolved release-blocking issue.

### Reliability and performance

- Unit, integration, race, lint, fuzz smoke, and cross-build jobs pass.
- A 10,000-target load test has no unbounded memory, queue, or goroutine growth. Captured 1k/10k/100k
  synthetic loads and microbenchmarks are recorded in `docs/performance.md`.
- Baseline throughput, p95 latency, allocation, and peak-memory measurements are recorded.

### Documentation and operations

- README, security policy, responsible-use guidance, configuration reference, output schema,
  signature authoring guide, and release notes are current.
- Supported Go and Elasticsearch versions are explicit.
- Rollback procedures exist for both binaries and signature databases.

## 12. Risk register

| Risk | Probability | Impact | Mitigation | Validation |
|---|---|---|---|---|
| False Elasticsearch positives | Medium | High | Weighted signals and negative corpus | Fixture precision tests |
| Accidental state-changing request | Low | Critical | Method allowlist and active-safe contract | Request-capture tests |
| Credential leakage | Medium | Critical | Central redaction and no raw request logging | Canary-secret tests |
| Unbounded CIDR/resource use | Medium | High | Streaming producers, bounded queues and limits | 100k synthetic load |
| Goroutine leak on cancellation | Medium | High | Context ownership and close protocol | Race and leak-oriented tests |
| Signature supply-chain compromise | Low | Critical | Trust root, checksums, signatures, staging | Tamper/interruption tests |
| Output schema drift | Medium | Medium | Schema version and golden compatibility tests | Artifact regression tests |
| Elasticsearch API variance | High | Medium | Supported-version matrix and capability checks | Container integration matrix |
| Retry amplification | Medium | High | Transient-only retries and retry budget | Fault-injection tests |

Risk entries are reviewed when a work package changes probability, impact, or mitigation.

## 13. Immediate execution queue

1. Adding an Elasticsearch product GET still requires a catalog entry in `internal/capability`
   and an active-safe test. Do not duplicate Authenticate as Get User.
2. The planned CLI tree is implemented, including `garga health`. Do not add authenticated scan
   or extra product commands until a later, explicit work package defines them.

The implementation cadence is always:

```text
contract -> tests -> implementation -> validation -> documentation -> diff review
```
