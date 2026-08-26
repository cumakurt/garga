# garga

garga is a safe-by-default command-line tool for authorized Elasticsearch security
assessments. The project is in early development; the current implementation provides the CLI
bootstrap, target input, configuration, HTTP transport, bounded scanner engine, Elasticsearch
fingerprinting, capability discovery, TLS/exposure checks, anonymous access classification,
explicit single-credential verification, an isolated opt-in credential audit, YAML
vulnerability signatures with semantic version matching and capability-aware evaluation,
streaming console, JSON, JSONL, CSV, and standalone HTML reports, signed signature-database
updates, structured JSON logs with a bounded scanner summary, captured performance baselines,
and an opt-in Elasticsearch container matrix. A product `scan` command is not exposed yet.

## Safety boundary

garga is intended only for systems you own or are explicitly authorized to assess. The planned
default scan path is non-destructive: it will not exploit vulnerabilities, modify cluster state,
write or delete data, or perform implicit credential spraying.

See [SECURITY.md](SECURITY.md) for vulnerability reporting and operational safety guidance.

## Requirements

- Go 1.26 or later on a supported Go release line.
- GNU Make is optional; all validation commands can also be run directly with Go tooling.

## Quick start

```sh
./run.sh
```

The launcher detects Linux, macOS, FreeBSD, OpenBSD, NetBSD, and Windows-compatible Unix shells.
When the current binary is ready, it skips dependency installation and rebuilding. Otherwise it:

1. checks the Go version and Git;
2. installs missing tools through a supported system package manager;
3. downloads only missing Go modules and verifies the module cache;
4. builds to a temporary file and atomically replaces `bin/garga` after a successful build;
5. runs the application help and prints working examples.

Supported automatic package managers include `apt-get`, `dnf`, `yum`, `pacman`, `zypper`,
`apk`, Homebrew, BSD package managers, and `winget` from a Windows-compatible shell. The launcher
does not execute remote install scripts. If a package manager is unavailable or provides an old
Go version, it prints the exact manual action required and leaves the existing binary untouched.

```sh
./run.sh --help
./run.sh --setup-only
./run.sh version
./run.sh --rebuild version
./run.sh -- --help
```

## Build

```sh
go build -o bin/garga ./cmd/garga
./bin/garga --help
./bin/garga version
```

The canonical Go module and repository path is `github.com/cumakurt/garga`.

## Validate

```sh
make check
make test-race
shellcheck run.sh tests/run_sh_test.sh
```

`make bench` is optional. It records machine-specific microbenchmarks used by
[docs/performance.md](docs/performance.md) and is not part of `make check`.

`make integration` is optional. It starts Elasticsearch containers and may pull
`docker.elastic.co` images; see [docs/integration.md](docs/integration.md).

The implementation roadmap, acceptance criteria, and release gates are defined in
[garga-MASTER-PLAN.md](garga-MASTER-PLAN.md).

The canonical parsing, target-file grammar, lazy CIDR expansion, and bounded deduplication
contracts are documented in [docs/target-input.md](docs/target-input.md).

Configuration precedence, fields, environment mappings, limits, and the secret boundary are
documented in [docs/configuration.md](docs/configuration.md). A complete starting file is
available at [garga.example.yaml](garga.example.yaml).

The reusable HTTP/TLS client, proxy, timeout, redirect, response-limit, and error-classification
contracts are documented in [docs/transport.md](docs/transport.md).

The bounded product-neutral response model, header allowlist, sanitized request metadata, and
probe error taxonomy are documented in [docs/probe.md](docs/probe.md).

The bounded worker/queue/order window, global and per-host rate policy, retry rules, statistics,
and cancellation lifecycle are documented in [docs/scanner.md](docs/scanner.md).

The Elasticsearch signal weights, score bands, strict root/version parsing, supported fixture
matrix, negative corpus, and redaction rules are documented in
[docs/fingerprint.md](docs/fingerprint.md).

Capability discovery, the GET-only API allowlist, availability classification, and check
suppression rules are documented in [docs/capability.md](docs/capability.md).

The check registry, stable check identifiers, finding schema `0.1`, evidence redaction,
anonymous access classes, and deduplication rules are documented in
[docs/checks.md](docs/checks.md).

Explicit credential verification, stdin secret input, and redaction rules are documented in
[docs/credentials.md](docs/credentials.md). Isolated credential audit ceilings, rates, and
isolation rules are documented in [docs/credential-audit.md](docs/credential-audit.md).

Vulnerability signature schema `0.1`, semantic version ranges, potential-only detection,
and capability-aware finding conversion are documented in [docs/signatures.md](docs/signatures.md).

Streaming console, JSON, JSONL, CSV, and standalone HTML reports, finding schema `0.1`, and
`garga report` are documented in [docs/reports.md](docs/reports.md).

Signed signature-database updates, the Ed25519 trust root, staging, and rollback are documented
in [docs/signature-updates.md](docs/signature-updates.md).

Structured JSON logs, secret redaction, and the scanner summary schema are documented in
[docs/observability.md](docs/observability.md).

Captured parser, fingerprint, version, JSONL, and worker-pool timings are documented in
[docs/performance.md](docs/performance.md).

The opt-in Elasticsearch container matrix (authentication and TLS on/off) is documented in
[docs/integration.md](docs/integration.md).

## Contributing and license

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, engineering, validation, and contribution
requirements. Governance decisions are recorded in [docs/adr](docs/adr), with dependency and
release responsibilities documented under [docs](docs).

garga is licensed under [GNU AGPL v3.0 only](LICENSE) (`AGPL-3.0-only`).

## Project status

The project is pre-release. CLI, configuration, and machine-output compatibility guarantees do
not begin until they are explicitly documented for a tagged release.
