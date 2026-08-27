# garga

<p align="center">
  <img src="garga.png" alt="garga — Elasticsearch security assessment CLI" width="720">
</p>

garga is a safe-by-default command-line tool for **authorized Elasticsearch security
assessments**. It discovers reachable services, identifies Elasticsearch from multiple
independent signals, evaluates exposure without changing cluster state, optionally matches
YAML vulnerability signatures, and streams evidence-backed reports.

The project is **pre-release**. CLI flags, configuration keys, and finding schema `0.1` are
implemented and tested, but they are not a tagged compatibility promise until a public
release documents them as such.

| | |
|---|---|
| Module | [`github.com/cumakurt/garga`](https://github.com/cumakurt/garga) |
| License | [GNU AGPL v3.0 only](LICENSE) (`AGPL-3.0-only`) |
| Language | Go 1.26 or later (CI also tests Go 1.27) |
| Product | Elasticsearch only; OpenSearch is treated as a negative fingerprint |

- [Safety boundary](#safety-boundary)
- [What garga does](#what-garga-does)
- [Requirements](#requirements)
- [Install](#install)
- [Commands](#commands)
- [Targets](#targets)
- [Configuration](#configuration)
- [Reports and logs](#reports-and-logs)
- [Exit codes](#exit-codes)
- [Elasticsearch support](#elasticsearch-support)
- [Development](#development)
- [Documentation](#documentation)
- [Contributing and license](#contributing-and-license)

## Safety boundary

Use garga only against systems you **own** or are **explicitly authorized** to assess.
Unauthorized scanning, credential guessing, or exploitation is outside the project's purpose
and may be illegal. Operator rules are in [docs/responsible-use.md](docs/responsible-use.md).
Vulnerability reporting is in [SECURITY.md](SECURITY.md).

The default assessment path (`garga scan`, `garga fingerprint`, `garga vuln`) is
non-destructive:

- product HTTP requests are **GET only**, with no request body;
- garga does not exploit vulnerabilities or attempt remote code execution;
- it does not create, update, or delete indices, documents, users, or cluster settings;
- it does not send credentials or spray passwords;
- `--insecure` skips TLS certificate verification only (not rate limits, timeouts, retries,
  redaction, or the GET-only contract).

Credential work is isolated:

- `garga auth-check` verifies **one** explicit credential from stdin;
- `garga auth-audit` is opt-in, rate-limited, and attempt-limited, with an explicit stdin list;
- neither command accepts a `--password` flag;
- YAML configuration and `GARGA_*` variables never hold secrets.

Authenticate uses Elasticsearch `GET /_security/_authenticate`.
`GET /_security/user/_authenticate` is Get User and is not used.

## What garga does

Implemented operator commands:

| Command | Role |
|---|---|
| `garga scan` | GET `/`, fingerprint, GET-only capability discovery, TLS/exposure checks, bundled CVE matching |
| `garga health` | Advanced GET-only cluster/node/index health, capacity, performance, configuration, backup, and security assessment |
| `garga fingerprint` | GET `/` product identity only |
| `garga vuln` | Signature-only potential CVE matching (bundled corpus; `--signatures DIR` optional) |
| `garga auth-check` | One credential, `GET /_security/_authenticate` |
| `garga auth-audit` | Explicit bounded credential audit |
| `garga report` | Offline JSONL → console/JSON/JSONL/CSV/HTML |
| `garga update` | Signed signature-database install and one-generation rollback |
| `garga version` | Build metadata |

Supporting behavior already in the binary:

- streaming targets (hosts, CIDRs, URLs, files, stdin) with lazy CIDR expansion and bounded
  exact deduplication;
- bounded workers, global and per-host rate limits, transient retries, and cancellation;
- reusable HTTP/TLS transport (timeouts, proxy, redirects, response size limits);
- multi-signal Elasticsearch fingerprinting (OpenSearch is never treated as Elasticsearch);
- GET-only API catalog and capability classification;
- finding schema `0.1` with redacted evidence;
- structured JSON logs on stderr (secrets redacted);
- signed Ed25519 signature bundles, staging, and rollback.

garga does **not** provide exploitation, writes, a web UI, distributed scanning, or products
other than Elasticsearch.

## Requirements

- Go **1.26** or later on a supported Go release line (needed to build from source).
- GNU Make is optional; equivalent Go commands are listed under [Development](#development).
- A POSIX-compatible shell if you use `./install.sh` (Linux, macOS, FreeBSD, OpenBSD, NetBSD,
  or a Windows-compatible Unix shell).

## Install

### From a source checkout (`install.sh`)

```sh
./install.sh
```

`install.sh` **only installs**. It does not run `garga` commands.

It detects the OS, installs missing Go/Git through a supported system package manager when
needed, downloads missing Go modules, builds `bin/garga` atomically, and copies the binary to
`PREFIX/bin` (default `/usr/local/bin`). When `bin/garga` is already current, it skips the
rebuild.

Writing under `/usr/local` typically requires root:

```sh
sudo ./install.sh
```

User-local install (if `~/.local/bin` is on `PATH`):

```sh
./install.sh --prefix "$HOME/.local"
```

| Option / variable | Effect |
|---|---|
| `-h`, `--help` | Installer usage only |
| `--rebuild` | Rebuild even when `bin/garga` is current |
| `--prefix DIR` / `PREFIX` | Install into `DIR/bin` (default `/usr/local`) |
| `DESTDIR` | Staging root prepended to `PREFIX` |

Supported automatic package managers include `apt-get`, `dnf`, `yum`, `pacman`, `zypper`,
`apk`, Homebrew, BSD package managers, and `winget` from a Windows-compatible shell. The
installer does not execute remote install scripts. If a manager is missing or supplies an old
Go version, it prints the manual action and leaves the existing binary untouched.

After installation:

```sh
garga --help
garga version
```

### With Make

```sh
make build                 # writes bin/garga
sudo make install          # copies to $(PREFIX)/bin/garga
sudo make uninstall
```

`PREFIX` defaults to `/usr/local`. `DESTDIR` is supported for staged installs.

### Manual build

```sh
go build -o bin/garga ./cmd/garga
./bin/garga --help
```

Release archives, checksums, and SBOMs are produced with `make release VERSION=vX.Y.Z` and
documented in [docs/release.md](docs/release.md). There is no tagged binary yet.

## Commands

Logs go to **stderr**. Findings and command results go to **stdout**.

### `garga scan`

Default assessment: probe targets, fingerprint Elasticsearch, discover GET-only capabilities,
and emit exposure findings plus potential CVE matches from the bundled Elasticsearch corpus.
`--signatures DIR` replaces that corpus. `--no-signatures` keeps TLS/exposure checks only.
Scan does not fetch signature bundles and does not send credentials.

```sh
garga scan 192.0.2.10
garga scan https://es.example.internal:9200 --format jsonl
garga scan --file targets.txt --format csv
garga scan --file - < targets.txt
```

Useful flags: `--file`, `--format` (`console`, `json`, `jsonl`, `csv`, `html`), `--config`,
`--signatures`, `--no-signatures`, `--no-progress`, `--insecure`, `--concurrency`, `--rate`,
`--per-host-rate`, `--max-targets`.

On a terminal, large or slow scans draw a live progress bar on stderr (counters only; no hosts).
`--no-progress` disables it. Findings stay on stdout.

CSV, JSON, JSONL, and HTML write machine output to stdout and a human detection summary to
stderr. Console already prints that summary on stdout.

Pipeline: canonicalize targets → bounded `GET /` → local fingerprint → capability GETs on
likely/confirmed endpoints → check registry and bundled CVE matching → streaming report.
Credential verification is not on this path. Findings do not fail the run: exit `0` means the
scan finished; exit `3` means at least one probe failed operationally.

Default exposure checks (no extra I/O beyond capability discovery):

| Check ID | Finding |
|---|---|
| `garga.tls.not_enabled` | Elasticsearch reached over HTTP |
| `garga.exposure.anonymous_access` | Unauthenticated access (`metadata` / `read` / `write` / `admin`) |
| `garga.exposure.security_unconfigured` | Security APIs missing |
| `garga.exposure.public_network` | Target is a public unicast IP (hostnames are not resolved) |

Details: [docs/scan.md](docs/scan.md), [docs/checks.md](docs/checks.md).

### `garga health`

Assess one Elasticsearch cluster through bounded, read-only APIs. The command collects a
normalized cluster snapshot, executes version-aware health checkers, correlates root causes,
calculates a weighted score, and reports skipped collectors when an API, permission, or version
is unavailable.

```sh
garga health https://es-prod.example.com --profile production --deep --format terminal
garga health https://es-prod.example.com --format json --fail-on high
garga health https://es-prod.example.com --snapshot-out baseline.json
garga health https://es-prod.example.com --baseline baseline.json
```

Normal mode avoids the higher-cost ILM, task, data-stream, node-settings, and snapshot collectors.
`--deep` enables those checks. Credentials may be provided with `--username` and
`--password-stdin`, `--api-key-stdin`, or `--bearer-token-stdin`. Credential transmission over
plain HTTP is refused unless `--allow-plaintext-auth` is explicitly supplied, and that condition
is reported as critical. Output formats are `terminal`, `json`, `html`, and `markdown`. Regardless
of the selected stdout format, every completed assessment also writes a timestamped, standalone
HTML report to the current directory and prints its path on stderr. The light-theme report embeds
`garga.png` and includes executive, technical, remediation, coverage, and telemetry sections.

Details: [docs/health.md](docs/health.md).

### `garga fingerprint`

`GET /` only. No extra APIs, no exposure checks, no signatures, no credentials.

```sh
garga fingerprint 192.0.2.10
garga fingerprint --file targets.txt --format jsonl
garga fingerprint https://es.example.internal:9200 --threshold 80
```

`--format` accepts `console`, `json`, or `jsonl` (`csv` and `html` are rejected). Identities use
schema `0.1` with event `fingerprint.identity`. `--threshold` overrides `fingerprint.threshold`
(default 80). Score bands: 0–39 `unknown`, 40–69 `possible`, 70–89 `likely`, 90–100 `confirmed`.
Port 9200 is never treated as product evidence. OpenSearch markers override coincidental
Elasticsearch field shapes.

Details: [docs/fingerprint.md](docs/fingerprint.md).

### `garga vuln`

Signature-only matching against the bundled Elasticsearch CVE corpus. `--signatures DIR`
replaces the corpus. TLS and exposure checks are omitted; use `garga scan` for those. Hits stay
**potential** (version evidence, not confirmed CVEs).

```sh
garga vuln 192.0.2.10
garga vuln --file targets.txt --format csv
garga vuln --signatures /var/lib/garga/current 192.0.2.10
```

Target and pacing flags match `garga scan`. Details: [docs/signatures.md](docs/signatures.md).

### `garga auth-check`

One target, one credential, one `GET /_security/_authenticate`.

```sh
garga auth-check https://es.example.internal:9200 --username elastic --password-stdin
garga auth-check https://es.example.internal:9200 --api-key-stdin
```

Passwords and API keys must come from stdin. Output is a secret-free status line
(`valid` / `invalid` / `security_unavailable`, …). Details: [docs/credentials.md](docs/credentials.md).

### `garga auth-audit`

Isolated opt-in audit. Not invoked by `scan`. Default rate is 1 request/second. Default
per-host ceiling is 5 attempts (`--max-attempts` at most 20). At most 32 credentials. Stops on
the first valid credential, missing security API, ceiling, or cancellation.

```sh
garga auth-audit https://es.example.internal:9200 --credentials-stdin <<'EOF'
basic elastic example-password
api_key example-id:example-key
EOF
```

Details: [docs/credential-audit.md](docs/credential-audit.md).

### `garga report`

Offline. Reads JSONL findings (stdin or `--input`) and writes console, JSON, JSONL, CSV, or
standalone HTML. Invalid records exit `2` without echoing the payload. HTML has no scripts or
external resources.

```sh
garga scan --format jsonl 192.0.2.10 > findings.jsonl
garga report --format html --input findings.jsonl > report.html
```

Details: [docs/reports.md](docs/reports.md).

### `garga update`

Installs a signed signature database. `--dir` is required. `--source` is a local directory or
HTTP(S) directory URL containing `manifest.json`, `manifest.sig`, and `signatures.zip`. The
embedded Ed25519 trust root verifies the manifest. Failures exit `4` and leave `current/`
unchanged.

```sh
garga update --source https://example.internal/garga-signatures/ --dir /var/lib/garga
garga update --rollback --dir /var/lib/garga
```

Point `garga scan --signatures` / `garga vuln --signatures` at that `current/` directory.
Details: [docs/signature-updates.md](docs/signature-updates.md).

### `garga version`

Prints version, commit, and related build metadata (linker-injectable for releases).

## Targets

`scan`, `fingerprint`, and `vuln` accept arguments, `--file`, or both (arguments first, then
file lines). `--file -` reads stdin. Unique-target ceiling defaults to 1,000,000
(`--max-targets`). Exhausting it exits `2`.

Accepted forms include IPv4/IPv6, hostnames, optional ports, HTTP(S) URLs with a reverse-proxy
base path, and CIDRs. URL userinfo, query strings, and fragments are rejected.

```text
# targets.txt
es-a.example.org:9200
192.0.2.0/28
https://[2001:db8::20]:9243/elastic
```

Grammar, lazy CIDR expansion, and deduplication: [docs/target-input.md](docs/target-input.md).

## Configuration

Precedence, lowest to highest:

1. built-in defaults
2. explicit YAML (`--config` or `GARGA_CONFIG`)
3. `GARGA_*` environment variables
4. command-line overrides (`--concurrency`, `--rate`, `--per-host-rate`, `--format`,
   `--threshold` on `fingerprint`, and health flags such as `--profile` and `--max-response-bytes`)

garga does not search the working directory or home directory for an implicit config file.
Start from [garga.example.yaml](garga.example.yaml). Files are at most 1 MiB, one YAML
document, unknown fields rejected.

| YAML | Environment | Default |
|---|---|---|
| `scanner.concurrency` | `GARGA_CONCURRENCY` | `20` |
| `scanner.requests_per_second` | `GARGA_RATE` | `50` |
| `scanner.per_host_requests_per_second` | `GARGA_PER_HOST_RATE` | `5` |
| `scanner.connect_timeout` | `GARGA_CONNECT_TIMEOUT` | `2s` |
| `scanner.request_timeout` | `GARGA_REQUEST_TIMEOUT` | `5s` |
| `scanner.retries` | `GARGA_RETRIES` | `1` |
| `scanner.max_response_bytes` | `GARGA_MAX_RESPONSE_BYTES` | `524288` |
| `fingerprint.threshold` | `GARGA_FINGERPRINT_THRESHOLD` | `80` |
| `health.profile` | `GARGA_HEALTH_PROFILE` | `standard` |
| `health.concurrency` | `GARGA_HEALTH_CONCURRENCY` | `4` |
| `health.requests_per_second` | `GARGA_HEALTH_RATE` | `5` |
| `health.top_n` | `GARGA_HEALTH_TOP_N` | `5` |
| `health.max_response_bytes` | `GARGA_HEALTH_MAX_RESPONSE_BYTES` | `33554432` |
| `output.format` | `GARGA_OUTPUT_FORMAT` | `console` |
| `logging.level` | `GARGA_LOG_LEVEL` | `warn` |

Credential audit does not use scanner rate settings. Full limits and validation:
[docs/configuration.md](docs/configuration.md).

## Reports and logs

Machine formats use finding schema `0.1` (pre-release; not the public `1.0` contract).

| Format | Use |
|---|---|
| `console` | Grouped by target; exploitable findings first, then severity; color on a TTY (`NO_COLOR` disables) |
| `jsonl` | One finding object per line; streaming |
| `json` | `{"schema_version":"0.1","findings":[...]}` |
| `csv` | Header plus one row per finding |
| `html` | Standalone, escaped, no scripts or network resources; exploitable rows highlighted |

Logs are JSON on stderr. Default `warn` does not emit scanner start/finish or per-probe lines.
Set `GARGA_LOG_LEVEL=info` for the bounded scan summary, or `debug` for per-probe records.
Credentials, tokens, and authorization material are redacted. See
[docs/observability.md](docs/observability.md).

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | Success. Findings do not fail `scan` / `fingerprint` / `vuln`. `garga health` also exits 0 when `--fail-on` is unset or the highest finding is below that threshold. |
| 1 | Unexpected internal or output failure. For `garga health --fail-on`, also used when the highest finding is medium/warning. |
| 2 | Invalid CLI, configuration, target input, or signature directory. For `garga health --fail-on`, also used when the highest finding is high. |
| 3 | Run finished, but at least one probe failed operationally. For `garga health --fail-on`, also used when the highest finding is critical. |
| 4 | Signature update verification, archive, or validation failure. `garga health` also uses 4 for connection, authentication, product, configuration, or collection errors, including invalid health flags. |
| 130 | Interrupted |

## Elasticsearch support

| Tier | Lines | Contract |
|---|---|---|
| Fully supported | 8.19.x, 9.3.x, 9.4.x | Fingerprint, capability, checks, credentials, signatures, opt-in containers |
| Legacy detection | 7.17.x, 8.0–8.18, 9.0–9.2 | Fingerprint, version extraction, passive signatures; API coverage is capability-driven |
| Unsupported | Before 7.17 | May fingerprint as `possible`; no complete check/vuln claim |
| Negative | OpenSearch | Never treated as an Elasticsearch compatibility line |

Policy: [docs/adr/0005-elasticsearch-version-support.md](docs/adr/0005-elasticsearch-version-support.md).
Opt-in live containers: [docs/integration.md](docs/integration.md).

## Development

```sh
make check          # fmt-check, shell-test, vet, unit tests, signatures-validate, build
make test-race
make lint           # pinned golangci-lint v2; downloads on first use; not part of check
make signatures-validate
make vulncheck      # govulncheck; use Go 1.26.6+ or 1.27.0+
make fuzz-smoke
shellcheck install.sh tests/install_sh_test.sh
```

`make check` is the default pull-request unit/format/shell/signature gate. `make lint` and
`make vulncheck` are additional PR/release gates.

Optional:

| Target | Notes |
|---|---|
| `make bench` | Machine-specific microbenchmarks; [docs/performance.md](docs/performance.md) |
| `make integration` | Elasticsearch containers; may pull `docker.elastic.co` images |
| `make release VERSION=vX.Y.Z` | Cross-platform archives, SBOM, `SHA256SUMS` |

Roadmap and acceptance criteria: [garga-MASTER-PLAN.md](garga-MASTER-PLAN.md).

## Documentation

| Topic | Document |
|---|---|
| Authorized use | [docs/responsible-use.md](docs/responsible-use.md), [SECURITY.md](SECURITY.md) |
| Scan command | [docs/scan.md](docs/scan.md) |
| Health assessment | [docs/health.md](docs/health.md) |
| Fingerprint | [docs/fingerprint.md](docs/fingerprint.md) |
| Targets | [docs/target-input.md](docs/target-input.md) |
| Configuration | [docs/configuration.md](docs/configuration.md), [garga.example.yaml](garga.example.yaml) |
| Transport | [docs/transport.md](docs/transport.md) |
| Probes | [docs/probe.md](docs/probe.md) |
| Scanner engine | [docs/scanner.md](docs/scanner.md) |
| Capabilities | [docs/capability.md](docs/capability.md) |
| Checks and findings | [docs/checks.md](docs/checks.md) |
| Credentials | [docs/credentials.md](docs/credentials.md) |
| Credential audit | [docs/credential-audit.md](docs/credential-audit.md) |
| Signatures | [docs/signatures.md](docs/signatures.md) |
| Signature updates | [docs/signature-updates.md](docs/signature-updates.md) |
| Reports | [docs/reports.md](docs/reports.md) |
| Logs | [docs/observability.md](docs/observability.md) |
| Performance | [docs/performance.md](docs/performance.md) |
| Integration matrix | [docs/integration.md](docs/integration.md) |
| Releases | [docs/release.md](docs/release.md) |
| Architecture decisions | [docs/adr](docs/adr) |
| Changelog | [CHANGELOG.md](CHANGELOG.md) |

## Contributing and license

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, engineering, validation, and contribution
requirements. Dependency policy is in [docs/dependency-policy.md](docs/dependency-policy.md).

By submitting a contribution you agree it is licensed under `AGPL-3.0-only`.
