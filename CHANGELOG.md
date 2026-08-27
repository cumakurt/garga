# Changelog

All notable changes to garga are documented in this file.

## Unreleased

### Added

- `garga health` advanced read-only Elasticsearch assessment with centralized collection and
  normalization, 37 version-aware health checkers, weighted root-cause scoring, correlation,
  partial-failure coverage, scanner telemetry, terminal/JSON/HTML/Markdown reports, configurable
  profiles and thresholds, optional deep collection, and secret-free baseline/delta snapshots.
- Every completed health assessment writes a timestamped, owner-only standalone PDF artifact
  (`garga-health-*.pdf`) in the current directory. The report covers executive summary, detailed
  evidence, correlations, remediation, coverage, and telemetry. `--html-report` (or
  `output.html_report` / `GARGA_OUTPUT_HTML_REPORT`) also writes the matching HTML document.
- Every completed `garga scan` writes a timestamped, owner-only standalone PDF artifact
  (`garga-scan-*.pdf`) in the current directory. The artifact is a penetration-test report
  structured to PTES, NIST SP 800-115, OWASP, and CREST (document control, disclaimer, scope,
  methodology, risk rating, technical findings with evidence, attack scenarios, remediation,
  and appendices). `--html-report` also writes the matching HTML report. Stdout `--format` is
  unchanged except that `--format html` evidence cells include observed proof lines. Console
  scan output always prints evidence for each finding.
- Standalone health and scan HTML reports include clickable developer LinkedIn and GitHub
  links in the footer. PDF artifacts include the same identity as plain-text URLs.

- Cross-platform release archives, SHA-256 checksums, SPDX SBOMs, and an optional GPG signature
  of `SHA256SUMS`.
- Responsible-use guidance and a documented binary/signature rollback procedure.
- `garga scan` for bounded, GET-only Elasticsearch assessments with streaming reports.
- `garga fingerprint` for GET `/` product identity without exposure checks.
- `garga vuln` for signature-only potential vulnerability matching.
- Committed golangci-lint v2 configuration, `make lint`, and pull-request `govulncheck`.
- GET-only enforcement in the shared HTTP transport (`NewRequest` and `Client.Do`).
- Shared Elasticsearch GET path catalog; credential verification uses `PathAuthenticate`.
- Bundled Elasticsearch CVE corpus (NVD CPE, OSV Maven, and Elastic security announcements as of
  2026-08-27). `garga scan` and `garga vuln` load it by default. `--signatures DIR` replaces it;
  `garga scan --no-signatures` skips CVE matching.
- Live TTY progress bar on stderr for `garga scan`, `garga vuln`, and `garga fingerprint`.
  `--no-progress` disables it. The bar uses probe counters only and does not print hosts or URLs.
- CSV columns `cvss` and `description`. CSV/JSON/JSONL/HTML also print a human detection summary
  on stderr.
- `make signatures-validate` for the bundled YAML corpus, included in `make check` and pull-request CI.
- `make install` copies the rebuilt `garga` binary to `$(PREFIX)/bin` (default `/usr/local/bin`).

### Changed

- `garga health` uses dedicated process codes: invalid flags, config, targets, and `--fail-on`
  values return 2; collection, connection, authentication, product, and timeout failures return 5;
  `--fail-on` warning/high/critical return 10/11/12. Those codes no longer overlay 1/2/3/4 used by
  other commands.
- `run.sh` is now `install.sh`. It installs build dependencies, builds `bin/garga`, and copies
  the binary to `PREFIX/bin`. It no longer launches garga commands.
- Default `logging.level` is `warn`. Scanner start/finish JSON is `info`; per-probe records stay
  `debug`.
- Console reports group findings by target, list exploitable findings first, use color on a
  terminal, and print a count summary including how many findings are exploitable.
- `garga health` terminal reports use the same TTY color rules as scan console output. Findings
  are grouped by severity, then category, with aligned check/resource/evidence fields, a colored
  score headline, and prioritized action colors. `NO_COLOR` and non-TTY stdout stay uncolored.
- Console and HTML listings highlight remotely usable compromise-class findings (`EXPLOITABLE`).
  The mark is not confirmed exploitation. Machine formats add an `exploitable` tag when the
  same classifier matches.

The project remains pre-release. CLI, configuration, and finding schema `0.1` are not yet a
tagged compatibility promise.
