# Changelog

All notable changes to garga are documented in this file.

## Unreleased

### Added

- `garga health` advanced read-only Elasticsearch assessment with centralized collection and
  normalization, 37 version-aware health checkers, weighted root-cause scoring, correlation,
  partial-failure coverage, scanner telemetry, terminal/JSON/HTML/Markdown reports, configurable
  profiles and thresholds, optional deep collection, and secret-free baseline/delta snapshots.
- Every completed health assessment writes a timestamped, owner-only standalone HTML artifact in
  the current directory. The responsive light-theme report embeds `garga.png` and provides an
  executive dashboard, detailed evidence, correlations, remediation, coverage, and telemetry.

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

- `run.sh` is now `install.sh`. It installs build dependencies, builds `bin/garga`, and copies
  the binary to `PREFIX/bin`. It no longer launches garga commands.
- Default `logging.level` is `warn`. Scanner start/finish JSON is `info`; per-probe records stay
  `debug`.
- Console reports group findings by target, list exploitable findings first, use color on a
  terminal, and print a count summary including how many findings are exploitable.
- Console and HTML listings highlight remotely usable compromise-class findings (`EXPLOITABLE`).
  The mark is not confirmed exploitation. Machine formats add an `exploitable` tag when the
  same classifier matches.

The project remains pre-release. CLI, configuration, and finding schema `0.1` are not yet a
tagged compatibility promise.
