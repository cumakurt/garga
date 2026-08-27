# Changelog

All notable changes to garga are documented in this file.

## Unreleased

### Added

- Cross-platform release archives, SHA-256 checksums, SPDX SBOMs, and an optional GPG signature
  of `SHA256SUMS`.
- Responsible-use guidance and a documented binary/signature rollback procedure.
- `garga scan` for bounded, GET-only Elasticsearch assessments with streaming reports.
- `garga fingerprint` for GET `/` product identity without exposure checks.
- `garga vuln` for signature-only potential vulnerability matching.
- Committed golangci-lint v2 configuration, `make lint`, and pull-request `govulncheck`.
- GET-only enforcement in the shared HTTP transport (`NewRequest` and `Client.Do`).
- Shared Elasticsearch GET path catalog; credential verification uses `PathAuthenticate`.
- `make signatures-validate` for committed YAML fixtures, included in `make check` and pull-request CI.
- `make install` copies the rebuilt `garga` binary to `$(PREFIX)/bin` (default `/usr/local/bin`).

### Changed

- `run.sh` is now `install.sh`. It installs build dependencies, builds `bin/garga`, and copies
  the binary to `PREFIX/bin`. It no longer launches garga commands.

The project remains pre-release. CLI, configuration, and finding schema `0.1` are not yet a
tagged compatibility promise.
