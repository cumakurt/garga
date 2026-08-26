# WP 10.2 — Release engineering

## Status

Complete.

## Scope

- Cross-platform release builds: Linux amd64/arm64, macOS amd64/arm64, Windows amd64.
- Archives with license, documentation, and injected version metadata.
- SHA-256 checksums, SPDX SBOM, optional GPG signing when `GARGA_RELEASE_GPG_KEY` is set.
- Reproducible `make release` plus tag-triggered GitHub release workflow.
- Responsible-use docs, changelog, rollback procedure, CI fuzz smoke.

## Acceptance

- [x] Linux amd64/arm64, macOS amd64/arm64, and Windows amd64 builds pass.
- [x] Release archives contain license, documentation, and version metadata.
- [x] Section 11 release gates that this package owns are documented and runnable from a clean checkout.
- [x] `make check` and `make test-race` pass.
- [x] No `scan` CLI. No new runtime module unless justified.

## Review

`make release VERSION=v0.0.0-test` produced five archives plus SPDX JSON and `SHA256SUMS`.
Checksums verified from `dist/`. The Linux amd64 binary printed the injected version and commit.
`make fuzz-smoke FUZZ_TIME=3s` passed. `go vet` remains the committed static analyzer; no
golangci-lint config was added. `make vulncheck` is documented for tagged releases and was not
run in this increment (it downloads the Go vulnerability database).
