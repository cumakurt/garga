# ADR 0018: Reproducible release artifacts

- Status: Accepted
- Date: 2026-08-26

## Context

Operators need official binaries they can checksum, inspect, and roll back. Ad-hoc `go build`
outputs differ by machine, omit licenses, and have no SBOM. Extra packaging frameworks would add
supply-chain surface for a task the Go toolchain already performs.

## Decision

- `scripts/release` is a standard-library Go tool in the same module. It is not part of the
  `garga` CLI and must not import Cobra or `internal/cli`.
- Official targets are Linux amd64/arm64, macOS amd64/arm64, and Windows amd64, built with
  `CGO_ENABLED=0`, `-trimpath`, and linker-injected version metadata.
- Each archive ships license, user documentation, an SPDX 2.3 module-graph SBOM, and
  `release-metadata.txt`. `SHA256SUMS` covers archives and the top-level SBOM.
- GPG signing of `SHA256SUMS` is optional and runs only when `GARGA_RELEASE_GPG_KEY` is set.
  Missing keys skip signing rather than fabricating a signature.
- Git tags `v*.*.*` invoke a GitHub Actions workflow that rebuilds from the tag and publishes
  `dist/` with `gh release`. Pull-request CI cross-compiles but does not attach archives.

## Consequences

A maintainer can reproduce artifacts from a clean checkout. SBOM completeness is limited to the
Go module graph. License conclusions for transitive modules remain `NOASSERTION` until a dedicated
license scan is justified.
