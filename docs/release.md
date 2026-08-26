# Releasing garga

This document is the operator procedure for building, verifying, publishing, and rolling back
official garga artifacts. Release approval follows [release-ownership.md](release-ownership.md).

## What a release contains

`make release VERSION=vX.Y.Z` writes `dist/` with:

| Artifact | Purpose |
|---|---|
| `garga_vX.Y.Z_<os>_<arch>.tar.gz` | Linux and macOS archives |
| `garga_vX.Y.Z_windows_amd64.zip` | Windows archive |
| `garga_vX.Y.Z.spdx.json` | SPDX 2.3 module-graph SBOM |
| `SHA256SUMS` | SHA-256 digests of archives and the SBOM |
| `SHA256SUMS.asc` | Optional detached GPG signature |

Each archive includes the binary, `LICENSE`, `README.md`, `SECURITY.md`, `CHANGELOG.md`,
responsible-use and release documentation, the SBOM, and `release-metadata.txt` (version, commit,
build time, GOOS/GOARCH). Version strings are injected into the binary with `-ldflags`.

Supported targets: Linux amd64/arm64, macOS amd64/arm64, Windows amd64. Builds use
`CGO_ENABLED=0`, `-trimpath`, and `-buildvcs=false`. Set `SOURCE_DATE_EPOCH` for a reproducible
timestamp.

The SBOM lists Go modules from `go list -m -json all`. It is not a substitute for a license
compliance audit. Transitive licenses are recorded as `NOASSERTION` unless they are the main
AGPL-3.0-only module.

## Cut a release from a clean checkout

1. Confirm Section 11 gates: `make check`, `make test-race`, `make fuzz-smoke`, and
   `make vulncheck`.
2. Update [CHANGELOG.md](../CHANGELOG.md) and [SECURITY.md](../SECURITY.md) supported versions.
3. Tag `vX.Y.Z` and push the tag. The `Release` workflow builds `dist/` and publishes a GitHub
   Release.
4. Local equivalent:

```sh
git checkout vX.Y.Z
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) GARGA_RELEASE_COMMIT=$(git rev-parse HEAD) \
  make release VERSION=vX.Y.Z
(cd dist && sha256sum -c SHA256SUMS)
```

Optional signing:

```sh
GARGA_RELEASE_GPG_KEY=0xYOURKEY make release VERSION=vX.Y.Z
gpg --verify dist/SHA256SUMS.asc dist/SHA256SUMS
```

Unsigned local builds are allowed. Official GitHub artifacts should be signed when the release
maintainer has the signing key available.

## Verify a downloaded archive

```sh
cd dist
sha256sum -c SHA256SUMS
tar -tzf garga_vX.Y.Z_linux_amd64.tar.gz
./garga_vX.Y.Z_linux_amd64/garga version
```

Confirm the printed version, commit, and build time match `release-metadata.txt` and the Git tag.

## Rollback

**Binaries:** install the previous GitHub Release tag. Keep the last known-good archive and its
`SHA256SUMS` file. garga has no in-place binary updater.

**Signature databases:** `garga update --rollback --dir DIR` restores the previous verified
database. See [signature-updates.md](signature-updates.md).

Emergency withdrawal of a bad tag is a GitHub Release unpublish plus an advisory from the release
maintainer.
