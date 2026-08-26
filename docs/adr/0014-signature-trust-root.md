# ADR 0014: Ed25519 signature trust root

- Status: Accepted
- Date: 2026-08-26

## Context

Vulnerability signatures must be updatable without shipping a new binary, but a download that is
only checksummed can be replaced by an attacker who also replaces the checksum. GPG and Sigstore
would add dependencies and operational complexity before the first public tag. A `--public-key`
flag would let an attacker supply the trust root.

## Decision

- The trust root is a single Ed25519 public key embedded in the binary (`crypto/ed25519`).
- A bundle is `manifest.json`, a hex-encoded detached signature over those exact bytes, and
  `signatures.zip`. The archive digest and per-file SHA-256 values are inside the signed
  manifest.
- `internal/update` fetches, verifies, extracts without path traversal or symlinks, validates
  every staged YAML file with `vulnerability.LoadDir`, then activates with rename plus one
  previous generation for rollback.
- `garga update` is the only entry point. Scanner, fingerprint, and check packages must not
  import this package.
- The private key is not stored in the repository. Rotation requires a binary that embeds a new
  public key.

## Consequences

Pre-release updates only verify against the embedded key. There is no default download URL.
Interrupted or invalid updates leave `current/` unchanged. Exit code 4 reports verification,
archive, or validation failure.
