# Signature updates

WP 8.2 installs a signed vulnerability signature database. Updates are explicit: they are not
part of a scan. The trust root is an Ed25519 public key embedded in the binary (D-004 / ADR 0014).
The matching private key is held by maintainers and is not stored in this repository.

## Bundle layout

`--source` is a local directory or an HTTP(S) directory URL containing:

| File | Role |
|---|---|
| `manifest.json` | Schema `0.1` document listing the archive checksum and per-file SHA-256 digests |
| `manifest.sig` | Hex-encoded Ed25519 signature over the exact `manifest.json` bytes |
| `signatures.zip` | ZIP of top-level `*.yaml` / `*.yml` files only |

The updater verifies the detached signature, checks the archive digest, extracts into staging
without following zip paths or symlinks, hashes every file, then runs the same `LoadDir`
validator used at scan time. Only then does it rename `staging` into `current/`. The previous
database is kept as `previous/` for one-generation rollback. `garga scan --signatures` and
`garga vuln --signatures` replace the bundled corpus with that `current/` directory.

## CLI

```sh
garga update --source URL_OR_DIR --dir DIR
garga update --rollback --dir DIR
```

`--dir` is required. HTTP fetches use the shared transport (timeouts, TLS, response limits) with
an 8 MiB archive cap. `--insecure` skips only TLS certificate verification. Verification,
archive, and validation failures exit `4` and leave `current/` unchanged.

## Manifest `0.1`

```json
{
  "schema_version": "0.1",
  "version": "2026.08.26.1",
  "archive_sha256": "64-lowercase-hex-characters",
  "files": [
    {"name": "example.yaml", "sha256": "64-lowercase-hex-characters", "size": 123}
  ]
}
```

File names must be basenames. Nested paths, `..`, absolute paths, extra ZIP entries, and
symlinks are rejected.
