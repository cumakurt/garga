# ADR 0009: Explicit credential verification

- Status: Accepted
- Date: 2026-08-26

## Context

Operators sometimes need to confirm a single authorized username/password or API key against
Elasticsearch. Putting that secret in YAML, `GARGA_*` variables, or a `--password` flag would
leak it through configuration dumps, process listings, and shell history. Sending mutations to
"see if the user can write" would violate the safe-by-default scan path. Credential spraying
belongs in a separate opt-in engine with no call path from normal commands.

## Decision

- Authentication material lives in `internal/credential`, not in `config.Config`.
- `garga auth-check` accepts Basic Auth via `--username` plus `--password-stdin`, or an API key
  via `--api-key-stdin`. No `--password` flag is provided.
- Verification is one GET to `/_security/_authenticate` through the shared transport.
- Results are `valid`, `invalid`, or `security_unavailable`. They contain no secret, username,
  or response body.
- Central redaction replaces known secret bytes and Authorization header values in any error
  text before it leaves the package.

## Consequences

Scan orchestration must not read this secret type unless a later work package adds an explicit,
documented authenticated scan mode. Credential audit is a separate engine in
`internal/credential/audit` with no call path from `auth-check` or a future `scan` command.
