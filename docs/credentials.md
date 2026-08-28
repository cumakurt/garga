# Credential verification

`garga auth-check` verifies one explicit Elasticsearch credential. It is not the normal scan
path and it is not credential spraying. The command sends a single GET to
`/_security/_authenticate` (`capability.PathAuthenticate`) and reports whether the server accepted
the credential. That path is the Elasticsearch Authenticate API; `GET /_security/user/_authenticate`
is Get User and is not used.

## Input

```text
garga auth-check TARGET --username USER --password-stdin
garga auth-check TARGET --api-key-stdin
```

- `--password-stdin` reads the Basic Auth password from standard input.
- `--api-key-stdin` reads one API key from standard input.
- Only the first line is used. A trailing newline is stripped. Input is limited to 4096 bytes.
- There is no `--password` flag. Command-line secrets can appear in process listings, shell
  history, and audit logs.

API key values that contain a colon are treated as `id:key` and Base64-encoded. Other values are
sent as the `ApiKey` header material the operator supplied.

Scheme-less targets use HTTP. A missing port defaults to 9200. Use an `https://` URL for TLS.
`--insecure` disables certificate verification only.

Credentials are never read from `garga` YAML configuration or `GARGA_*` environment variables.

## Output

The command writes one secret-free line and exits `0` when verification completes:

```text
auth-check: valid mechanism=basic status=200
auth-check: invalid mechanism=api_key status=401
auth-check: security_unavailable mechanism=basic status=404
```

`valid` means the authenticate API accepted the credential. `invalid` means authentication or
authorization failed. `security_unavailable` means the security API was not present. Transport
failures exit `1`. Invalid flags or targets exit `2`.

## Redaction

Secret material is not copied into errors, logs, or the result line. The credential object
formats as `credential:basic` or `credential:api_key`. Response bodies are discarded after the
status code is classified.

Trying more than one credential requires an isolated command. `garga auth-audit` verifies a short
explicit list and is documented in [credential-audit.md](credential-audit.md). Technique-specific
stuffing, spraying, brute-force, and dictionary assessments use `garga auth-detect`, documented in
[credential-detect.md](credential-detect.md). Those paths are never invoked from a normal scan.

## Health assessment credentials

`garga health` may send one optional credential on GET collectors. Prefer stdin so secrets do not
enter shell history. Supported mechanisms are Basic Auth (`--username` plus `--password-stdin`),
`--api-key-stdin`, and `--bearer-token-stdin`. Only one mechanism may be selected.

The automation variables `ESHEALTH_USERNAME`, `ESHEALTH_PASSWORD`, `ESHEALTH_API_KEY`, and
`ESHEALTH_BEARER_TOKEN` are accepted. They are never read from garga YAML or `GARGA_*` settings,
and they are never written to logs, snapshots, or reports. Credentials over HTTP are refused
unless `--allow-plaintext-auth` is set; that override is reported as a critical finding.

Details: [health.md](health.md).
