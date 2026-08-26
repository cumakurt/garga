# Credential verification

`garga auth-check` verifies one explicit Elasticsearch credential. It is not the normal scan
path and it is not credential spraying. The command sends a single GET to
`/_security/_authenticate` and reports whether the server accepted the credential.

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

Trying more than one credential requires the isolated `garga auth-audit` command documented in
[credential-audit.md](credential-audit.md). That path is never invoked from a normal scan.
