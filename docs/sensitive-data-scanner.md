# Sensitive data scanner

`garga secrets` is an isolated, opt-in Elasticsearch sensitive-data discovery command.
It connects only with credentials the operator supplies and only to clusters the
operator is authorized to assess.

The command does **not** export indices. It reports whether mappings and a bounded
sample of documents appear to contain credentials, tokens, keys, or similar secrets.

Use it only against Elasticsearch systems you own or are explicitly authorized to
assess. Unauthorized scanning may be illegal.

## Architecture

```text
internal/cli  -->  internal/secrets  -->  internal/credential
                                     -->  internal/ratelimit
                                     -->  internal/target
                                     -->  internal/pdfdoc
```

The engine is not on the `scan`, `fingerprint`, `vuln`, or `health` path.

1. Connect with the existing Basic Auth, API key, or Bearer credential model.
2. Read cluster identity (`GET /`), authentication (`GET /_security/_authenticate`),
   index catalog, aliases, and data streams.
3. **Stage 1:** inspect index mappings and score field names.
4. **Stage 2:** sample documents with `POST /{index}/_search`, `_source` filtering,
   `sort: ["_doc"]`, `search_after`, and small batches. Elasticsearch 8+/9 disable
   `_id` fielddata by default, so sampling does not sort on `_id`.
5. Classify values locally. Deduplicate with a per-run HMAC-SHA256 over category and
   secret material. Discard document bodies after classification.

Point-in-time (PIT) search is not used because closing a PIT requires `DELETE`.

The shared HTTP transport remains GET-only. Secrets uses a dedicated client that
allowlists:

- `GET /`, `GET /_cluster/health`, `GET /_security/_authenticate`, `GET /_cat/indices`,
  `GET /_alias`, `GET /_data_stream`, `GET /{index}/_mapping`
- `POST /{index}/_search` with a JSON body

`PUT`, `DELETE`, `PATCH`, bulk write, mapping updates, and cluster-setting changes
are rejected.

## Supported detectors

| Detector | Examples |
|---|---|
| Field-name scoring | `password`, `client_secret`, `api_key`, `private_key` (camelCase / snake_case / kebab-case / dotted paths) |
| Cloud credentials | AWS access key ID, AWS secret access key (field-gated), Google API key, Azure account key |
| Developer tokens | GitHub PAT, GitHub fine-grained PAT, GitLab PAT, Slack token/webhook |
| Tokens | JWT, Bearer/Basic `Authorization` headers (`credential.http.basic` / `credential.http.bearer`) |
| Keys | PEM/OpenSSH/PGP private keys (reported as "Private key detected") |
| Connection strings | postgres, mysql, mongodb, redis, mssql, JDBC, `user:pass@` URLs (username/password/host components, password masked) |
| Config text | `.env` assignments, LDAP bind, SMTP password, Docker `auths` |
| Password hashes | bcrypt, Argon2, PBKDF2, scrypt, SHA crypt, MD5 crypt, NTLM-like (hash context only) |
| Credential pairs | Same-object username+password, client_id+secret, access_key+secret_key, database/API/token pairs, config-block assignments |
| Generic entropy | Shannon entropy + length + charset, gated by field semantics |

Public certificates and public keys are `info`, not secrets.

## Severity and confidence

Severity: `info`, `low`, `medium`, `high`, `critical`.

Confidence: `low`, `medium`, `high`, `confirmed-pattern`.

Default `--min-confidence` is `medium`. A `password` field with a credential-like
value is typically `critical` / `high`. A `request_id` holding random hex is `low`
and is omitted by default.

## Masking

Console, JSON, JSONL, table, and SARIF never include the full secret:

- `password` → `p***********d`
- AWS access key → `AKIA****************`
- Bearer/JWT → `eyJhbG...4F8A`
- `postgres://admin:SuperSecret@db01/db` → `postgres://a***:S**********@db01/db`
- private keys → `Private key detected`
- password hashes → `Password hash detected (bcrypt)`

The timestamped PDF written to the current directory (`garga-secrets-*.pdf`, mode
`0600`) includes recovered secret values so an authorized operator can remediate.
Private keys and password hashes remain type-only even in the PDF.

## Sampling and performance

Defaults are production-safe:

| Setting | Default |
|---|---|
| `--concurrency` | 2 targets |
| `--rate-limit` | 5 requests/second |
| `--sample-size` | 100 documents per index |
| `--max-documents` | 10 000 documents per run |
| `--timeout` | 10 minutes |
| `--max-depth` | 8 |
| `--max-array-items` | 64 |
| `--max-field-bytes` | 1 MiB |

`--deep-scan` switches to a central deep profile without making unbounded reads:

| Setting | Deep default | Hard cap |
|---|---|---|
| `--deep-sample-size` | 500 documents per index | 1 000 |
| `--deep-max-documents` | 50 000 documents per run | 100 000 |
| `--deep-max-depth` | 16 | 32 |
| `--deep-max-array-items` | 256 | 1 000 |
| `--deep-max-field-bytes` | 4 MiB | 8 MiB |

Deep scan also inspects mapping `text`/`keyword` fields that do not look sensitive by name,
walks nested objects/arrays more thoroughly, and uses a broader correlation alias list
(`uid`, `login_name`, `secretValue`, …) with the same confidence threshold. Pagination stays
`search_after` + `_doc` + `_source` filtering + small batches. HTTP 429 responses apply
exponential backoff and slow subsequent requests. Deep flags without `--deep-scan` are rejected.

Credential correlation is document-local. Sibling fields in the same object or the same array
element can form a pair; `accounts[0].username` is never joined with `accounts[1].password`,
and fields in different documents are never joined. Correlation findings include
`object_path`, `related_fields`, `credential_type`, and `masked_values`. They do not store
plaintext secrets. JSON `scan_mode` is `normal` or `deep`. Summary counts separate field
findings from correlated findings.

Document sampling uses `_doc` order so `search_after` works without a PIT and without
enabling `indices.id_field_data.enabled`. Sampling failures are logged and the rest of
the run continues.

HTTP 429, timeouts, connection resets, TLS errors, and partial shard failures fail
that request after bounded exponential backoff; other indices and targets continue.
System indices (names starting with `.`) are skipped unless
`--include-system-indices` is set. If a `.security*` index is readable, garga emits
a critical finding and does not dump authentication material from it.

## CLI usage

```text
export ES_PASSWORD='...'
garga secrets --target https://es.example.internal:9200 \
  --user elastic --password-env ES_PASSWORD \
  --format table

garga secrets --targets clusters.txt --format json --output findings.json

garga secrets --target https://es.example.internal:9200 \
  --api-key-env ES_API_KEY \
  --indices 'app-logs-*' --exclude-indices 'metrics-*' \
  --min-confidence high --verbose

garga secrets --target https://es.example.internal:9200 \
  --user elastic --password-env ES_PASSWORD \
  --deep-scan --format json
```

`--format` is `json`, `jsonl`, `table`, or `sarif`. There is no `--password` flag.
mTLS is available with `--ca-cert`, `--client-cert`, and `--client-key`.

### Synthetic test data

```text
garga secrets generate --target https://localhost:9200 \
  --user elastic --password-env ES_PASSWORD --insecure
```

This writes clearly fake documents into `garga-sensitive-test`. The corpus covers
every built-in detector family: passwords and credential pairs, AWS/GCP/Azure,
GitHub/GitLab/Slack, JWT and Basic/Bearer headers, PEM/OpenSSH/PGP private keys,
postgres/mysql/mongodb/redis/mssql/JDBC/Elasticsearch URLs, `.env` / LDAP / SMTP /
Docker auth, Kubernetes service-account material, password hashes, camelCase and
kebab-case field names, nested objects, and high-entropy secrets. False-positive
fixtures (UUID, checksum, public cert/key, `monkey`) are included so the scanner
can be checked against noise. Do not run the generator against production.

Example PDF output from the Docker demo is in
[`sample/garga-secrets-sample.pdf`](../sample/garga-secrets-sample.pdf). Terminal
screenshots are in the README [Screenshots](../README.md#screenshots) section.

## Limitations

- Sampling can miss secrets that appear only in unsampled documents.
- Generic entropy detection cannot prove that a high-entropy string is a secret.
- Correlation does not match usernames in one document with passwords in another.
- Point-in-time (PIT) search is not used; closing a PIT would require `DELETE`.
- The scanner never validates a discovered credential against another system.
- Absence of findings is not a certification that an index is clean.
- Private keys are never printed in full.

## Safety

All product queries are read-only. Discovered secrets are not written to debug
logs, error messages, or machine-readable reports. The PDF is an engagement
artifact: store it as confidential and restrict access to authorized operators.
