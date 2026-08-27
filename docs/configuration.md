# Configuration reference

garga resolves configuration in this order, from lowest to highest precedence:

1. built-in defaults;
2. an explicitly selected YAML file;
3. `GARGA_*` environment variables;
4. command-line overrides.

The configuration is fully resolved and validated before a command may start network activity.
`garga scan` and `garga vuln` bind `--concurrency`, `--rate`, `--per-host-rate`, and `--format`
to the typed override layer. `garga fingerprint` also binds `--threshold` to
`fingerprint.threshold`. `garga report` uses `output.format` when `--format` is omitted.

## Selecting a file

Set `GARGA_CONFIG` to a YAML path. A command that supplies an explicit configuration path takes
precedence over this environment variable. garga does not search the working directory or home
directory for an implicit file.

Use [garga.example.yaml](../garga.example.yaml) as a starting point. Files are limited to 1 MiB,
must contain exactly one YAML document, and reject unknown fields. Empty files are valid and use
all built-in defaults.

## Settings

| YAML setting | Environment variable | Default | Valid values |
|---|---|---:|---|
| `scanner.concurrency` | `GARGA_CONCURRENCY` | `20` | `1` through `1000` |
| `scanner.requests_per_second` | `GARGA_RATE` | `50` | greater than `0`, at most `10000` |
| `scanner.per_host_requests_per_second` | `GARGA_PER_HOST_RATE` | `5` | greater than `0`, at most `1000` and no greater than the global rate |
| `scanner.connect_timeout` | `GARGA_CONNECT_TIMEOUT` | `2s` | greater than `0`, at most `5m` |
| `scanner.request_timeout` | `GARGA_REQUEST_TIMEOUT` | `5s` | greater than `0`, at most `5m` |
| `scanner.retries` | `GARGA_RETRIES` | `1` | `0` through `10` |
| `scanner.max_response_bytes` | `GARGA_MAX_RESPONSE_BYTES` | `524288` | `1024` through `10485760` bytes |
| `fingerprint.threshold` | `GARGA_FINGERPRINT_THRESHOLD` | `80` | `1` through `100` |
| `output.format` | `GARGA_OUTPUT_FORMAT` | `console` | `console`, `json`, `jsonl`, `csv`, `html` |
| `logging.level` | `GARGA_LOG_LEVEL` | `info` | `error`, `warn`, `info`, `debug` |

The connect timeout must not exceed the request timeout. Duration values use Go duration syntax,
for example `500ms`, `2s`, or `1m30s`.

## Secret boundary

This general configuration model deliberately contains no credentials, authorization headers,
API keys, or passwords. Authentication input uses `garga auth-check` and `garga auth-audit` with
stdin secrets as documented in [credentials.md](credentials.md) and
[credential-audit.md](credential-audit.md). Scanner rate settings do not apply to credential
audit. `garga scan`, `garga fingerprint`, and `garga vuln` do not accept credentials.
Configuration parse and validation errors
identify the field or environment variable but never echo its supplied value.

Logs are JSON on stderr. `logging.level` selects `error`, `warn`, `info`, or `debug`. The default
`info` level does not emit per-request probe lines. See [observability.md](observability.md).
