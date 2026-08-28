# Configuration reference

garga resolves configuration in this order, from lowest to highest precedence:

1. built-in defaults;
2. an explicitly selected YAML file;
3. `GARGA_*` environment variables;
4. command-line overrides.

The configuration is fully resolved and validated before a command may start network activity.
`garga scan` and `garga vuln` bind `--concurrency`, `--rate`, `--per-host-rate`, and `--format`
to the typed override layer. `garga fingerprint` also binds `--threshold` to
`fingerprint.threshold`. `garga health` binds `--profile`, `--concurrency`,
`--requests-per-second`, `--top-n`, `--max-response-bytes`, and `--request-timeout`.
`garga scan`, `garga health`, and `garga assess` bind `--html-report` to `output.html_report`.
`garga report` uses `output.format` when `--format` is omitted.

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
| `health.profile` | `GARGA_HEALTH_PROFILE` | `standard` | `development`, `small`, `standard`, `large`, `logging`, `search`, `security`, `production` |
| `health.concurrency` | `GARGA_HEALTH_CONCURRENCY` | `4` | `1` through `32` |
| `health.requests_per_second` | `GARGA_HEALTH_RATE` | `5` | greater than `0`, at most `100` |
| `health.top_n` | `GARGA_HEALTH_TOP_N` | `5` | `1` through `100` |
| `health.max_response_bytes` | `GARGA_HEALTH_MAX_RESPONSE_BYTES` | `33554432` | `1024` through `134217728` bytes |
| `output.format` | `GARGA_OUTPUT_FORMAT` | `console` | `console`, `json`, `jsonl`, `csv`, `html`, `sarif`, `vex` |
| `output.html_report` | `GARGA_OUTPUT_HTML_REPORT` | `false` | boolean; also write timestamped HTML CWD reports for `scan`, `health`, and `assess` |
| `logging.level` | `GARGA_LOG_LEVEL` | `warn` | `error`, `warn`, `info`, `debug` |

Health thresholds are nested below `health.thresholds`. Percentage triplets must be ordered as
`warning < high < critical`. Shard sizes accept decimal (`GB`, `MB`) and binary (`GiB`, `MiB`)
units. Duration values use Go duration syntax. See [health.md](health.md) for the complete health
threshold set and profile behavior.

The connect timeout must not exceed the request timeout. Duration values use Go duration syntax,
for example `500ms`, `2s`, or `1m30s`.

## Secret boundary

This general configuration model deliberately contains no credentials, authorization headers,
API keys, or passwords. Authentication input uses `garga auth-check` and `garga auth-audit` with
stdin secrets as documented in [credentials.md](credentials.md) and
[credential-audit.md](credential-audit.md). Scanner rate settings do not apply to credential
audit. `garga scan`, `garga fingerprint`, and `garga vuln` do not accept credentials. `garga health`
and `garga assess` keep authentication outside this configuration model: stdin is preferred, while the dedicated
`ESHEALTH_USERNAME`, `ESHEALTH_PASSWORD`, `ESHEALTH_API_KEY`, and `ESHEALTH_BEARER_TOKEN`
variables exist for automation. Those variables are never included in configuration formatting,
logs, snapshots, or reports.
Configuration parse and validation errors
identify the field or environment variable but never echo its supplied value.

Logs are JSON on stderr. `logging.level` selects `error`, `warn`, `info`, or `debug`. The default
`warn` level does not emit scanner start/finish or per-request probe lines. Set `info` for
bounded scan summaries or `debug` for per-probe records. See [observability.md](observability.md).
