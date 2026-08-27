# Scan command

`garga scan` is the default assessment path. It probes authorized targets with GET requests,
fingerprints Elasticsearch, discovers read-only capabilities, evaluates exposure checks, and
streams findings. It does not send credentials or change cluster state. Product identity without
checks is `garga fingerprint`; see [fingerprint.md](fingerprint.md). Signature-only matching is
`garga vuln`; see [signatures.md](signatures.md).

```sh
garga scan 192.0.2.10
garga scan https://es.example.internal:9200 --format jsonl
garga scan --file targets.txt --signatures /var/lib/garga/current
garga scan --file - < targets.txt
```

## Inputs

Targets may be command-line arguments, a `--file` of line-oriented hosts, CIDRs, and URLs, or
both (arguments first, then file lines). `--file -` reads stdin. Grammar, CIDR expansion, and
exact deduplication are documented in [target-input.md](target-input.md). Duplicate canonical
targets are suppressed. The unique-target ceiling defaults to 1,000,000 and may be raised with
`--max-targets`. Exhausting that ceiling exits `2`.

`--insecure` skips TLS certificate verification only. It does not disable rate limits, timeouts,
retries, redaction, or the GET-only method contract.

`--signatures` loads YAML files from a directory through the same validator used by
`garga update`. Omit it to run TLS and exposure checks without CVE matching. Scan does not
fetch or activate signature bundles.

## Pipeline

1. Canonicalize and stream targets through the bounded scanner engine (`GET /`).
2. Fingerprint each successful probe without extra I/O.
3. When the identity is likely or confirmed, discover GET-only capabilities.
4. Evaluate the check registry (and optional signatures) into `model.Finding` values.
5. Stream findings to the selected reporter. The complete scan is not retained.

Orchestration lives in `internal/app`. The scanner engine remains product-neutral. Credential
verification and credential audit are not on this path.

Capability follow-up GETs are sequential per emitted endpoint and independently paced at the
configured global and per-host rates. They can overlap remaining root probes, so the combined
instantaneous rate may briefly exceed the scanner-only budget.

## Output and exit codes

`--format` selects `console`, `json`, `jsonl`, `csv`, or `html`. When omitted, `output.format`
from configuration applies. Machine formats use finding schema `0.1`. Logs stay on stderr.

| Code | Meaning |
|---:|---|
| 0 | Scan finished. Findings do not fail the run. |
| 1 | Unexpected internal or output failure |
| 2 | Invalid CLI, configuration, target input, or signature directory |
| 3 | Scan finished, but at least one probe failed operationally |
| 130 | Interrupted |

## Configuration flags

These flags bind to the typed override layer and outrank environment variables and files:

| Flag | Configuration |
|---|---|
| `--concurrency` | `scanner.concurrency` |
| `--rate` | `scanner.requests_per_second` |
| `--per-host-rate` | `scanner.per_host_requests_per_second` |
| `--format` | `output.format` |
| `--config` | explicit YAML path |

Timeouts, retries, response limits, fingerprint threshold, and log level remain file or
`GARGA_*` settings. See [configuration.md](configuration.md).
