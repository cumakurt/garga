# Scan command

`garga scan` is the default assessment path. It probes authorized targets with GET requests,
fingerprints Elasticsearch, discovers read-only capabilities, evaluates exposure checks, and
streams findings. It does not send credentials or change cluster state. Product identity without
checks is `garga fingerprint`; see [fingerprint.md](fingerprint.md). Signature-only matching is
`garga vuln`; see [signatures.md](signatures.md).

```sh
garga scan 192.0.2.10
garga scan https://es.example.internal:9200 --format csv
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

`--signatures` replaces the bundled corpus with YAML files from a directory. `garga scan`
loads the bundled Elasticsearch CVE corpus by default. `--no-signatures` skips CVE matching
and keeps TLS/exposure checks. Scan does not fetch or activate signed update bundles.

## Pipeline

1. Canonicalize and stream targets through the bounded scanner engine (`GET /`).
2. Fingerprint each successful probe without extra I/O.
3. When the identity is likely or confirmed, discover GET-only capabilities.
4. Evaluate the check registry and bundled (or `--signatures`) CVE matches into `model.Finding` values.
5. Stream findings to the selected reporter. Console and HTML emphasize exploitable findings.
   CSV, JSON, JSONL, HTML, SARIF, and VEX also print a human detection summary on stderr. The complete
   scan is not retained in machine writers. Independently of `--format`, a detailed timestamped
   PDF artifact (`garga-scan-*.pdf`) is written to the current directory when the scan has
   submitted probes or produced findings. `--html-report` also writes the HTML artifact.

Orchestration lives in `internal/app`. The scanner engine remains product-neutral. Credential
verification and credential audit are not on this path.

Capability follow-up GETs are sequential per emitted endpoint and independently paced at the
configured global and per-host rates. They can overlap remaining root probes, so the combined
instantaneous rate may briefly exceed the scanner-only budget.

## Output and exit codes

`--format` selects `console`, `json`, `jsonl`, `csv`, `html`, `sarif`, or `vex`. When omitted, `output.format`
from configuration applies. Machine formats use finding schema `1.0`. Logs stay on stderr.

On a terminal, `garga scan` draws a live progress bar on stderr while probes are in flight
(`completed/submitted`, percent, rate, and eta). The bar uses only counters: it never prints
hosts or URLs. It stays hidden for a fast single-target run. `--no-progress` disables it.
Piped stderr (CI, files) does not show the bar. Findings remain on stdout.

Every completed scan also writes `garga-scan-<timestamp>-<id>.pdf` in the working directory
(mode `0600`) and prints the absolute path on stderr. The artifact is titled `Test Report` and is
structured to PTES, NIST SP 800-115, OWASP, and CREST: document control, disclaimer, executive
summary, engagement overview, in/out of scope, rules of engagement, methodology, risk rating,
summary and technical findings (grouped by severity, with OWASP/CWE, evidence, and residual
risk), attack scenarios, remediation roadmap, positive observations, coverage limitations,
and appendices (assets, CVEs, glossary). Console scan output always shows evidence for every
finding. `--format html` on stdout remains the compact streaming table for automation; the CWD
PDF is the operator-facing assessment. Pass `--html-report` (or `output.html_report` /
`GARGA_OUTPUT_HTML_REPORT`) to also write `garga-scan-*.html` with the same content.

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
| `--html-report` | `output.html_report` |
| `--config` | explicit YAML path |

Timeouts, retries, response limits, fingerprint threshold, and log level remain file or
`GARGA_*` settings. See [configuration.md](configuration.md).
