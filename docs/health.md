# Elasticsearch health assessment

`garga health` turns read-only Elasticsearch API responses into an operational assessment of one
cluster. It is separate from the multi-target security-oriented `scan` command: health accepts
exactly one target, may use one explicit credential, and reports cluster, node, index, capacity,
performance, configuration, backup, and security risks.

```sh
garga health https://es-prod.example.com --profile production
garga health https://es-prod.example.com --profile production --deep --format html > health.html
garga health https://es-prod.example.com --format json --fail-on high
```

## Safety boundary

Every Elasticsearch request is `GET` with no request body. Health never creates or deletes an
index, changes settings or policies, relocates shards, verifies a snapshot repository, or changes
cluster state. Allocation explain is called without a body only after the snapshot reports an
unassigned shard. Snapshot repositories and histories are read, but repositories are never
verified or modified.

All requests have an overall deadline, a per-request timeout, a response-size limit, bounded
concurrency, client-side rate limiting, and a finite retry budget. Only transient network errors,
`408`, `429`, and `5xx` responses are retried. Authentication failures and missing permissions are
not retried.

Credentials are optional. Prefer stdin so secrets do not enter shell history:

```sh
printf '%s\n' "$ES_PASSWORD" | \
  garga health https://es.example.com --username elastic --password-stdin

printf '%s\n' "$ES_API_KEY" | \
  garga health https://es.example.com --api-key-stdin
```

Basic, API key, and Bearer authentication are supported. A credential is refused over HTTP unless
`--allow-plaintext-auth` is explicitly set. That override produces a critical security finding.
The central redaction layer removes authorization material, passwords, API keys, tokens, secrets,
credentials, and cookies from evidence and every report format. `--insecure` disables certificate
verification only; it does not weaken any other safety control.

The automation environment variables `ESHEALTH_USERNAME`, `ESHEALTH_PASSWORD`,
`ESHEALTH_API_KEY`, and `ESHEALTH_BEARER_TOKEN` are supported. Only one credential mechanism may
be selected.

## Architecture

The command uses one normalized snapshot instead of allowing checks to query Elasticsearch:

```text
Elasticsearch GET APIs
        |
        v
bounded collector
        |
        v
version-tolerant normalizer
        |
        v
ClusterSnapshot
        |
        +--> independent version-aware checkers
        |
        +--> weighted scoring and root-cause correlation
        |
        v
terminal / JSON / HTML / Markdown report
```

This keeps Elasticsearch I/O centralized, prevents duplicate API calls, makes partial permissions
visible, and lets checker tests run without a live cluster. Elasticsearch 7.17, 8.x, and 9.x root
responses have dedicated fixtures. OpenSearch and versions before 7.17 are rejected.

## Collection plans

Normal mode uses low- and medium-cost APIs:

- `/`, `/_cluster/health`, `/_cluster/stats`, `/_cluster/settings`, and
  `/_cluster/pending_tasks`;
- `/_nodes` and bounded node stats;
- CAT indices and shards, plus index settings;
- security authentication when available;
- allocation explain only when an unassigned shard exists.

`--deep` additionally enables the potentially larger node-settings, ILM explain, data stream,
task, snapshot repository, and recent snapshot-history collectors. At most 20 repositories are
queried, and snapshot history is capped at 20 entries per repository. Dynamic repository names
are strictly validated before being placed in a path.

An optional endpoint failure does not abort the assessment. `401`, `403`, `404`, unsupported
versions, malformed responses, and size limits are recorded with distinct collector status and
cause. Only the required product/version request is fatal.

## Analysis coverage

The registry currently contains 37 independent checks covering:

- cluster status, pending tasks, and single-node availability;
- node role redundancy and disk capacity projection from a compatible baseline;
- JVM heap and baseline-normalized garbage collection;
- CPU and normalized load, physical memory/swap, and file descriptors;
- configured disk watermarks and disk imbalance;
- thread-pool queues/rejections, circuit breakers, and indexing pressure;
- unassigned allocation evidence, shard density, small/large shards, and statistical imbalance;
- index health, replicas, deleted documents, empty/old indices, and index blocks;
- search/indexing counters, merge/refresh pressure, cache/fielddata evictions, and segment density;
- ILM, data streams, long tasks, snapshots, allocation settings, HTTP authentication, and TLS
  certificate lifetime.

Snapshot-only cumulative values are labeled as historical and are not treated as current rates.
Delta findings use two snapshots and report the elapsed interval. Heuristic findings include a
confidence level and are evaluated with profile, node role, system-index, topology, shard size,
heap, and configured-watermark context where applicable.

## Profiles and thresholds

Profiles select environment context. Each profile changes at least one checker:

| Profile | Distinct behavior |
|---|---|
| `development` | Softens single-node, replica, and role findings to informational |
| `small` | Same availability/replica leniency as development; anonymous access stays high |
| `standard` | Default operational thresholds |
| `large` | Stricter shard/disk imbalance and two-master quorum (high instead of medium) |
| `logging` | Higher shard-count heuristic for ingest-heavy nodes |
| `search` | Tighter segment density and merge/refresh pressure heuristics |
| `security`, `production` | Anonymous access is critical when authenticate evidence proves it |

Anonymous access is recorded only from authenticate evidence: an `_anonymous` identity, an
`anonymous` authentication type, or HTTP 200 without a supplied credential. A `401`/`403`
authenticate response is not treated as anonymous access.

Thresholds belong under `health.thresholds`, not in checker code. The complete default structure
is represented below; omitted fields retain typed defaults:

```yaml
health:
  profile: production
  concurrency: 4
  requests_per_second: 5
  top_n: 5
  max_response_bytes: 33554432
  thresholds:
    jvm: {warning: 75, high: 85, critical: 95}
    memory: {warning: 90, high: 95, critical: 98}
    disk: {warning: 75, high: 85, critical: 95}
    cpu: {warning: 75, high: 90, critical: 98}
    file_descriptors: {warning: 70, high: 85, critical: 95}
    deleted_documents: {warning: 0.20, high: 0.40}
    shard_size:
      small: 1GB
      large_warning: 50GB
      large_high: 100GB
    shard_imbalance: {warning: 0.25, high: 0.50}
    disk_imbalance: {warning: 15, high: 30}
    certificate: {warning: 30, high: 14, critical: 7}
    pending_task_warning: 30s
    pending_task_high: 2m
    long_task_warning: 30m
    backup_warning: 72h
    backup_high: 168h
    thread_pool_queue_high: 100
```

Elasticsearch persistent and transient disk watermarks override static disk thresholds when they
can be normalized safely. Defaults, persistent values, and transient values remain distinct in the
snapshot.

## Score and findings

Findings use stable `ES-*` IDs and severities `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`, and
`OK`. Each finding can include resource, evidence, threshold, impact, recommendation, references,
confidence, and root-cause identity.

The score starts at 100 and applies weights of 25/10/5/2/0 for critical/high/medium/low/info.
Only the highest-severity finding for the same root cause contributes to the deduction, preventing
one failure from artificially multiplying its score impact. Health bands are Critical (0-24), High
Risk (25-49), Degraded (50-74), Minor Issues (75-89), Healthy (90-99), and Perfect (100).

The correlation layer currently recognizes disk-watermark allocation failures, combined JVM and
memory pressure, and shard/disk imbalance. Correlations state a probable root cause and confidence;
they do not claim certainty from a single snapshot.

## Baselines and deltas

Save a secret-free cumulative-counter baseline and compare it with a later assessment:

```sh
garga health https://es.example.com --snapshot-out baseline.json
garga health https://es.example.com --baseline baseline.json
```

Use `--force` only to replace an existing `--snapshot-out` file. Baselines are JSON schema `1.0`,
written with owner-only permissions, limited to 16 MiB when read, and accepted only when their
cluster UUID matches and their timestamp precedes the current scan. They contain counters, not
credentials or raw Elasticsearch payloads. Counter resets caused by a node restart are recognized
instead of being reported as negative activity.

## Reports and exit codes

`--format` accepts `terminal`, `json`, `html`, and `markdown`. `terminal` (also accepted as
`console`) is a colorized operator report on a TTY: findings are grouped by severity, then
category, with aligned fields and a scored headline. Color is omitted when stdout is not a
terminal, `TERM=dumb`, or `NO_COLOR` is set. JSON uses a stable health-report schema version
separate from the scan finding schema. Markdown includes findings, probable root causes, the
prioritized action plan, collector coverage, telemetry, and methodology. Regardless of that
stdout format, every completed assessment atomically writes a timestamped
`garga-health-*.pdf` artifact to the current directory with owner-only permissions and prints
its absolute path on stderr. This preserves clean machine output while making a durable PDF
report available in every mode. Pass `--html-report` (or `output.html_report` /
`GARGA_OUTPUT_HTML_REPORT`) to also write `garga-health-*.html`.

The optional HTML report is a responsive, print-friendly light-theme document. It embeds the
repository `garga.png` logo and all styling, contains no scripts or external network resources,
and escapes report data. Its sections include an executive dashboard, severity summary, top
risks, independent node/index resource rankings, evidence-rich findings, probable root causes,
prioritized remediation, collector-by-collector coverage, scanner telemetry, and methodology.
The PDF artifact covers the same sections and is complete enough to be reviewed independently
of terminal output.

By default, findings are reported without failing the process. `--fail-on warning`,
`--fail-on high`, or `--fail-on critical` enables automation thresholds. Health uses dedicated
codes so those results are not confused with other commands:

| Code | Meaning |
|---:|---|
| 0 | Assessment completed below the requested failure threshold |
| 1 | Report or baseline write failure |
| 2 | Invalid flags, configuration, target, credentials, or `--fail-on` value |
| 5 | Connection, authentication, product, timeout, or health collection failure |
| 10 | Highest finding is medium/warning at or above the requested threshold |
| 11 | Highest finding is high at or above the requested threshold |
| 12 | Highest finding is critical at or above the requested threshold |
| 130 | Interrupted |

The report is written before a severity exit code is returned. Output errors remain general
internal errors (exit 1) rather than health-state results. Code 4 is reserved for signature
update failures and is not used by `garga health`.

## Deliberate limits

Health does not predict an exact date when storage will fill from one sample. A future forecast
requires at least two compatible time-separated capacity snapshots; current reports expose the
measurements and delta foundation without inventing a growth rate. Cache hit ratios, historical
rejection counts, cumulative GC time, large shards, and CPU snapshots are explicitly described as
workload-dependent rather than automatic incident proof.
