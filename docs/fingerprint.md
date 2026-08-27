# Elasticsearch fingerprint contract

Fingerprinting is a pure, deterministic evaluation of one bounded probe result. The engine itself
does not make network requests and never treats port 9200 as product evidence. `garga fingerprint`
issues `GET /` through the bounded scanner, then evaluates that probe locally. The
supported-version policy is recorded in [ADR 0005](adr/0005-elasticsearch-version-support.md).

## CLI

```sh
garga fingerprint 192.0.2.10
garga fingerprint --file targets.txt --format jsonl
garga fingerprint https://es.example.internal:9200 --threshold 80
```

The command does not discover extra APIs, evaluate checks, load signatures, or send credentials.
`--format` accepts `console`, `json`, or `jsonl`. Finding-oriented `csv` and `html` formats are
rejected. Identities use schema `0.1` with event `fingerprint.identity`. Probe failures after a
completed run exit `3`. `--threshold` overrides `fingerprint.threshold`. Target ingestion matches
[scan.md](scan.md). Signature-only matching is `garga vuln`; see [signatures.md](signatures.md).

## Score model

Signals are evaluated in this fixed order:

| Signal | Weight | Match rule |
|---|---:|---|
| `opensearch_marker` | `-100` | Root distribution or tagline identifies OpenSearch |
| `elastic_product_header` | `60` | `X-Elastic-Product` exactly identifies Elasticsearch |
| `elastic_tagline` | `25` | Canonical `You Know, for Search` root tagline |
| `elastic_version` | `15` | Strict three-component Elasticsearch version |
| `elastic_build_metadata` | `10` | At least two expected build metadata fields |
| `elastic_cluster_identity` | `10` | `name`, `cluster_name`, and `cluster_uuid` are present |
| `elastic_auth_challenge` | `25` | Security Basic/API key challenge on 401 or 403 |
| `elastic_warning_header` | `10` | Elasticsearch-formatted deprecation warning |
| `json_content_type` | `5` | JSON or Elasticsearch vendor JSON media type |

The sum is clamped to 0–100. OpenSearch markers therefore override coincidental Elasticsearch
field shapes and even a conflicting product header.

| Score | Classification |
|---:|---|
| 0–39 | `unknown` |
| 40–69 | `possible` |
| 70–89 | `likely` |
| 90–100 | `confirmed` |

The default detection threshold is 80. Classification always describes the score band, while
`Detected` tells callers whether the configured threshold was met. Product and version fields
are populated only for a detected response. Every signal, including unmatched signals, remains
available with a fixed identifier, weight, match state, and sanitized explanation.

## Parsing and data handling

The root parser reads only top-level identity fields and selected version/build fields from the
transport-bounded body. It rejects trailing JSON documents, invalid types, control-bearing or
oversized strings, and non-version text. Version suffixes are restricted to Elasticsearch's
known snapshot/alpha/beta/release-candidate forms so an arbitrary server value cannot become
report detail.

No raw response body, arbitrary header, node name, cluster name, UUID, build hash, or
authentication realm is copied into the fingerprint result. Version is the only server-derived
detail and passes the strict grammar first.

## Fixture corpus

Sanitized positive fixtures cover Elasticsearch 7.17.23, 8.0.0, 8.19.19, 9.0.0, 9.3.8, and
9.4.4. Negative fixtures cover OpenSearch, Kibana, generic JSON, nginx, and Apache. All names,
UUIDs, hashes, and dates are synthetic; fixtures contain no production response data. Malformed,
truncated, invalid UTF-8, and deeply nested fuzz inputs must never panic.

Live container coverage for the fully supported pins is opt-in and documented in
[integration.md](integration.md).
