# Vulnerability signatures

garga stores vulnerability knowledge in YAML signatures, not in compiled scanner logic. The
loader and version matcher are documented below. Capability-aware finding conversion is in
[ADR 0012](adr/0012-vulnerability-evaluation.md).

## Schema `0.1`

```yaml
schema_version: "0.1"
id: garga.vuln.example-affected-range
title: Example version-range signature
description: Optional explanation.
severity: high
cvss: 7.5
cve:
  - CVE-2023-00000
product: elasticsearch
affected:
  - ">=7.0.0 <7.17.23"
  - ">=8.0.0 <8.11.1"
applicability:
  components_any: [ingest-attachment]
  realms_any: [jwt, oidc]
  jvm_major_min: 11
  jvm_major_max: 17
  settings_all:
    xpack.security.enabled: "true"
threat:
  known_exploited: false
  epss: 0.01234
  epss_percentile: 0.87654
  updated: "2026-08-27"
detection: version
references:
  - https://www.elastic.co/support/eol
remediation: Upgrade to a version outside the affected ranges.
```

Rules:

- `id` is stable and always starts with `garga.vuln.`.
- `product` is `elasticsearch`.
- `detection` is `version` for this schema. Version-only hits are not confirmed findings.
- Optional `requires` lists capability identifiers that must already be `available`. Unknown
  names are rejected. Derived capabilities such as `anonymous` add no extra HTTP request.
- Optional `applicability` describes observable runtime prerequisites. Values in
  `components_any` and `realms_any` are ORed; component, realm, JVM, and setting groups are ANDed.
  JVM bounds are inclusive. `settings_all` accepts only bounded non-sensitive setting names and
  values.
- Optional `threat` stores signed-corpus prioritization data. EPSS values and percentiles are in
  the inclusive `0` to `1` range, and `updated` is an ISO date. `known_exploited` reflects CISA
  KEV membership at that date; it does not prove exploitation of the assessed target.
- `affected` is a list of ranges. A version matches when any range matches. A range is a
  space-separated list of `=`, `>`, `>=`, `<`, or `<=` comparators, all of which must hold.
- Version comparison is semantic. `8.11.10` is greater than `8.11.2`.
- Prerelease suffixes follow the fingerprint grammar: `SNAPSHOT`, `alphaN`, `betaN`, `rc.N`.
  A prerelease is less than the corresponding release.
- Unknown YAML fields, extra documents, symlinks, duplicate IDs, and invalid constraints are
  rejected. Errors name the signature file and, when the YAML parser reports it, the line.

## Passive detection states

| State | Meaning |
|---|---|
| `unmatched` | Product or version is outside the signature. |
| `potential` | The observed version is in an affected range. Evidence is version-only. |
| `applicable` | The affected version and every observable runtime prerequisite match. |
| `not_applicable` | At least one known runtime prerequisite does not match; no finding is emitted. |

Finding conversion emits schema `0.1` findings with `potential` tags. Version-only signatures use
low confidence. Signatures whose `requires` capabilities are available use medium confidence.
High confidence is reserved for `applicable` context-aware matches. Evaluation sends no additional
HTTP request; it reuses capability discovery or the normalized `garga assess` snapshot. A missing
inventory keeps the result `potential` instead of treating absence as proof. Declared probes, when
present, are GET paths from the capability allowlist.

`checks.WithSignatures` appends this evaluator to the default registry. `SignatureRegistry`
evaluates signatures only.

`garga scan` and `garga vuln` load the bundled corpus in `internal/vulnerability/bundled`
(embedded in the binary). That corpus is Elasticsearch server advisories from NVD CPE
(`elastic:elasticsearch` / `elasticsearch:elasticsearch`), OSV Maven
(`org.elasticsearch:elasticsearch`), and Elastic security announcements as of 2026-08-27.
Hits remain potential: version evidence is not confirmed exploitation. Kibana, Logstash, and
Beats advisories are out of product scope. Configuration- and runtime-dependent advisories stay
potential because a root version response cannot prove realm, plugin, processor, JDK, or local
mitigation state. Override with `--signatures DIR`.
`garga scan --no-signatures` runs exposure checks only.

`make signatures-validate` loads that bundled directory through the same `LoadDir` validator.
It does not fetch or activate a signed database.

## Official advisory audit

Maintainers can audit the existing corpus against official Elastic Security Announcement topics,
CVE Services records, CISA KEV, and the current FIRST EPSS data set:

```sh
go run ./scripts/advisory-sync \
  -signatures internal/vulnerability/bundled \
  -snapshot advisory-audit.json
```

The sync fetcher uses GET only, bounded responses, a 30-second client timeout, HTTPS downgrade
protection, up to five redirects, and three transient attempts with bounded `Retry-After`
handling. It inventories every CVE already in the corpus plus CVEs discovered in Elasticsearch
security topics. Missing signatures are generated only when structured CVE affected-version
records can be converted to this range grammar without ambiguity; unsafe records are reported as
`blocked` for manual review. The tool exits `3` while ready or blocked gaps remain.

Enrichment never overwrites its source. It creates a new validated directory and can optionally
include validated candidates:

```sh
go run ./scripts/advisory-sync \
  -signatures internal/vulnerability/bundled \
  -candidates review-candidates \
  -corpus-out enriched-corpus \
  -include-candidates
```

## Publishing

After review, create the deterministic update artifacts consumed by `garga update`:

```sh
go run ./scripts/signature-bundle \
  -signatures enriched-corpus \
  -out publish/2026.08.27.1 \
  -version 2026.08.27.1 \
  -key maintainer-ed25519-private.pem
```

The key must match the public trust root embedded in the release that will consume the bundle.
The publisher validates the complete corpus, rejects symlinks and existing output paths, and
atomically creates deterministic `manifest.json`, `manifest.sig`, and `signatures.zip` files.
Signed database installation and rollback are documented in
[signature-updates.md](signature-updates.md).
