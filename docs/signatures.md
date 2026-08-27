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

Finding conversion emits schema `0.1` findings with `potential` tags. Version-only signatures use
low confidence. Signatures whose `requires` capabilities are available use medium confidence.
High confidence and a confirmed state are not used. Evaluation sends no additional HTTP request;
it reuses capability discovery. Declared probes, when present, are GET paths from the capability
allowlist.

`checks.WithSignatures` appends this evaluator to the default registry. `SignatureRegistry`
evaluates signatures only.

`garga scan` and `garga vuln` load the bundled corpus in `internal/vulnerability/bundled`
(embedded in the binary). That corpus is Elasticsearch server advisories from NVD CPE
(`elastic:elasticsearch` / `elasticsearch:elasticsearch`), OSV Maven
(`org.elasticsearch:elasticsearch`), and Elastic security announcements as of 2026-08-27.
Hits remain potential: version evidence is not confirmed exploitation. Kibana, Logstash, and
Beats advisories are out of product scope. Override with `--signatures DIR`.
`garga scan --no-signatures` runs exposure checks only.

`make signatures-validate` loads that bundled directory through the same `LoadDir` validator.
It does not fetch or activate a signed database.

Signed database updates are documented in [signature-updates.md](signature-updates.md).
