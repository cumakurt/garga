# ADR 0005: Elasticsearch version support matrix

- Status: Accepted
- Date: 2026-08-26

## Context

Elasticsearch response shape, authentication defaults, and available read-only APIs vary by
major and minor release. Claiming every historical version would create untested security-check
behavior. Supporting only the newest release would make an assessment tool ineffective for
identifying obsolete deployments.

Elastic's version policy maintains the newest two minor releases of the current major and the
final minor of the previous major. As of this decision, the current release lines are 9.4.x and
9.3.x, while 8.19.x is the final previous-major line. Elasticsearch 7.17 reached end of support
on 2026-01-15.

Sources:

- [Elastic product end-of-life and version policy](https://www.elastic.co/support/eol)
- [Current Elasticsearch release notes](https://www.elastic.co/docs/release-notes/elasticsearch)
- [Elasticsearch 8.19 release notes](https://www.elastic.co/guide/en/elasticsearch/reference/8.19/es-release-notes.html)

## Decision

v1 has two compatibility tiers:

| Tier | Version lines | Contract |
|---|---|---|
| Fully supported | 8.19.x, 9.3.x, 9.4.x | Fingerprint, capability, check, credential, vulnerability, and container integration coverage |
| Legacy detection | 7.17.x, 8.0–8.18, 9.0–9.2 | Fingerprint, version extraction, end-of-support reporting, and passive signature matching; API/check availability is capability-driven and not guaranteed |

Representative pinned fixtures cover 7.17.23, 8.0.0, 8.19.19, 9.0.0, 9.3.8, and 9.4.4.
Container release gates cover the newest available patch in each fully supported line and one
7.17.23 legacy smoke lane. Exact current-line patch pins are reviewed before every release.

Elasticsearch versions before 7.17 are unsupported. They may produce a `possible` fingerprint,
but garga does not claim complete version, capability, check, or vulnerability behavior for them.
OpenSearch is a negative product corpus and is never treated as an Elasticsearch compatibility
line.

## Consequences

Capability detection, rather than version checks alone, gates product-specific requests. Fixture
tests may cover more versions than the container matrix, but that does not upgrade their support
tier. A newly released Elasticsearch minor is not fully supported until sanitized fixtures and
the container lane pass. Matrix changes require this ADR or a superseding ADR to be updated.
