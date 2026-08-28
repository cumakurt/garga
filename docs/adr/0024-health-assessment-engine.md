# ADR 0024: Read-only health assessment engine

- Status: Accepted
- Date: 2026-08-27

## Context

The existing assessment commands were optimized for multi-target product identification and
security exposure checks. Operational Elasticsearch health requires a different boundary: one
cluster, larger version-dependent responses, optional authentication, correlated metrics, and
delta-aware interpretation of cumulative counters. Allowing each health rule to make its own API
calls would duplicate expensive requests, hide partial permission failures, and make safety and
testing difficult to enforce.

## Decision

- Health is an explicit `garga health TARGET` command and does not change the behavior of `scan`.
- A centralized collector issues only bounded, bodyless `GET` requests and records cost, permission,
  failure, byte, retry, and duration metadata.
- Normalization converts supported Elasticsearch 7.17, 8.x, and 9.x response shapes into one
  `ClusterSnapshot`; checkers receive the snapshot and cannot perform network I/O.
- Optional high-cost collection is gated by `--deep`. Allocation explain is conditional on
  unassigned shards.
- Checkers declare stable IDs, category, description, and supported versions. Missing or denied
  data skips the affected check instead of aborting unrelated analysis.
- Scoring deduplicates penalties by root cause. Correlation and confidence remain separate from
  direct API evidence.
- Baseline files contain a minimal secret-free counter model and are cluster- and time-bound.
- Authentication is outside general YAML configuration. Plaintext credential transport is denied
  by default, and all reporter inputs pass through centralized redaction.
- Health report schema `1.0` is independent from the pre-release streaming finding schema used by
  other commands.

## Consequences

One API response can safely feed many checks, and fixtures can test most behavior without a live
cluster. Large-cluster impact is bounded by concurrency, rate, response size, and the normal/deep
cost split. New checks must extend the normalized model or reuse existing fields; they must not
query Elasticsearch directly. A partial report can contain skipped checks, so consumers must read
coverage metadata instead of assuming that absence of a finding proves a check ran.

The model deliberately does not infer trends from one snapshot. Accurate rates and forecasts need
a compatible earlier baseline, and unsupported counter resets are ignored rather than converted
to misleading negative deltas.

ADR 0025 extends this engine with the explicit `garga assess` command, runtime-aware vulnerability
evaluation, interoperable artifacts, lifecycle comparison, evidence integrity, and multi-snapshot
forecasting without changing the `garga health` contract.
