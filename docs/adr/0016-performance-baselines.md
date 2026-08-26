# ADR 0016: Documentary performance baselines

- Status: Accepted
- Date: 2026-08-26

## Context

The master plan requires parser, fingerprint, version, JSONL, and worker-pool benchmarks plus
1k/10k/100k synthetic loads. Exact `ns/op` values move with CPU frequency, `GOMAXPROCS`, and Go
patch releases. Encoding those numbers as CI assertions would fail on slower runners without
proving a real regression. Extra benchmark frameworks would add a dependency for a job the
standard `testing` package already does.

## Decision

- Hot paths use Go `testing.B` with `-benchmem`. `make bench` runs them; `make check` does not.
- Unit tests assert **bounds**: worker/queue/reorder ceilings, a goroutine peak relative to the
  baseline, and reporters/sinks that do not retain a finding or result slice. 100k cases skip
  under `-short`.
- Captured timings, allocations, heap snapshots, throughput, and percentiles live in
  [docs/performance.md](../performance.md) with the machine and command that produced them.
- Performance claims in documentation must cite that file (or a newer capture), never invented
  numbers.

## Consequences

A slower laptop or CI runner can still merge if bounds hold. A real unbounded-growth bug still
fails the load tests. Refreshing the baseline is a documentation change after a measured run, not
a reason to pin nanoseconds in CI.
