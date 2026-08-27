# Scanner engine contract

The scanner engine is a product-neutral, bounded pipeline from concrete endpoints to probe
results. It owns the supplied source and sink for one run and closes both exactly once.
`garga scan` and `garga vuln` use this engine for root probes and keep fingerprint, check, and
report logic in `internal/app`.

## Bounded pipeline

Built-in defaults use 20 workers, a queue of 40 tasks, 50 requests per second globally, and 5
requests per second per host. Configuration may tune these values only within validated limits.

The engine assigns a monotonically increasing input sequence and emits completed results in that
order. Ordering does not permit unbounded accumulation: an outstanding window equal to
`workers + queue capacity` applies backpressure before the source reads another endpoint. A slow
early task can therefore retain at most one window of later results. Queue depth, active workers,
and reorder-buffer peaks are reported in bounded-cardinality statistics. Synthetic 1k, 10k, and
100k loads keep those peaks at the configured ceilings; captured timings are in
[performance.md](performance.md).

The limiter is a goroutine-free pacer in `internal/ratelimit`. Global reservations and per-host
reservations both apply to every initial request and retry. Expired per-host state is pruned
periodically, so a long scan of unique hosts does not retain one limiter forever.

## Retry policy

Normal scans make one initial attempt plus the configured retry count. Retries use deterministic
endpoint-derived jitter around capped exponential backoff. This spreads simultaneous retryable
failures without making tests or behavior depend on a process-global random source.

Only these outcomes are retryable:

- request timeouts, DNS/connect/general network failures, and truncated response reads;
- HTTP status `408`, `425`, `429`, `500`, `502`, `503`, or `504`.

Cancellation, TLS verification, invalid endpoints, redirect policy, malformed HTTP, oversized
responses, generic/deterministic errors, and HTTP authentication/authorization responses are not
retried. Source parse errors occur before scheduling and are never sent to the retry path.

## Cancellation and output lifecycle

Cancellation stops source production, limiter waits, retry backoff, and context-aware probes.
Workers do not emit cancellation placeholders. Results that completed before cancellation are
drained and written in sequence order; if a canceled sequence leaves a gap, remaining completed
results are flushed in ascending sequence order. Sink writes use a cancellation-independent
context so local reporters can finalize completed results. Sink implementations must remain
bounded and return promptly.

`Run` waits for the producer and every worker, drains the result channel, closes the sink, and
then returns. It never starts a goroutine per target. When `Options.Progress` is set, one extra
ticker samples bounded counters until `Run` returns; the callback must not block or print hosts.
`Succeeded` statistics mean a bounded HTTP
probe completed, regardless of its HTTP status; a result with a probe error counts as `Failed`.

The default log level is `warn`, so those records are omitted unless the operator raises
`logging.level` or `GARGA_LOG_LEVEL` to `info` or `debug`. At `info`, the engine logs start
(worker and queue limits) and finish (the counter summary). Per-probe lines are `debug` only and
do not include hosts or URLs. The summary schema is documented in
[observability.md](observability.md).
