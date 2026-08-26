# Performance baseline

WP 9.2 records captured CPU, allocation, memory, goroutine, throughput, and latency numbers for
the parser, fingerprint engine, version matcher, JSONL reporter, and in-memory scanner worker
pool. These are a machine-specific snapshot, not a public SLA.

CI asserts resource **bounds** (queue, workers, reorder window, goroutine ceiling, no retained
finding slice). It does not assert exact `ns/op`. Refresh this file when a work package changes
hot-path cost, and cite a new capture.

## Capture environment

| Field | Value |
|---|---|
| Date | 2026-08-26 |
| Go | `go1.26.5 linux/amd64` |
| CPU | Intel(R) Core(TM) Ultra 9 285H |
| Logical CPUs | 16 (1 thread per core, 16 cores) |
| `GOMAXPROCS` | 16 (from the `-16` benchmark suffix) |
| CPU frequency | max 5400 MHz; `lscpu` reported scaling at 33% during capture |
| OS | Linux 7.1.9 x86_64 |
| Command | `make bench` (`go test -run='^$' -bench=. -benchmem -count=1` on the packages below) |
| Percentiles | `go test -count=1 -v` on the named latency tests in the same session |

The synthetic scanner and JSONL loads do not use the network. The in-memory prober returns
`HTTP 200` with an empty body. Do not compare these throughputs to a networked Elasticsearch scan.

## Microbenchmarks (`-benchmem`)

Mean cost from one `-count=1` run:

| Benchmark | ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| `Parse` IPv4 `192.0.2.10` | 176.7 | 32 | 2 |
| `Parse` hostname | 411.3 | 144 | 3 |
| `Parse` HTTPS URL | 708.2 | 176 | 3 |
| CIDR `Next` (`10.0.0.0/8`) | 72.83 | 15 | 1 |
| Fingerprint `Analyze` Elasticsearch 9.4.4 root | 27968 | 7832 | 97 |
| Fingerprint `Analyze` nginx HTML negative | 1346 | 1488 | 10 |
| `ParseVersion` `8.17.3` | 161.6 | 48 | 1 |
| `Evaluate` affected range (`8.11.0`) | 1365 | 296 | 7 |
| `Evaluate` unmatched (`8.11.10`) | 1111 | 240 | 5 |
| JSONL `Write` one finding to `io.Discard` | 1479 | 352 | 1 |
| Scanner `Run` 1,000 in-memory tasks (8 workers, queue 16) | 3,158,690 | 324,904 | 5,795 |
| Scanner `Run` 10,000 in-memory tasks (8 workers, queue 16) | 33,344,091 | 3,210,614 | 59,822 |

Implied in-memory scanner means from the 10,000-task benchmark: about **3.3 µs/task**,
**321 B/task**, and **6 allocs/task**.

## Latency percentiles

Sequential 10,000-sample loops on the same machine (`p50` / `p95` / `p99`):

| Path | p50 | p95 | p99 |
|---|---|---|---|
| `Parse` IPv4 | 316 ns | 414 ns | 474 ns |
| `Parse` hostname | 448 ns | 689 ns | 964 ns |
| `Parse` HTTPS URL | 886 ns | 1.167 µs | 1.897 µs |
| Fingerprint Elasticsearch 9.4.4 root | 21.486 µs | 40.469 µs | 61.269 µs |
| `ParseVersion` | 167 ns | 298 ns | 370 ns |
| `Evaluate` affected range | 1.496 µs | 2.19 µs | 3.059 µs |
| JSONL `Write` | 1.304 µs | 2.077 µs | 2.737 µs |
| Scanner sequential emit interval (1 worker, 10,000 tasks) | 2.414 µs | 5.783 µs | 11.568 µs |

The sequential scanner row is the gap between successive sink writes with one worker, not network
RTT. Mean task cost for that run was 2.58 µs.

## Synthetic loads (1k / 10k / 100k)

`TestEngineSyntheticLoadsRemainBounded` uses 8 workers, queue capacity 16, zero retries, an
in-memory prober, and a **counting** sink that does not store results.

| Tasks | Elapsed | Throughput | Peak goroutines | Peak queue | Peak workers | Peak reorder | HeapInuse before | HeapInuse after |
|---:|---|---:|---:|---:|---:|---:|---:|---:|
| 1,000 | 2.588 ms | 386,375/s | 13 | 16 | 3 | 24 | 991,232 B | 1,056,768 B |
| 10,000 | 31.472 ms | 317,739/s | 13 | 16 | 5 | 24 | 1,032,192 B | 1,138,688 B |
| 100,000 | 293.770 ms | 340,402/s | 13 | 16 | 5 | 24 | 1,056,768 B | 1,196,032 B |

JSONL streaming to `io.Discard` (writer has no finding slice):

| Findings | Elapsed | Throughput |
|---:|---|---:|
| 1,000 | 2.243 ms | 445,839/s |
| 10,000 | 17.419 ms | 574,077/s |
| 100,000 | 113.490 ms | 881,134/s |

## Bounds these numbers support

- Queue depth never exceeded capacity 16. Reorder buffer never exceeded the outstanding window
  (`workers + queue` = 24). Peak goroutines stayed at 13 from 1k through 100k.
- After-GC `HeapInuse` grew by about 139 KiB from the 1k run to the 100k run. That is not linear
  in task count; the engine and JSONL writer do not retain the full result set.
- The 100,000-task and 100,000-finding cases skip under `go test -short`.

Reproduce with:

```sh
make bench
go test -count=1 -v -run 'TestParseLatencyPercentiles|TestAnalyzeLatencyPercentiles|TestVersionLatencyPercentiles|TestJSONLWriteLatencyPercentiles|TestJSONLStreamingLoadsDoNotRetainFindings|TestEngineSyntheticLoadsRemainBounded|TestEngineSequentialTaskLatencyPercentiles' ./internal/target ./internal/fingerprint ./internal/vulnerability ./internal/report ./internal/scanner
```
