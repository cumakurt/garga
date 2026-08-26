# ADR 0001: Safe operational defaults

- Status: Accepted
- Date: 2026-08-26

## Context

garga assesses network services that may contain production data. Unbounded concurrency,
state-changing requests, implicit credential attempts, permissive TLS, or unlimited response
handling could harm targets or operators even when the assessment is authorized.

## Decision

Normal scans are read-only and non-destructive. Check implementations may use only methods and
paths reviewed under the active-safe contract. Credential auditing is a separate explicit mode
and has no call path from normal scanning.

The initial normal-scan defaults are:

- 20 concurrent workers;
- 50 requests per second globally;
- 5 requests per second per host;
- a bounded queue sized to at most twice the worker count;
- one retry for transient failures only;
- a 2-second connect timeout and 5-second overall request timeout;
- a 512 KiB response-body limit and 64 KiB response-header limit;
- TLS certificate and hostname verification enabled;
- at most three redirects, with sensitive headers removed across origins.

Configuration is validated before network execution. Cancellation propagates through target
sources, scheduling, limiting, retries, and requests.

## Consequences

Large authorized assessments may require explicit tuning. Faster defaults are not accepted
without benchmark and safety evidence. `--insecure` may disable certificate verification only;
it does not disable limits, timeouts, redaction, or method safety.
