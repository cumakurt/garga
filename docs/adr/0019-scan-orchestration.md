# ADR 0019: Scan orchestration

- Status: Accepted
- Date: 2026-08-26

## Context

Work Packages 1.1 through 10.2 implemented target input, transport, a product-neutral scanner,
fingerprinting, capability discovery, checks, signatures, reporters, and logging. Operators still
could not run a bounded assessment from the public CLI. Putting fingerprint, check, and report
logic inside the scanner would break the product-neutral engine contract. Putting it in
`internal/cli` would mix Cobra with HTTP orchestration.

## Decision

- `garga scan` is the public assessment command.
- `internal/app` owns one-run orchestration: target conversion, transport, scanner, fingerprint,
  capability discovery, check evaluation, optional signature loading, and streaming reports.
- The scanner engine continues to issue only product-neutral `GET /` probes.
- Capability follow-up requests remain the GET-only allowlist in `internal/capability`.
- Scan does not import Cobra, `internal/credential`, `internal/credential/audit`, or
  `internal/update`.
- Findings never fail the process. Probe failures after a completed run exit `3`.

## Consequences

Authenticated scan, if added later, is an explicit mode and must not reuse the credential-audit
engine. `garga fingerprint` is the identity-only command defined in ADR 0020. `garga vuln` is the
signature-matching command defined in ADR 0021.
