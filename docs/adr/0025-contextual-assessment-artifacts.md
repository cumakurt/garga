# ADR 0025: Contextual assessment and interoperable artifacts

- Status: Accepted
- Date: 2026-08-28

## Context

Anonymous version matching is useful for broad discovery but cannot determine whether a
configuration-, JDK-, realm-, plugin-, or module-dependent advisory applies to a cluster. The
project also needs reviewable finding changes, common security interchange formats, verifiable
deliverables, and capacity trend analysis without weakening its GET-only safety boundary.

## Decision

- `garga assess` is an explicit single-target mode built on the centralized health collector. It
  may use one operator-provided credential, enables deep collection by default, and never uses the
  credential-audit engine.
- Signatures may declare bounded runtime applicability and signed threat metadata. Unknown
  inventory leaves a result potential; a known mismatch suppresses it; a known match is
  applicable. None of those states confirms exploitation.
- CISA KEV and FIRST EPSS data prioritize findings but do not change affected-version truth.
- SARIF 2.1.0 and CycloneDX 1.6 VEX are bounded, deterministic whole-document reporters. The
  existing JSONL path remains the streaming lifecycle interchange.
- `garga diff`, `garga evidence`, and `garga forecast` are offline commands. They use bounded
  inputs, reject ambiguous or duplicate identity, and do not contact Elasticsearch.
- Advisory synchronization never modifies the active corpus. Candidate creation requires
  safely convertible structured CVE version data, and publishing reuses the existing Ed25519
  update manifest and archive contract.
- Human PDF artifacts use the visible title `Test Report` and expose the same applicability and
  threat-priority facts as machine output.

## Consequences

Authenticated assessment remains isolated from multi-target scan and credential spraying.
Runtime inventory can reduce false positives but cannot prove the absence of unpublished issues,
unobservable prerequisites, or exploitation. SARIF/VEX generation retains at most 100,000
findings; evidence bundles retain at most 32 artifacts and 256 MiB of declared content. Forecast
input is limited to 64 snapshots and 64 MiB in total. Capacity dates are statistical estimates
with explicit fit confidence, not service guarantees.
