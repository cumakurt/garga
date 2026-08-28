# ADR 0013: Streaming reporters

- Status: Accepted
- Date: 2026-08-26

## Context

Findings must be consumed by people and automation without holding an entire scan in memory.
HTML reports must remain usable offline and must not execute attacker-controlled markup. Claiming
schema `1.0` before the first public tag would freeze a pre-release field set.

## Decision

- Reporters live in `internal/report` and consume `model.Finding` only. They must not import the
  scanner, CLI, or Cobra.
- `Writer` is a streaming interface: `Write` emits one finding; `Close` completes the document.
  JSONL and the JSON document writer do not retain a finding slice. Console may buffer until
  `Close` so human output can be grouped by target, with exploitable findings listed first,
  then severity, and ANSI color on a TTY.
- Supported formats are `console`, `json`, `jsonl`, `csv`, `html`, SARIF 2.1.0, and CycloneDX 1.6 VEX.
- SARIF and VEX require a complete document and therefore retain at most 100,000 findings before
  deterministic rendering. Exceeding the limit fails instead of silently truncating output.
- Machine formats carry `schema_version` `0.1`. Console output is not a machine schema.
- HTML uses `html.EscapeString` for all finding text, inline CSS only, and no external resources.
  `garga scan` also writes a buffered, timestamped PDF assessment and can write a matching HTML
  assessment to the working directory; those side channels do not change stdout writers.
- `garga report` reads JSONL from stdin or `--input` and writes one of the formats. It does not
  contact the network.

## Consequences

`garga scan` and `garga vuln` stream findings into these writers without coupling report encoding
to scheduler internals. The public `1.0` finding schema remains reserved for the first public
tag, after golden fixtures and release documentation exist.
