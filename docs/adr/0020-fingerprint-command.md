# ADR 0020: Fingerprint command

- Status: Accepted
- Date: 2026-08-27

## Context

Operators sometimes need product identity without running exposure checks or capability
follow-up GETs. Folding that into `garga scan` would mix detection with assessment. Emitting
fingerprint results as `model.Finding` values would overload the finding schema.

## Decision

- `garga fingerprint` probes `GET /` only, then evaluates `internal/fingerprint` locally.
- Output is a streamed identity record (schema `0.1`, event `fingerprint.identity`), not a finding.
- Supported encodings are console, JSON, and JSONL. CSV and HTML remain finding-report formats.
- The command does not import credential audit or the signature updater.
- Probe failures after a completed run exit `3`, matching scan.

## Consequences

`garga vuln` is the signature-matching command defined in ADR 0021. Identity JSON is a
pre-release shape and is not finding schema `1.0`.
