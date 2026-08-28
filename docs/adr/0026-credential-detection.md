# ADR 0026: Credential detection modes

- Status: Accepted
- Date: 2026-08-28

## Context

Operators performing authorized assessments sometimes need to test whether known or likely
credentials are accepted by Elasticsearch. The existing `garga auth-audit` command only accepts a
short explicit list and does not model common assessment techniques such as credential stuffing,
password spraying, brute force, or dictionary attacks.

Those techniques must remain isolated from the anonymous scan path, bounded, and secret-safe.
They must continue to use the GET-only authenticate contract.

## Decision

- Credential detection lives in `internal/credential/detect` and is invoked only by
  `garga auth-detect`.
- Supported modes are:
  - `stuffing`: explicit username+password pairs from stdin or a local file, including leak-style
    `user:pass`, `user,pass`, `user pass`, and `basic USER PASS` lines;
  - `spraying`: each password is tried across every username before the next password, from
    structured stdin or `--users-file` plus a password list, with optional `--spray-delay`;
  - `brute-force`: many passwords, or a bounded charset product, against one username;
  - `dictionary`: an operator wordlist (`--wordlist` or `--passwords-stdin`) against one username.
- Dictionary mode does not generate candidates. Charset generation is brute-force only and is
  rejected unless the product is at most 256 candidates.
- Every attempt is `GET /_security/_authenticate`. 401/403 are never retried. Exhausted HTTP 429
  responses stop the run as `rate_limited`.
- Default rate is 1 request/second globally and per host. Default attempt ceiling is 100,
  configurable up to 1000.
- Input limits: 512 stuffing pairs, 256 usernames, 256 passwords, 512 spraying combinations.
- Secrets are stdin or local list files. There is no `--password` flag.
- Scanner, fingerprint, capability, check, health, and report packages must not import the
  detection engine.

## Consequences

`garga auth-detect` is a separate explicit mode from `garga auth-audit`. The audit command keeps
its smaller 32-credential / 20-attempt contract for quick verification lists. Detection modes
support larger bounded plans but remain unsuitable for unbounded internet-scale guessing.
