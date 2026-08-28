# Deep project analysis — canonical report gates

## Status

Complete.

## Scope

- [x] Repository and secrets/report architecture map
- [x] Fix verified secrets engine bugs (source release, wide objects, 429 decay, redirect headers)
- [x] Wire entropy walk flag; default entropy on for Engine
- [x] Renderer parity: partial failures, pretty categories, SARIF severity, PDF INFO color
- [x] Mandatory tests: output parity, zero-plaintext pipeline, pre-render invariants, determinism
- [x] Docs/CHANGELOG alignment (severity enum case)
- [x] Quality gates: test, race, vet, build, secrets benchmarks

## Review

Secrets Console/JSON/PDF already shared one `ScanReport`. This pass closed the
mandatory gates: structural output-parity tests, pipeline plaintext-canary checks
(including `pdftotext` when present), broader `ValidateResult` coverage, and
deterministic finding sort.

Verified engine fixes: sampled `_source` is now released by index (not a range
copy), wide objects keep sensitive keys under the object-size cap, 429 slowdown
decays after 2xx, and cross-origin redirects strip Authorization plus Cookie /
Proxy-Authorization / Referer.

`garga scan` / `garga health` remain separate streaming/health report models
(ADR 0013 / health schema 1.0). They were not rewritten onto the secrets
`ScanReport`; that would be a breaking reporter redesign, not a secrets-scanner
defect.
