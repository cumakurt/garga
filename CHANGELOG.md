# Changelog

All notable changes to garga are documented in this file.

## Unreleased

## [0.1.0] - 2026-08-28

First public release. CLI flags, configuration keys, and streaming finding schema `1.0` are the
compatibility baseline for this tag.

### Changed

- README screenshot gallery keeps only captures with a readable assessment result
  (`fingerprint`, `scan`, `auth-check`, `auth-audit`, `auth-detect`, `health`, `secrets`).
  Empty or one-line captures (`vuln` with no findings, `--help`, `version`, unsigned
  `update`, fixture generate, truncated JSON/CSV) are no longer published.
- README screenshots and `sample/` PDF reports are regenerated from Elasticsearch 8.19.20
  Docker demos after the scanner and reporting fixes in this tag.

### Fixed

- Secrets generate no longer follows cross-origin redirects, so Authorization and PUT
  bodies cannot leak to another host. Search sampling now truncates oversized `_search`
  hit arrays to the requested size. Mapping walks count `properties` wrappers toward
  `maxDepth`. Document walks honor cancellation. Assignment-style correlation caps the
  number of parsed lines.
- Health HTML score colors match the canonical health labels (`High Risk`, `Perfect`,
  `Minor Issues`). Report writers redact metrics resource names. Baseline overwrite
  refuses to replace a symbolic link.
- Secrets console, JSON, and PDF reports now share the same canonical summary counters,
  including partial failures. Table and PDF category labels match the summary. SARIF keeps
  canonical severity on each result. Wide documents keep sensitive fields when object-size
  caps apply, sampled document bodies are released after classification, and 429 slowdown
  decays after successful requests.

### Added

- `garga auth-detect` for bounded credential stuffing, password spraying, brute-force, and
  dictionary assessments against one Elasticsearch target. Modes are explicit, rate-limited, and
  isolated from the scan path. Secrets come from stdin or local list files (`--wordlist`,
  `--users-file`, `--credentials-file`). Brute-force may generate a bounded charset product.
  Stuffing accepts leak-style `user:pass` pairs. Spraying uses a password-outer loop and optional
  `--spray-delay`.
- `garga secrets --deep-scan` for an explicit, still-bounded higher-coverage profile: larger
  per-index samples, generic keyword/text `_source` fields, deeper object/array walks, and a
  broader correlation alias list. Hard caps remain. Credential correlation reports same-object
  pairs (`username`+`password`, client credentials, access-key pairs, database/API/token pairs,
  connection strings, HTTP Basic/Bearer) with `related_fields`, `masked_values`, and occurrence
  counts. JSON includes `scan_mode` and examination stats. PIT search is not used.
- README screenshots from an authorized Docker Elasticsearch 8.19.20 demo, plus example PDF
  reports under `sample/`. The scan sample PDF is produced from an anonymous (security-disabled)
  node and includes an EXPLOITABLE unauthenticated-admin finding. Auth-detect screenshots show a
  successful credential detection in stuffing, spraying, dictionary, and brute-force modes.
- `garga assess`, an authenticated-capable GET-only security assessment that combines the health
  engine with version, node JDK, module/plugin, realm, safe-setting, and signature applicability
  evidence. Runtime prerequisites distinguish `applicable` findings from version-only
  `potential` findings without sending exploit payloads.
- CISA KEV and FIRST EPSS/percentile metadata, threat-data dates, and bounded priority scores in
  signatures, finding schemas, CSV, HTML, terminal, and PDF reporting.
- SARIF 2.1.0 and CycloneDX 1.6 VEX output for `scan`, `vuln`, and offline `report` workflows.
- `garga diff` for deterministic new/resolved/unchanged/regressed/improved lifecycle comparison,
  including CI failure thresholds for new, regressed, or any changed findings.
- `garga evidence pack` and `garga evidence verify` for deterministic SHA-256 assessment bundles
  with optional Ed25519 signing and bounded archive verification.
- `garga forecast` for offline 85/90/95 percent disk-threshold projections from 2-64 compatible
  health baselines, with regression fit and explicit confidence.
- Maintainer `advisory-sync` and `signature-bundle` tools for bounded official-feed auditing,
  reviewable candidate generation, corpus enrichment, and deterministic signed update publishing.
- Cross-node Elasticsearch, JDK, and installed module/plugin drift analysis.
- `garga health` advanced read-only Elasticsearch assessment with centralized collection and
  normalization, 38 version-aware health checkers, weighted root-cause scoring, correlation,
  partial-failure coverage, scanner telemetry, terminal/JSON/HTML/Markdown reports, configurable
  profiles and thresholds, optional deep collection, and secret-free baseline/delta snapshots.
- Every completed health assessment writes a timestamped, owner-only standalone PDF artifact
  (`garga-health-*.pdf`) in the current directory. The report covers executive summary, detailed
  evidence, correlations, remediation, coverage, and telemetry. `--html-report` (or
  `output.html_report` / `GARGA_OUTPUT_HTML_REPORT`) also writes the matching HTML document.
- Every completed `garga scan` writes a timestamped, owner-only standalone PDF artifact
  (`garga-scan-*.pdf`) in the current directory. The artifact is titled `Test Report` and
  structured to PTES, NIST SP 800-115, OWASP, and CREST (document control, disclaimer, scope,
  methodology, risk rating, technical findings with evidence, attack scenarios, remediation,
  and appendices). `--html-report` also writes the matching HTML report. Stdout `--format` is
  unchanged except that `--format html` evidence cells include observed proof lines. Console
  scan output always prints evidence for each finding.
- Standalone health and scan HTML reports include clickable developer LinkedIn and GitHub
  links in the footer. PDF artifacts include the same identity as plain-text URLs.

- Cross-platform release archives, SHA-256 checksums, SPDX 2.3 SBOMs with explicit main-package
  relationships, and an optional GPG signature of `SHA256SUMS`.
- Responsible-use guidance and a documented binary/signature rollback procedure.
- `garga scan` for bounded, GET-only Elasticsearch assessments with streaming reports.
- `garga fingerprint` for GET `/` product identity without exposure checks.
- `garga vuln` for signature-only potential vulnerability matching.
- Committed golangci-lint v2 configuration, `make lint`, and pull-request `govulncheck`.
- GET-only enforcement in the shared HTTP transport (`NewRequest` and `Client.Do`).
- Shared Elasticsearch GET path catalog; credential verification uses `PathAuthenticate`.
- Bundled Elasticsearch CVE corpus (NVD CPE, OSV Maven, and Elastic security announcements as of
  2026-08-27). `garga scan` and `garga vuln` load it by default. `--signatures DIR` replaces it;
  `garga scan --no-signatures` skips CVE matching.
- Official Elasticsearch advisory coverage now includes the conditional Log4j2 message-lookup
  issues, JWT realm denial of service, and ingest-attachment XXE records that were absent from
  the initial bundled corpus.
- Live TTY progress bar on stderr for `garga scan`, `garga vuln`, and `garga fingerprint`.
  `--no-progress` disables it. The bar uses probe counters only and does not print hosts or URLs.
- CSV columns `cvss` and `description`. CSV/JSON/JSONL/HTML also print a human detection summary
  on stderr.
- `make signatures-validate` for the bundled YAML corpus, included in `make check` and pull-request CI.
- `make install` copies the rebuilt `garga` binary to `$(PREFIX)/bin` (default `/usr/local/bin`).

### Changed

- Streaming finding documents now use schema `1.0`, the public contract reserved in
  [ADR 0003](docs/adr/0003-output-versioning.md).

- `garga secrets` now discards raw discovered values before constructing its canonical `1.1`
  report. Console, JSON, JSONL, table, SARIF, and PDF render the same masked findings and
  authoritative summary. A pre-render invariant gate checks IDs, enums, timestamps,
  occurrences, and summary parity; explicit output files are written atomically with mode
  `0600` and symbolic-link destinations are rejected.
- `garga secrets` document sampling sorts on `_doc` so Elasticsearch 8+/9 clusters can be
  scanned without enabling `_id` fielddata. Sampling failures are logged at warn.

- The minimum build toolchain is Go 1.26.6 so release binaries include the standard-library
  security fixes required by `govulncheck`.
- Supported container lanes now track security-updated Elasticsearch 8.19.20 and 9.4.5 plus the
  current 9.5.2 release.
- PDF reports use the concise `Test Report` title, dedicated cover pages, format-neutral
  methodology text, threat-priority fields, clearer evidence hierarchy, and wider status columns
  so long labels remain readable.
- `garga health` uses dedicated process codes: invalid flags, config, targets, and `--fail-on`
  values return 2; collection, connection, authentication, product, and timeout failures return 5;
  `--fail-on` warning/high/critical return 10/11/12. Those codes no longer overlay 1/2/3/4 used by
  other commands.
- `run.sh` is now `install.sh`. It installs build dependencies, builds `bin/garga`, and copies
  the binary to `PREFIX/bin`. It no longer launches garga commands.
- Default `logging.level` is `warn`. Scanner start/finish JSON is `info`; per-probe records stay
  `debug`.
- Console reports group findings by target, list exploitable findings first, use color on a
  terminal, and print a count summary including how many findings are exploitable.
- `garga health` terminal reports use the same TTY color rules as scan console output. Findings
  are grouped by severity, then category, with aligned check/resource/evidence fields, a colored
  score headline, and prioritized action colors. `NO_COLOR` and non-TTY stdout stay uncolored.
- Console and HTML listings highlight remotely usable compromise-class findings (`EXPLOITABLE`).
  The mark is not confirmed exploitation. Machine formats add an `exploitable` tag when the
  same classifier matches.
