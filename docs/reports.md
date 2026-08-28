# Reports

Reporters support console, JSON, JSONL, CSV, standalone HTML, SARIF 2.1.0, and CycloneDX 1.6
VEX. They
consume `model.Finding` values and do not import the scanner. Machine formats use finding schema
`0.1`. That is a pre-release document shape and is not the public `1.0` contract in
[ADR 0003](adr/0003-output-versioning.md).

`garga scan`, `garga vuln`, and `garga report` share these writers. Scan and vuln stream findings
as they are produced.

## CLI

```sh
garga report [--format console|json|jsonl|csv|html|sarif|vex] [--input FILE] [--config FILE]
```

Input is JSONL: one finding JSON object per line, from stdin or `--input`. The default format is
`console`, or `output.format` when a configuration file or `GARGA_OUTPUT_FORMAT` is set. The
command does not contact the network. Invalid records exit `2` and are not echoed.

## Formats

| Format | Contract |
|---|---|
| `jsonl` | One self-describing finding object per line. Writers do not retain the complete scan. |
| `json` | A document `{"schema_version":"0.1","findings":[...]}`. Findings are marshaled as they arrive. |
| `csv` | A header row plus one row per finding, including `cve`, `cvss`, and `description`. Formula-like cells are prefixed with `'`. Machine formats also print a grouped console summary on stderr. |
| `html` | A standalone document with inline CSS. All text is HTML-escaped. There are no scripts, links, images, or other network resources. Exploitable rows are highlighted. Each row's evidence cell lists observed proof cards (native codes plus target, transport, and product facts). |
| `sarif` | A deterministic SARIF 2.1.0 log. Check IDs become rules, findings become results, targets become artifact locations, and stable finding IDs become partial fingerprints. |
| `vex` | A deterministic CycloneDX 1.6 VEX document. Targets are components, CVEs are vulnerabilities, and observable applicability maps to VEX analysis states. |
| `console` | Human-oriented, grouped by target. Exploitable findings are listed first, then severity. Color is used on a terminal unless `NO_COLOR` is set. Every finding prints visual evidence lines (`code — summary`). It is not a machine schema. |

JSON, JSONL, CSV, and HTML emit findings in write order. SARIF and VEX retain at most 100,000
findings so they can construct schema-level rule and component indexes deterministically. Console buffers until `Close` and
groups by target, then lists exploitable findings first, then severity (critical first). Empty
schema versions are set to `0.1` on write.

A finding is marked `exploitable` when evidence shows unauthenticated `read`/`write`/`admin`
access, or when a signature looks like a remote-compromise class (RCE, untrusted
deserialization, authentication bypass, or CISA KEV). The mark is a listing emphasis. It is
not confirmed exploitation: garga does not send writes or exploit payloads. Anonymous metadata,
TLS-not-enabled, public-network, and denial-of-service advisories are not marked.

## JSON fields

Stable finding field names:

`schema_version`, `id`, `check_id`, `title`, `description`, `target` (`scheme`, `host`, `port`,
`path`), `product`, `version`, `severity`, `confidence`, `cvss`, `cve`, `evidence` (`code`,
`summary`), `remediation`, `references`, `first_seen`, `tags`, `resource`, `applicability`,
`known_exploited`, `epss`, `epss_percentile`, `priority_score`, and `threat_updated`.

CSV columns:

`schema_version`, `id`, `check_id`, `title`, `severity`, `confidence`, `product`, `version`,
`target`, `resource`, `cve`, `cvss`, `description`, `tags`, `evidence`, `remediation`,
`applicability`, `known_exploited`, `epss`, `epss_percentile`, `priority_score`, and
`threat_updated`.

When the selected format is not `console`, `garga scan`, `garga vuln`, and `garga report` also
print a grouped human summary of the same findings on stderr so operators can see detected
conditions without opening the machine file.

`garga scan` additionally writes a timestamped standalone PDF assessment (`garga-scan-*.pdf`)
to the current directory. That artifact is not the streaming `--format html` table: it is a
security assessment titled `Test Report` and structured to PTES, NIST SP 800-115, OWASP, and
CREST: document control, disclaimer,
executive summary, scope, rules of engagement, methodology, risk rating, technical findings
with evidence, attack scenarios, remediation, and appendices. Pass `--html-report` to also
write `garga-scan-*.html`. `garga health` writes `garga-health-*.pdf` the same way, with
optional HTML via the same flag. Machine stdout writers still do not retain the complete scan.
JSON, JSONL, and CSV keep the finding schema `evidence` field as emitted by checks; they do
not invent extra codes.

## Lifecycle comparison

`garga diff` compares two JSONL finding streams offline. Inputs are bounded to 100,000 unique
stable IDs each and duplicate IDs are rejected. The output is deterministic and supports
`console`, `json`, and `jsonl`.

```sh
garga diff --baseline before.jsonl --current after.jsonl
garga diff --baseline before.jsonl --current after.jsonl --format json --fail-on regressed
```

The lifecycle states are `new`, `resolved`, `unchanged`, `regressed`, and `improved`. Regression
and improvement compare severity first, then CISA KEV status, runtime applicability, and the
bounded priority score. `--fail-on new`, `regressed`, or `any-change` returns exit code `3` only
after writing the comparison.

## Evidence bundles

`garga evidence pack` creates a new deterministic ZIP without overwriting an existing path. Each
artifact is recorded in a sorted SHA-256 manifest; `--signing-key` optionally signs the exact
manifest with Ed25519. Private keys must be owner-only files and may be PKCS#8 PEM, hex, or
base64. `garga evidence verify` rehashes every declared artifact and optionally verifies the
corresponding PKIX PEM, hex, or base64 public key.

```sh
garga evidence pack --file report.pdf --file findings.sarif.json --output assessment.zip
garga evidence verify assessment.zip
garga evidence verify signed-assessment.zip --public-key assessment-public.pem
```

Bundles accept at most 32 regular non-symlink artifacts, 64 MiB per artifact, and 256 MiB total.
Verification rejects path traversal, duplicate and undeclared entries, decompression-size
mismatches, malformed manifests, digest changes, key-ID mismatches, and invalid signatures.
