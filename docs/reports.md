# Reports

WP 8.1 adds streaming reporters for console, JSON, JSONL, CSV, and standalone HTML. Reporters
consume `model.Finding` values and do not import the scanner. Machine formats use finding schema
`0.1`. That is a pre-release document shape and is not the public `1.0` contract in
[ADR 0003](adr/0003-output-versioning.md).

`garga scan`, `garga vuln`, and `garga report` share these writers. Scan and vuln stream findings
as they are produced.

## CLI

```sh
garga report [--format console|json|jsonl|csv|html] [--input FILE] [--config FILE]
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
| `console` | Human-oriented, grouped by target. Exploitable findings are listed first, then severity. Color is used on a terminal unless `NO_COLOR` is set. Every finding prints visual evidence lines (`code — summary`). It is not a machine schema. |

Deterministic machine formats emit findings in write order. Console buffers until `Close` and
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
`summary`), `remediation`, `references`, `first_seen`, `tags`, `resource`.

CSV columns:

`schema_version`, `id`, `check_id`, `title`, `severity`, `confidence`, `product`, `version`,
`target`, `resource`, `cve`, `cvss`, `description`, `tags`, `evidence`, `remediation`.

When the selected format is not `console`, `garga scan`, `garga vuln`, and `garga report` also
print a grouped human summary of the same findings on stderr so operators can see detected
conditions without opening the machine file.

`garga scan` additionally writes a timestamped standalone HTML assessment (`garga-scan-*.html`)
to the current directory. That artifact is not the streaming `--format html` table: it is a
health-themed report with an executive summary and per-finding cause, impact, cost,
remediation, and a visual **Observed evidence** panel that is always rendered for every finding
(native check evidence plus observed target, transport, and product facts). Machine stdout
writers still do not retain the complete scan. JSON, JSONL, and CSV keep the finding schema
`evidence` field as emitted by checks; they do not invent extra codes.
