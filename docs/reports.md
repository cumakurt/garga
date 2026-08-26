# Reports

WP 8.1 adds streaming reporters for console, JSON, JSONL, CSV, and standalone HTML. Reporters
consume `model.Finding` values and do not import the scanner. Machine formats use finding schema
`0.1`. That is a pre-release document shape and is not the public `1.0` contract in
[ADR 0003](adr/0003-output-versioning.md).

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
| `csv` | A header row plus one row per finding. Formula-like cells are prefixed with `'`. |
| `html` | A standalone document with inline CSS. All text is HTML-escaped. There are no scripts, links, images, or other network resources. |
| `console` | Human-oriented text. It is not a machine schema. |

Deterministic formats emit findings in write order. Callers that need stable grouping should
deduplicate first. Empty schema versions are set to `0.1` on write.

## JSON fields

Stable finding field names:

`schema_version`, `id`, `check_id`, `title`, `description`, `target` (`scheme`, `host`, `port`,
`path`), `product`, `version`, `severity`, `confidence`, `cvss`, `cve`, `evidence` (`code`,
`summary`), `remediation`, `references`, `first_seen`, `tags`, `resource`.

CSV columns:

`schema_version`, `id`, `check_id`, `title`, `severity`, `confidence`, `product`, `version`,
`target`, `resource`, `cve`, `tags`, `evidence`, `remediation`.
