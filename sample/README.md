# Example PDF reports

These files are **sample outputs** from authorized Docker Elasticsearch 8.19.20
demos. Scan samples come from an anonymous (security-disabled) node. Health,
assessment, and secrets samples come from a security-enabled node. They are not
production assessments.

Regenerate them with `scripts/docker-feature-demo.sh` after `make build`. The
script copies the latest timestamped PDFs from the demo working directory.

| File | Command | Contents |
|---|---|---|
| [garga-scan-sample.pdf](garga-scan-sample.pdf) | `garga scan` | Anonymous GET-only scan with an EXPLOITABLE unauthenticated-admin finding |
| [garga-health-sample.pdf](garga-health-sample.pdf) | `garga health` | Authenticated cluster health assessment |
| [garga-assessment-sample.pdf](garga-assessment-sample.pdf) | `garga assess` | Authenticated security assessment with CVE applicability |
| [garga-secrets-sample.pdf](garga-secrets-sample.pdf) | `garga secrets` | Sensitive-data findings from synthetic fixtures |

## Secrets sample privacy

`garga-secrets-sample.pdf` contains masked findings from `garga secrets generate`
fixtures (`garga-sensitive-test`, 49 synthetic documents). The demo index is built
to exercise every detector family (cloud keys, developer tokens, private keys,
connection strings, hashes, nested objects, and more).

Console, JSON, JSONL, table, SARIF, and PDF all use the same canonical masked
findings. Treat reports as confidential because index names, document IDs, field
paths, and cluster metadata may still be sensitive.
