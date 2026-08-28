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

## Secrets sample warning

`garga-secrets-sample.pdf` includes recovered values from `garga secrets generate`
fixtures (`garga-sensitive-test`, 47 synthetic documents). The demo index is built
to exercise every detector family (cloud keys, developer tokens, private keys,
connection strings, hashes, nested objects, and more). Those values are **fake**
(`fake-password-garga-test-ONLY`, AWS example-style keys, and similar). They are
not production credentials.

Console, JSON, JSONL, table, and SARIF output remain masked. The PDF is the only
artifact that includes recovered secret values (except private keys and password
hashes, which stay type-only). Treat any real `garga-secrets-*.pdf` as confidential.
