# Security Policy

## Authorized use

garga is intended for defensive security testing of systems you own or are explicitly authorized
to assess. Users are responsible for defining scope, obtaining permission, and complying with all
applicable laws and organizational policies.

The project must remain safe by default. A normal scan must not exploit vulnerabilities, change
cluster state, modify data, or perform credential spraying. Credential audit is isolated as
`garga auth-audit`: it is explicit, rate-limited, attempt-limited, cancellable, and redacted.
Technique-specific username and password detection is isolated as `garga auth-detect` with the
same GET-only authenticate contract and additional attempt ceilings. Sensitive-data discovery is
isolated as `garga secrets`: it samples documents through allowlisted GET APIs and
`POST /_search` only, never writes cluster state, and masks secrets in default reports.

## Reporting a vulnerability

Do not disclose a suspected vulnerability in a public issue. Use the repository's
[private security advisory form](https://github.com/cumakurt/garga/security/advisories/new). If
the form is unavailable, contact the release maintainer privately before sharing reproduction
details.

Include:

- the affected version or commit;
- the security impact and required preconditions;
- minimal reproduction steps;
- whether credentials or sensitive target data are involved;
- any suggested mitigation.

Never include real credentials, access tokens, customer data, or production target details in a
report or test fixture.

## Operational precautions

- Review `install.sh` before first use because automatic setup may invoke the detected system
  package manager with administrative privileges for Git, curl, and CA certificates. The
  installer reports those packages first and never uses a remote shell installer. When the
  system Go compiler is missing or unusable it downloads an official archive from `go.dev` and
  verifies the SHA-256 digest before extracting it. It does not run garga after copying the
  binary onto PATH.
- Start with a small, explicitly authorized target set.
- Review concurrency, rate, timeout, proxy, and TLS settings before scanning.
- Treat scan artifacts as sensitive because they may describe exposed services.
- Prefer secret input through standard input or a local list file whose contents are not logged.
  `garga auth-check` accepts `--password-stdin` and `--api-key-stdin`. `garga auth-audit` accepts
  `--credentials-stdin`. `garga auth-detect` accepts stdin or `--credentials-file` / `--wordlist`
  / `--users-file` / `--passwords-file`. `garga secrets` reads credentials from environment
  variables named by `--password-env`, `--api-key-env`, or `--bearer-token-env`. None of these
  commands provides a `--password` flag; command-line passwords may be visible in process listings.
- Stop and investigate if observed traffic differs from the documented non-destructive behavior.

## Supported versions

| Version | Security fixes |
|---|---|
| v0.1.x | Yes |
| unreleased `main` | Yes, until the next tag |

See [docs/release.md](docs/release.md) for artifact verification and rollback.
