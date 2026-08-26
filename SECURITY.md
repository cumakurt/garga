# Security Policy

## Authorized use

garga is intended for defensive security testing of systems you own or are explicitly authorized
to assess. Users are responsible for defining scope, obtaining permission, and complying with all
applicable laws and organizational policies.

The project must remain safe by default. A normal scan must not exploit vulnerabilities, change
cluster state, modify data, or perform credential spraying. Credential audit is isolated as
`garga auth-audit`: it is explicit, rate-limited, attempt-limited, cancellable, and redacted.

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

- Review `run.sh` before first use because automatic setup may invoke the detected system package
  manager with administrative privileges. The launcher reports the packages first and never uses
  a remote shell installer.
- Start with a small, explicitly authorized target set.
- Review concurrency, rate, timeout, proxy, and TLS settings before scanning.
- Treat scan artifacts as sensitive because they may describe exposed services.
- Prefer secret input through standard input. `garga auth-check` accepts `--password-stdin` and
  `--api-key-stdin`. `garga auth-audit` accepts `--credentials-stdin`. Neither command provides a
  `--password` flag; command-line passwords may be visible in process listings.
- Stop and investigate if observed traffic differs from the documented non-destructive behavior.

## Supported versions

The project is pre-release. Until the first tagged binary, only `main` is assessed for security
fixes. After tags exist, this section will list supported versions and disclosure timelines.
See [docs/release.md](docs/release.md) for artifact verification and rollback.
