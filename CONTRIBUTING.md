# Contributing to garga

Thank you for helping improve garga. Changes must preserve its authorized-use and safe-by-default
boundaries. Do not submit exploit payloads, destructive checks, real credentials, customer data,
or production target details.

## Before opening a change

- Use a public issue for ordinary bugs and proposals.
- Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
- Keep one change focused on one problem and search for an existing implementation pattern first.
- Discuss changes to CLI contracts, configuration, output schemas, safety policy, or package
  boundaries before implementation.

## Development setup

Install Go 1.26 or later, clone the repository, and run:

```sh
./run.sh --setup-only
make check
make test-race
```

The equivalent individual validation commands are:

```sh
make fmt-check
bash -n run.sh tests/run_sh_test.sh
bash tests/run_sh_test.sh
go vet ./...
go test ./...
go test -race ./...
go test -run='^$' -bench=. -benchmem ./internal/target ./internal/fingerprint ./internal/vulnerability ./internal/report ./internal/scanner
go build ./...
go mod tidy -diff
shellcheck run.sh tests/run_sh_test.sh
make fuzz-smoke
make release VERSION=v0.0.0-test
```

`shellcheck` is required for launcher changes. `make bench` is opt-in: timings are machine-specific
and are recorded in [docs/performance.md](docs/performance.md). `make integration` is opt-in:
it requires Docker, may pull Elasticsearch images, and is documented in
[docs/integration.md](docs/integration.md). `make vulncheck` downloads the Go vulnerability
database and is required before a tagged release. Longer fuzz campaigns remain opt-in and must be
documented in the pull request when applicable.

## Engineering expectations

- Write source code, identifiers, comments, logs, errors, tests, and technical documentation in
  English.
- Add behavior-focused tests for normal, boundary, invalid-input, and error paths.
- Keep network operations bounded and cancellable; use explicit timeouts.
- Never log, serialize, or echo credentials, authorization headers, or sensitive payloads.
- Reuse configured formatters, linters, task targets, and existing architectural patterns.
- Add a dependency only when the standard library and current dependencies are insufficient.
- Update user documentation and ADRs when behavior or contracts change.

Review the final diff for unrelated edits, generated artifacts, debug code, secrets, stale
documentation, and vague TODOs.

## Contribution license

By submitting a contribution, you agree that it is licensed under the repository's
`AGPL-3.0-only` license and that you have the right to provide it under those terms.
