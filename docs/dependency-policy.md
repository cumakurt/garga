# Dependency update policy

garga minimizes runtime dependencies because every dependency expands the build and security
review surface.

## Adding a dependency

A pull request that adds a direct dependency must explain why the Go standard library and current
modules are insufficient, identify the maintained upstream, review its license, and describe its
runtime and supply-chain impact. Dependencies used only by tests or tooling must remain outside
the runtime graph where Go tooling permits it.

Direct Go modules are declared explicitly in `go.mod`; `go.sum` is committed. Unrelated upgrades
and lock-file churn are not accepted. GitHub Actions maintained by GitHub may use reviewed major
version tags; third-party actions must use immutable commit SHAs.

## Update cadence

Dependabot checks Go modules and GitHub Actions weekly. Routine compatible updates are grouped by
ecosystem. Security updates are handled as soon as impact is understood and are never delayed for
the routine batch.

Every update must pass:

```sh
go mod tidy -diff
go mod verify
make check
make test-race
make lint
```

Run `govulncheck ./...` (or `make vulncheck`) for release candidates, pull-request CI, and for
changes responding to a Go vulnerability. Review transitive graph, license, release notes, and
behavior changes before merging. Major updates require an explicit migration note. A dependency
is removed when its functionality is no longer used.
