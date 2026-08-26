# ADR 0004: Repository identity and license

- Status: Accepted
- Date: 2026-08-26

## Context

The bootstrap used a temporary local Go module and had no redistribution terms. Public releases,
dependency metadata, contribution terms, and security links require canonical identities.

## Decision

The canonical repository and Go module path is `github.com/cumakurt/garga`.

garga is licensed under `AGPL-3.0-only`. Contributions are accepted under the same license. The
complete license text is stored in the repository root as `LICENSE`; package metadata and release
archives must use the SPDX identifier `AGPL-3.0-only`.

## Consequences

All internal imports and release metadata use the canonical module path. Downstream
redistributors and modified network-accessible deployments must comply with the AGPL. A future
module-path or license change is a public-contract change and requires a superseding ADR plus
maintainer approval.
