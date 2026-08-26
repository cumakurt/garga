# Release ownership

The repository owner and initial release maintainer is Cuma Kurt (`@cumakurt`). The release
maintainer owns final approval of public contracts, signing identity, repository secrets, release
publication, emergency withdrawal, and security-advisory coordination.

## Release responsibilities

The release maintainer must:

1. confirm every release gate in the master plan from a clean checkout;
2. review dependency and vulnerability scan results;
3. approve CLI, configuration, schema, signature trust-root, and supported-version metadata;
4. verify version injection, archives, checksums, SBOMs, signatures, and release notes;
5. publish artifacts through the canonical `github.com/cumakurt/garga` repository;
6. retain the previous known-good binary and signature database for rollback.

No contributor may publish an official artifact or use release credentials without explicit
authorization from the release maintainer. If ownership changes, this document, CODEOWNERS,
security contacts, and signing-key documentation must change together.
