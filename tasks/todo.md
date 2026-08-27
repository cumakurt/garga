# Highlight exploitable findings in scan listings

## Status

Complete.

## Scope

When findings are listed (console, stderr notice, HTML), emphasize those that
are remotely usable for compromise. Do not claim confirmed exploitation.
Do not add exploit steps, PoCs, or payloads.

## Classifier (conservative)

Highlight as exploitable:

- Anonymous access class `read`, `write`, or `admin` (including inferred).
- Vulnerability advisories whose title/description/references indicate RCE,
  arbitrary code execution, untrusted deserialization, authentication bypass,
  or CISA KEV.

Do not highlight:

- Anonymous metadata, TLS-not-enabled, public-network, security-unconfigured.
- Authenticated DoS / resource consumption CVEs.
- XSS or information-disclosure-only advisories.

## Acceptance

- [x] Console prefixes `EXPLOITABLE`, sorts those first within a target, and
      summarizes `N exploitable`. Honest `note` that this is not a confirmed exploit.
- [x] HTML emphasizes matching rows without scripts or network resources.
- [x] Machine formats add an `exploitable` tag when classified (schema 0.1 additive).
- [x] Golden fixtures for metadata/TLS samples stay unchanged (HTML CSS header only).
- [x] Tests, docs, and changelog updated.

## Review

Classifier lives in `internal/report` so `garga report` of older JSONL still
highlights. Version-only CVE hits stay `potential`; the badge is listing
emphasis, not a confidence upgrade.
