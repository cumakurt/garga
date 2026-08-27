# Color and group garga health console output

## Status

Complete.

## Scope

Make `garga health` terminal/console reports colored, severity-leveled, grouped, and
aligned — without changing JSON, HTML, or Markdown contracts.

## Acceptance

- [x] TTY color with `NO_COLOR` / dumb TERM / non-TTY disabled
- [x] Findings grouped by severity, then category
- [x] Colored score, counts, top risks, actions, and coverage
- [x] Tests, docs, changelog
- [x] Existing redaction and format tests still pass

## Review

Terminal output now matches the scan console vocabulary: cyan section headers, gray rules,
padded severity labels, and aligned `check` / `resource` / `evidence` fields. Findings are
grouped `SEVERITY · Category (n)`. JSON/HTML/Markdown writers were not changed.
