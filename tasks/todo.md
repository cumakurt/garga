# install.sh — install-only bootstrap

## Status

Complete.

## Scope

Rename `run.sh` to `install.sh` and keep the script as an installer: missing build
dependencies, atomic `bin/garga` build, copy to `PREFIX/bin`. Do not exec garga.

## Acceptance

- [x] `install.sh` exists; `run.sh` is removed.
- [x] Extra arguments and former launcher flags (`version`, `--setup-only`) are rejected.
- [x] `--help` prints installer usage only.
- [x] `DESTDIR`/`PREFIX` copy is unit-tested when `bin/garga` exists.
- [x] Docs, changelog, Makefile `shell-test` updated.

## Review

`./install.sh` prepares `bin/garga` and copies it to `${DESTDIR}${PREFIX}/bin/garga`. After
install, operators run `garga --help` or `garga version` themselves.
