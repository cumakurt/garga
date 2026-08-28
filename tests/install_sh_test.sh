#!/usr/bin/env bash

set -Eeuo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

# PROJECT_ROOT is resolved at runtime so the test works from any working directory.
# shellcheck disable=SC1091
source "${PROJECT_ROOT}/install.sh"

assert_supported() {
	local installed="$1"
	local required="$2"
	if ! go_version_is_supported "${installed}" "${required}"; then
		printf 'expected %s to satisfy %s\n' "${installed}" "${required}" >&2
		exit 1
	fi
}

assert_unsupported() {
	local installed="$1"
	local required="$2"
	if go_version_is_supported "${installed}" "${required}"; then
		printf 'expected %s not to satisfy %s\n' "${installed}" "${required}" >&2
		exit 1
	fi
}

assert_supported "go1.26.6" "1.26.6"
assert_supported "go1.26.9" "1.26.6"
assert_supported "go1.27.0" "1.26.6"
assert_supported "go2.0.0" "1.26.6"
assert_supported "go1.27rc1" "1.26.6"

assert_unsupported "go1.25.9" "1.26.6"
assert_unsupported "go1.26.5" "1.26.6"
assert_unsupported "go1.26rc1" "1.26.6"
assert_unsupported "go1.26beta2" "1.26.6"
assert_unsupported "devel go1.27" "1.26.6"
assert_unsupported "unknown" "1.26.6"

FORCE_REBUILD=0
SHOW_HELP=0
PREFIX="/usr/local"
parse_arguments --rebuild --prefix /opt/garga --help
if ((FORCE_REBUILD != 1)); then
	printf 'expected --rebuild to set FORCE_REBUILD\n' >&2
	exit 1
fi
if ((SHOW_HELP != 1)); then
	printf 'expected --help to set SHOW_HELP\n' >&2
	exit 1
fi
if [[ "${PREFIX}" != "/opt/garga" ]]; then
	printf 'expected --prefix to set PREFIX to /opt/garga, got %s\n' "${PREFIX}" >&2
	exit 1
fi

FORCE_REBUILD=0
SHOW_HELP=0
PREFIX="/usr/local"
parse_arguments --prefix=/usr
if [[ "${PREFIX}" != "/usr" ]]; then
	printf 'expected --prefix= to set PREFIX to /usr, got %s\n' "${PREFIX}" >&2
	exit 1
fi

if (parse_arguments version) 2>/dev/null; then
	printf 'expected parse_arguments to reject garga commands\n' >&2
	exit 1
fi

if (parse_arguments --setup-only) 2>/dev/null; then
	printf 'expected parse_arguments to reject --setup-only\n' >&2
	exit 1
fi

if (parse_arguments --prefix) 2>/dev/null; then
	printf 'expected parse_arguments to reject a missing --prefix value\n' >&2
	exit 1
fi

help_output="$("${PROJECT_ROOT}/install.sh" --help)"
if [[ "${help_output}" != *'This script does not run garga commands.'* ]]; then
	printf 'expected installer help to state that it does not run garga commands\n' >&2
	exit 1
fi
if [[ "${help_output}" == *'[INFO]'* ]]; then
	printf 'expected --help to print usage only\n' >&2
	exit 1
fi

if [[ -x "${BINARY_PATH}" ]]; then
	DESTDIR="$(mktemp -d "${TMPDIR:-/tmp}/garga-install-test.XXXXXX")"
	PREFIX="/usr/local"
	install_prepared_binary >/dev/null
	installed="${DESTDIR}/usr/local/bin/garga"
	if [[ ! -x "${installed}" ]]; then
		printf 'expected install_prepared_binary to write %s\n' "${installed}" >&2
		rm -rf -- "${DESTDIR}"
		exit 1
	fi
	rm -rf -- "${DESTDIR}"
	DESTDIR=""
	PREFIX="/usr/local"
fi

printf 'install.sh unit checks passed\n'
