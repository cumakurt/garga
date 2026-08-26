#!/usr/bin/env bash

set -Eeuo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

# PROJECT_ROOT is resolved at runtime so the test works from any working directory.
# shellcheck disable=SC1091
source "${PROJECT_ROOT}/run.sh"

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

assert_supported "go1.26.0" "1.26.0"
assert_supported "go1.26.5" "1.26.0"
assert_supported "go1.27.0" "1.26.0"
assert_supported "go2.0.0" "1.26.0"
assert_supported "go1.27rc1" "1.26.0"

assert_unsupported "go1.25.9" "1.26.0"
assert_unsupported "go1.26rc1" "1.26.0"
assert_unsupported "go1.26beta2" "1.26.0"
assert_unsupported "devel go1.27" "1.26.0"
assert_unsupported "unknown" "1.26.0"

printf 'run.sh unit checks passed\n'
