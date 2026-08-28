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

assert_can_download() {
	local installed="$1"
	if ! go_can_download_toolchain "${installed}"; then
		printf 'expected %s to be able to download a newer toolchain\n' "${installed}" >&2
		exit 1
	fi
}

assert_cannot_download() {
	local installed="$1"
	if go_can_download_toolchain "${installed}"; then
		printf 'expected %s not to be able to download a newer toolchain\n' "${installed}" >&2
		exit 1
	fi
}

assert_can_download "go1.21.0"
assert_can_download "go1.26.5"
assert_can_download "go1.27.0"
assert_cannot_download "go1.20.14"
assert_cannot_download "go1.21rc1"
assert_cannot_download "unknown"

if [[ "$(normalize_go_os Linux)" != "linux" || "$(normalize_go_arch x86_64)" != "amd64" ]]; then
	printf 'expected Linux/x86_64 to map to linux/amd64\n' >&2
	exit 1
fi
if [[ "$(normalize_go_arch aarch64)" != "arm64" || "$(normalize_go_arch armv7l)" != "armv6l" ]]; then
	printf 'expected aarch64/armv7l to map to arm64/armv6l\n' >&2
	exit 1
fi
if [[ "$(normalize_go_arch riscv64)" != "riscv64" || "$(normalize_go_arch loongarch64)" != "loong64" ]]; then
	printf 'expected riscv64/loongarch64 mappings\n' >&2
	exit 1
fi
if normalize_go_arch sparc64 >/dev/null; then
	printf 'expected sparc64 to be unsupported\n' >&2
	exit 1
fi
if [[ "$(go_archive_filename 1.26.6 linux amd64)" != "go1.26.6.linux-amd64.tar.gz" ]]; then
	printf 'expected official linux-amd64 archive name\n' >&2
	exit 1
fi

if ! go_version_report_is_gccgo "go version go1.18.1 gccgo (GCC) 12.2.0 linux/amd64"; then
	printf 'expected gccgo version report to be detected\n' >&2
	exit 1
fi
if go_version_report_is_gccgo "go version go1.26.5 linux/amd64"; then
	printf 'expected official go version report not to be gccgo\n' >&2
	exit 1
fi

catalog="$(mktemp "${TMPDIR:-/tmp}/garga-go-catalog.XXXXXX")"
cat >"${catalog}" <<'EOF'
[{"version":"go1.26.6","files":[{"filename":"go1.26.6.linux-amd64.tar.gz","os":"linux","arch":"amd64","sha256":"AaBbCcDd0123","kind":"archive"}]}]
EOF
digest="$(go_archive_sha256 "${catalog}" "go1.26.6.linux-amd64.tar.gz")"
rm -f -- "${catalog}"
if [[ "${digest}" != "AaBbCcDd0123" ]]; then
	printf 'expected catalog SHA-256 AaBbCcDd0123, got %s\n' "${digest}" >&2
	exit 1
fi
if ! checksums_match "AABBCCDD0123" "AaBbCcDd0123"; then
	printf 'expected checksum comparison to be case-insensitive\n' >&2
	exit 1
fi

REQUIRED_GO_VERSION="1.26.6"
GARGA_GO_CACHE="/tmp/garga-go-cache"
if [[ "$(official_go_root)" != "/tmp/garga-go-cache" ]]; then
	printf 'expected GARGA_GO_CACHE to set the toolchain root\n' >&2
	exit 1
fi
unset GARGA_GO_CACHE

local_go_version() {
	printf '%s\n' "${MOCK_GO_VERSION}"
}
go_is_gccgo() {
	return 1
}

MOCK_GO_VERSION="go1.26.6"
if ! select_go_toolchain || ((USE_LOCAL_TOOLCHAIN != 1)); then
	printf 'expected go1.26.6 to use the local toolchain\n' >&2
	exit 1
fi

MOCK_GO_VERSION="go1.26.5"
if ! select_go_toolchain || ((USE_LOCAL_TOOLCHAIN != 0)); then
	printf 'expected go1.26.5 to download toolchain 1.26.6\n' >&2
	exit 1
fi

MOCK_GO_VERSION="go1.20.14"
if select_go_toolchain; then
	printf 'expected go1.20.14 not to satisfy or download toolchain 1.26.6\n' >&2
	exit 1
fi
if ((USE_LOCAL_TOOLCHAIN != 0)); then
	printf 'expected go1.20.14 not to select the local toolchain\n' >&2
	exit 1
fi

go_is_gccgo() {
	return 0
}
MOCK_GO_VERSION="go1.27.0"
if select_go_toolchain; then
	printf 'expected gccgo to be rejected even when GOVERSION looks new\n' >&2
	exit 1
fi
go_is_gccgo() {
	return 1
}

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
if [[ "${help_output}" != *'GARGA_GO_CACHE'* ]]; then
	printf 'expected installer help to document GARGA_GO_CACHE\n' >&2
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
