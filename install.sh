#!/usr/bin/env bash

set -Eeuo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BINARY_PATH="${PROJECT_ROOT}/bin/garga"
GO_MOD_PATH="${PROJECT_ROOT}/go.mod"
GO_SUM_PATH="${PROJECT_ROOT}/go.sum"

OS_KIND="unknown"
OS_NAME="Unknown operating system"
REQUIRED_GO_VERSION=""
INSTALLED_GO_VERSION=""
NEED_GO=0
NEED_GIT=0
USE_LOCAL_TOOLCHAIN=1
FORCE_REBUILD=0
SHOW_HELP=0
TEMP_BINARY=""
GO_FETCH_DIR=""
PREFIX="${PREFIX:-/usr/local}"
DESTDIR="${DESTDIR:-}"
# Go 1.21 introduced GOTOOLCHAIN=auto, which can download the compiler named in go.mod.
MIN_TOOLCHAIN_DOWNLOAD_GO_VERSION="1.21.0"
GO_DOWNLOAD_CATALOG_URL="https://go.dev/dl/?mode=json&include=all"
GO_DOWNLOAD_FILE_BASE_URL="https://go.dev/dl"

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
	COLOR_BLUE=$'\033[34m'
	COLOR_GREEN=$'\033[32m'
	COLOR_YELLOW=$'\033[33m'
	COLOR_RED=$'\033[31m'
	COLOR_RESET=$'\033[0m'
else
	COLOR_BLUE=""
	COLOR_GREEN=""
	COLOR_YELLOW=""
	COLOR_RED=""
	COLOR_RESET=""
fi

info() {
	printf '%s[INFO]%s %s\n' "${COLOR_BLUE}" "${COLOR_RESET}" "$*"
}

success() {
	printf '%s[OK]%s %s\n' "${COLOR_GREEN}" "${COLOR_RESET}" "$*"
}

warn() {
	printf '%s[WARN]%s %s\n' "${COLOR_YELLOW}" "${COLOR_RESET}" "$*" >&2
}

fail() {
	printf '%s[ERROR]%s %s\n' "${COLOR_RED}" "${COLOR_RESET}" "$*" >&2
	exit 1
}

cleanup() {
	if [[ -n "${TEMP_BINARY}" && -e "${TEMP_BINARY}" ]]; then
		rm -f -- "${TEMP_BINARY}"
	fi
	if [[ -n "${GO_FETCH_DIR}" && -d "${GO_FETCH_DIR}" ]]; then
		rm -rf -- "${GO_FETCH_DIR}"
	fi
}

trap cleanup EXIT INT TERM

show_install_help() {
	cat <<'EOF'
Usage:
  ./install.sh [options]

Install missing build dependencies, build garga, and copy the binary to
PREFIX/bin (default /usr/local/bin) so the garga command is on PATH.

Options:
  -h, --help         Show this installer help.
  --rebuild          Rebuild even when the existing binary is current.
  --prefix DIR       Install into DIR/bin instead of /usr/local/bin.

Environment:
  PREFIX             Same as --prefix (default /usr/local).
  DESTDIR            Optional staging root prepended to PREFIX.
  GARGA_GO_CACHE     Directory for a downloaded official Go toolchain.

This script does not run garga commands. After installation, use:
  garga --help
  garga version
EOF
}

parse_arguments() {
	while (($# > 0)); do
		case "$1" in
		-h | --help)
			SHOW_HELP=1
			shift
			;;
		--rebuild)
			FORCE_REBUILD=1
			shift
			;;
		--prefix)
			if (($# < 2)) || [[ -z "${2:-}" ]]; then
				fail "--prefix requires a directory."
			fi
			PREFIX="$2"
			shift 2
			;;
		--prefix=*)
			PREFIX="${1#--prefix=}"
			if [[ -z "${PREFIX}" ]]; then
				fail "--prefix requires a directory."
			fi
			shift
			;;
		*)
			fail "unexpected argument '$1'. This installer does not run garga commands. Use './install.sh --help'."
			;;
		esac
	done
}

detect_operating_system() {
	local kernel
	kernel="$(uname -s 2>/dev/null || true)"

	case "${kernel}" in
	Linux)
		OS_KIND="linux"
		OS_NAME="Linux"
		if [[ -r /etc/os-release ]]; then
			local key value
			while IFS='=' read -r key value; do
				if [[ "${key}" == "PRETTY_NAME" ]]; then
					value="${value#\"}"
					value="${value%\"}"
					OS_NAME="${value}"
					break
				fi
			done </etc/os-release
		fi
		;;
	Darwin)
		OS_KIND="macos"
		OS_NAME="macOS"
		;;
	FreeBSD)
		OS_KIND="freebsd"
		OS_NAME="FreeBSD"
		;;
	OpenBSD)
		OS_KIND="openbsd"
		OS_NAME="OpenBSD"
		;;
	NetBSD)
		OS_KIND="netbsd"
		OS_NAME="NetBSD"
		;;
	MINGW* | MSYS* | CYGWIN*)
		OS_KIND="windows"
		OS_NAME="Windows compatibility shell"
		;;
	*)
		OS_KIND="unknown"
		OS_NAME="${kernel:-Unknown operating system}"
		;;
	esac
}

read_required_go_version() {
	local directive version _
	while read -r directive version _; do
		if [[ "${directive}" == "go" && -n "${version:-}" ]]; then
			REQUIRED_GO_VERSION="${version}"
			return
		fi
	done <"${GO_MOD_PATH}"

	fail "Unable to read the required Go version from ${GO_MOD_PATH}. Restore a valid go.mod file and rerun ./install.sh."
}

go_version_is_supported() {
	local current="$1"
	local required="$2"
	local current_major current_minor current_patch
	local current_suffix
	local required_major required_minor required_patch

	if [[ ! "${current}" =~ ^go([0-9]+)\.([0-9]+)(\.([0-9]+))?([^0-9].*)?$ ]]; then
		return 1
	fi
	current_major="${BASH_REMATCH[1]}"
	current_minor="${BASH_REMATCH[2]}"
	current_patch="${BASH_REMATCH[4]:-0}"
	current_suffix="${BASH_REMATCH[5]:-}"

	if [[ ! "${required}" =~ ^([0-9]+)\.([0-9]+)(\.([0-9]+))? ]]; then
		return 1
	fi
	required_major="${BASH_REMATCH[1]}"
	required_minor="${BASH_REMATCH[2]}"
	required_patch="${BASH_REMATCH[4]:-0}"

	if ((current_major != required_major)); then
		((current_major > required_major))
		return
	fi
	if ((current_minor != required_minor)); then
		((current_minor > required_minor))
		return
	fi
	if [[ -n "${current_suffix}" ]]; then
		return 1
	fi
	((current_patch >= required_patch))
}

local_go_version() {
	GOTOOLCHAIN=local go env GOVERSION 2>/dev/null || true
}

go_is_gccgo() {
	local report
	report="$(go version 2>/dev/null || true)"
	go_version_report_is_gccgo "${report}"
}

go_version_report_is_gccgo() {
	[[ "$1" == *gccgo* ]]
}

# Distro packages often trail go.mod by a patch. Official Go 1.21+ can fetch the
# matching toolchain. gccgo cannot.
go_can_download_toolchain() {
	go_version_is_supported "$1" "${MIN_TOOLCHAIN_DOWNLOAD_GO_VERSION}"
}

select_go_toolchain() {
	USE_LOCAL_TOOLCHAIN=0
	INSTALLED_GO_VERSION="$(local_go_version)"
	if go_is_gccgo; then
		return 1
	fi
	if go_version_is_supported "${INSTALLED_GO_VERSION}" "${REQUIRED_GO_VERSION}"; then
		USE_LOCAL_TOOLCHAIN=1
		return 0
	fi
	if go_can_download_toolchain "${INSTALLED_GO_VERSION}"; then
		return 0
	fi
	return 1
}

system_go_is_usable() {
	command -v go >/dev/null 2>&1 && select_go_toolchain
}

normalize_go_os() {
	case "$1" in
	Linux | linux)
		printf 'linux\n'
		;;
	Darwin | darwin)
		printf 'darwin\n'
		;;
	FreeBSD | freebsd)
		printf 'freebsd\n'
		;;
	OpenBSD | openbsd)
		printf 'openbsd\n'
		;;
	NetBSD | netbsd)
		printf 'netbsd\n'
		;;
	*)
		return 1
		;;
	esac
}

normalize_go_arch() {
	case "$1" in
	x86_64 | amd64)
		printf 'amd64\n'
		;;
	aarch64 | arm64)
		printf 'arm64\n'
		;;
	armv7l | armv6l | arm)
		printf 'armv6l\n'
		;;
	i386 | i686 | i86pc)
		printf '386\n'
		;;
	ppc64le)
		printf 'ppc64le\n'
		;;
	s390x)
		printf 's390x\n'
		;;
	riscv64)
		printf 'riscv64\n'
		;;
	loongarch64 | loong64)
		printf 'loong64\n'
		;;
	*)
		return 1
		;;
	esac
}

go_archive_filename() {
	printf 'go%s.%s-%s.tar.gz\n' "$1" "$2" "$3"
}

official_go_root() {
	local cache_home
	if [[ -n "${GARGA_GO_CACHE:-}" ]]; then
		printf '%s\n' "${GARGA_GO_CACHE%/}"
		return
	fi
	if [[ -n "${XDG_CACHE_HOME:-}" ]]; then
		cache_home="${XDG_CACHE_HOME}"
	elif [[ -n "${HOME:-}" ]]; then
		cache_home="${HOME}/.cache"
	else
		cache_home="${PROJECT_ROOT}/.cache"
	fi
	printf '%s\n' "${cache_home%/}/garga/go/go${REQUIRED_GO_VERSION}"
}

have_downloader() {
	command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || command -v fetch >/dev/null 2>&1
}

download_url() {
	local url="$1"
	local dest="$2"

	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --connect-timeout 30 --max-time 600 --retry 2 --retry-delay 2 -o "${dest}" "${url}"
		return
	fi
	if command -v wget >/dev/null 2>&1; then
		wget -q -T 30 -t 3 -O "${dest}" "${url}"
		return
	fi
	if command -v fetch >/dev/null 2>&1; then
		fetch -T 30 -o "${dest}" "${url}"
		return
	fi
	return 1
}

install_brew_packages() {
	local brew_packages=()
	local pkg
	for pkg in "$@"; do
		if [[ "${pkg}" == "ca-certificates" ]]; then
			continue
		fi
		brew_packages+=("${pkg}")
	done
	if ((${#brew_packages[@]} == 0)); then
		return 0
	fi
	info "Installing missing dependencies with Homebrew: ${brew_packages[*]}"
	brew install "${brew_packages[@]}"
}

file_sha256() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
		return
	fi
	if command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | awk '{print $1}'
		return
	fi
	if command -v openssl >/dev/null 2>&1; then
		openssl dgst -sha256 "$1" | awk '{print $NF}'
		return
	fi
	return 1
}

go_archive_sha256() {
	local catalog="$1"
	local filename="$2"
	local digest

	digest="$(awk -v want="${filename}" '
		/"filename"/ {
			name = $0
			sub(/.*"filename":[[:space:]]*"/, "", name)
			sub(/".*/, "", name)
			keep = (name == want)
		}
		keep && /"sha256"/ {
			sha = $0
			sub(/.*"sha256":[[:space:]]*"/, "", sha)
			sub(/".*/, "", sha)
			print sha
			exit
		}
	' "${catalog}")"
	if [[ -z "${digest}" ]]; then
		return 1
	fi
	printf '%s\n' "${digest}"
}

checksums_match() {
	local actual="$1"
	local expected="$2"
	local actual_lc expected_lc
	actual_lc="$(printf '%s' "${actual}" | tr '[:upper:]' '[:lower:]')"
	expected_lc="$(printf '%s' "${expected}" | tr '[:upper:]' '[:lower:]')"
	[[ -n "${actual_lc}" && "${actual_lc}" == "${expected_lc}" ]]
}

binary_is_current() {
	if [[ ! -x "${BINARY_PATH}" ]]; then
		return 1
	fi
	if ! "${BINARY_PATH}" version >/dev/null 2>&1; then
		return 1
	fi
	if [[ "${GO_MOD_PATH}" -nt "${BINARY_PATH}" || "${GO_SUM_PATH}" -nt "${BINARY_PATH}" ]]; then
		return 1
	fi

	local newer_source=""
	local file
	# Avoid GNU find -quit so busybox/Alpine find works. Process substitution keeps
	# SIGPIPE from find | head from aborting the script under pipefail.
	while IFS= read -r file; do
		newer_source="${file}"
		break
	done < <(find "${PROJECT_ROOT}/cmd" "${PROJECT_ROOT}/internal" -type f -name '*.go' -newer "${BINARY_PATH}" -print 2>/dev/null)
	[[ -z "${newer_source}" ]]
}

check_build_dependencies() {
	NEED_GO=0
	NEED_GIT=0
	USE_LOCAL_TOOLCHAIN=1

	if ! command -v go >/dev/null 2>&1; then
		NEED_GO=1
		USE_LOCAL_TOOLCHAIN=0
		warn "Go is not installed. Go ${REQUIRED_GO_VERSION} or newer is required to build garga."
	elif go_is_gccgo; then
		NEED_GO=1
		USE_LOCAL_TOOLCHAIN=0
		INSTALLED_GO_VERSION="$(local_go_version)"
		warn "gccgo is not a supported build compiler. The installer will download official Go ${REQUIRED_GO_VERSION}."
	elif select_go_toolchain; then
		if ((USE_LOCAL_TOOLCHAIN == 0)); then
			warn "Installed ${INSTALLED_GO_VERSION:-Go version unknown} is older than required Go ${REQUIRED_GO_VERSION}."
			info "The system Go will download toolchain ${REQUIRED_GO_VERSION} instead of replacing the distro package."
		fi
	else
		NEED_GO=1
		warn "Installed ${INSTALLED_GO_VERSION:-Go version unknown} is too old to build garga or download Go ${REQUIRED_GO_VERSION}."
		info "The installer will download the official Go ${REQUIRED_GO_VERSION} toolchain from go.dev."
	fi

	if ! command -v git >/dev/null 2>&1; then
		NEED_GIT=1
		warn "Git is not installed. It is optional when GOPROXY can serve modules, and required for direct VCS fetches."
	fi
}

run_as_root() {
	if ((EUID == 0)); then
		"$@"
		return
	fi
	if command -v sudo >/dev/null 2>&1; then
		info "Administrative privileges are required; sudo may prompt for your password."
		sudo "$@"
		return
	fi
	return 1
}

install_listed_packages() {
	local packages=("$@")
	if ((${#packages[@]} == 0)); then
		return 0
	fi

	case "${OS_KIND}" in
	linux)
		if command -v apt-get >/dev/null 2>&1; then
			info "Installing missing dependencies with apt-get: ${packages[*]}"
			run_as_root apt-get update && run_as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}" || return 1
			return 0
		fi
		if command -v dnf >/dev/null 2>&1; then
			info "Installing missing dependencies with dnf: ${packages[*]}"
			run_as_root dnf install -y "${packages[@]}" || return 1
			return 0
		fi
		if command -v microdnf >/dev/null 2>&1; then
			info "Installing missing dependencies with microdnf: ${packages[*]}"
			run_as_root microdnf install -y "${packages[@]}" || return 1
			return 0
		fi
		if command -v yum >/dev/null 2>&1; then
			info "Installing missing dependencies with yum: ${packages[*]}"
			run_as_root yum install -y "${packages[@]}" || return 1
			return 0
		fi
		if command -v tdnf >/dev/null 2>&1; then
			info "Installing missing dependencies with tdnf: ${packages[*]}"
			run_as_root tdnf install -y "${packages[@]}" || return 1
			return 0
		fi
		if command -v pacman >/dev/null 2>&1; then
			info "Installing missing dependencies with pacman: ${packages[*]}"
			run_as_root pacman -S --needed --noconfirm "${packages[@]}" || return 1
			return 0
		fi
		if command -v zypper >/dev/null 2>&1; then
			info "Installing missing dependencies with zypper: ${packages[*]}"
			run_as_root zypper --non-interactive install "${packages[@]}" || return 1
			return 0
		fi
		if command -v apk >/dev/null 2>&1; then
			info "Installing missing dependencies with apk: ${packages[*]}"
			run_as_root apk add "${packages[@]}" || return 1
			return 0
		fi
		if command -v xbps-install >/dev/null 2>&1; then
			info "Installing missing dependencies with xbps-install: ${packages[*]}"
			run_as_root xbps-install -Sy "${packages[@]}" || return 1
			return 0
		fi
		if command -v eopkg >/dev/null 2>&1; then
			info "Installing missing dependencies with eopkg: ${packages[*]}"
			run_as_root eopkg install -y "${packages[@]}" || return 1
			return 0
		fi
		if command -v brew >/dev/null 2>&1; then
			install_brew_packages "${packages[@]}" || return 1
			return 0
		fi
		warn "No supported Linux package manager was found. Continuing without system packages."
		return 0
		;;
	macos)
		if command -v brew >/dev/null 2>&1; then
			install_brew_packages "${packages[@]}" || return 1
			return 0
		fi
		warn "Homebrew is not installed. Continuing without system packages."
		return 0
		;;
	freebsd)
		info "Installing missing dependencies with pkg: ${packages[*]}"
		run_as_root pkg install -y "${packages[@]}" || return 1
		return 0
		;;
	openbsd)
		info "Installing missing dependencies with pkg_add: ${packages[*]}"
		run_as_root pkg_add "${packages[@]}" || return 1
		return 0
		;;
	netbsd)
		if ! command -v pkgin >/dev/null 2>&1; then
			warn "pkgin is not installed. Continuing without system packages."
			return 0
		fi
		info "Installing missing dependencies with pkgin: ${packages[*]}"
		run_as_root pkgin -y install "${packages[@]}" || return 1
		return 0
		;;
	*)
		warn "Automatic package installation is not supported on ${OS_NAME}."
		return 0
		;;
	esac
}

install_system_packages() {
	local packages=()

	if ((NEED_GO)) && ! have_downloader; then
		packages+=(curl)
	fi
	if ((NEED_GIT)); then
		packages+=(git)
	fi
	if ((${#packages[@]} == 0)); then
		return 0
	fi
	# Homebrew and BSD package names differ; native Linux repos use ca-certificates.
	if [[ "${OS_KIND}" == "linux" ]]; then
		packages=(ca-certificates "${packages[@]}")
	fi

	if install_listed_packages "${packages[@]}"; then
		hash -r
		return 0
	fi
	warn "System package installation failed. The installer will continue if a downloader and toolchain are available."
	hash -r
	return 0
}

use_go_root() {
	local root="$1"
	PATH="${root}/bin:${PATH}"
	export PATH
	hash -r
}

install_official_go() {
	local goos goarch filename dest_root catalog archive expected actual kernel machine

	kernel="$(uname -s 2>/dev/null || true)"
	machine="$(uname -m 2>/dev/null || true)"
	goos="$(normalize_go_os "${kernel}")" || fail "No official Go archive is published for kernel ${kernel:-unknown}."
	goarch="$(normalize_go_arch "${machine}")" || fail "No official Go archive is published for architecture ${machine:-unknown}. Install Go >= ${REQUIRED_GO_VERSION} from https://go.dev/dl/ and rerun ./install.sh."
	filename="$(go_archive_filename "${REQUIRED_GO_VERSION}" "${goos}" "${goarch}")"
	dest_root="$(official_go_root)"

	if [[ -x "${dest_root}/bin/go" ]]; then
		use_go_root "${dest_root}"
		if system_go_is_usable; then
			success "Reusing cached Go ${REQUIRED_GO_VERSION} at ${dest_root}."
			return
		fi
	fi

	if ! have_downloader; then
		fail "curl or wget is required to download Go ${REQUIRED_GO_VERSION} from https://go.dev/dl/. Install one of them, then rerun ./install.sh."
	fi

	GO_FETCH_DIR="$(mktemp -d "${TMPDIR:-/tmp}/garga-go.XXXXXX")"
	catalog="${GO_FETCH_DIR}/catalog.json"
	archive="${GO_FETCH_DIR}/${filename}"

	info "Downloading the Go release catalog from go.dev to verify ${filename}."
	if ! download_url "${GO_DOWNLOAD_CATALOG_URL}" "${catalog}"; then
		fail "Could not download the Go release catalog. Check internet access and TLS certificates, then rerun ./install.sh."
	fi
	expected="$(go_archive_sha256 "${catalog}" "${filename}")" || fail "Go ${REQUIRED_GO_VERSION} has no official archive ${filename}. Install Go from https://go.dev/dl/ and rerun ./install.sh."

	info "Downloading official ${filename}. The archive is SHA-256 verified before use."
	if ! download_url "${GO_DOWNLOAD_FILE_BASE_URL}/${filename}" "${archive}"; then
		fail "Could not download ${filename}. Check internet access and TLS certificates, then rerun ./install.sh."
	fi
	actual="$(file_sha256 "${archive}")" || fail "No SHA-256 tool was found (sha256sum, shasum, or openssl)."
	if ! checksums_match "${actual}" "${expected}"; then
		fail "Checksum mismatch for ${filename}. The download was discarded. Rerun ./install.sh."
	fi

	mkdir -p -- "$(dirname -- "${dest_root}")"
	rm -rf -- "${dest_root}.new"
	mkdir -p -- "${dest_root}.new"
	if ! tar -C "${dest_root}.new" -xzf "${archive}"; then
		rm -rf -- "${dest_root}.new"
		fail "Could not extract ${filename}."
	fi
	if [[ ! -x "${dest_root}.new/go/bin/go" ]]; then
		rm -rf -- "${dest_root}.new"
		fail "The downloaded Go archive did not contain bin/go."
	fi
	rm -rf -- "${dest_root}"
	mv -- "${dest_root}.new/go" "${dest_root}"
	rm -rf -- "${dest_root}.new"
	rm -rf -- "${GO_FETCH_DIR}"
	GO_FETCH_DIR=""

	use_go_root "${dest_root}"
	if ! system_go_is_usable; then
		fail "The downloaded Go toolchain at ${dest_root} is not usable."
	fi
	success "Official Go ${REQUIRED_GO_VERSION} is ready at ${dest_root}."
}

install_windows_dependencies() {
	if ! command -v winget.exe >/dev/null 2>&1; then
		fail "No supported Windows package manager was found. Install Go >= ${REQUIRED_GO_VERSION} from https://go.dev/dl/ and Git from https://git-scm.com/download/win, then reopen the shell and rerun ./install.sh."
	fi
	if ((NEED_GO)); then
		info "Installing Go with winget."
		if ! winget.exe install --id GoLang.Go --exact --silent --accept-package-agreements --accept-source-agreements; then
			fail "winget could not install Go. Install Go >= ${REQUIRED_GO_VERSION} from https://go.dev/dl/, reopen the shell, and rerun ./install.sh."
		fi
	fi
	if ((NEED_GIT)); then
		info "Installing Git with winget."
		if ! winget.exe install --id Git.Git --exact --silent --accept-package-agreements --accept-source-agreements; then
			fail "winget could not install Git. Install it from https://git-scm.com/download/win, reopen the shell, and rerun ./install.sh."
		fi
	fi

	for directory in "/c/Program Files/Go/bin" "/c/Program Files/Git/cmd"; do
		if [[ -d "${directory}" ]]; then
			PATH="${directory}:${PATH}"
		fi
	done
	export PATH
}

install_dependencies() {
	if ((NEED_GO == 0 && NEED_GIT == 0)); then
		success "Required build dependencies are already installed."
		return
	fi

	if [[ "${OS_KIND}" == "windows" ]]; then
		install_windows_dependencies
		hash -r
		return
	fi

	install_system_packages
	if ((NEED_GO)); then
		install_official_go
	fi
	hash -r
}

verify_build_dependencies() {
	if ! command -v go >/dev/null 2>&1; then
		fail "Go is still unavailable after installation. Open a new terminal or add the Go bin directory to PATH, then rerun ./install.sh."
	fi
	if ! select_go_toolchain; then
		fail "${INSTALLED_GO_VERSION:-The installed Go version} does not satisfy Go ${REQUIRED_GO_VERSION} and cannot download that toolchain. Upgrade from https://go.dev/dl/, ensure the new go command is on PATH, then rerun ./install.sh."
	fi
	if ! command -v git >/dev/null 2>&1; then
		warn "Git is unavailable. Module downloads will use GOPROXY; direct VCS fetches may fail."
	fi
	success "Build dependencies are ready (${INSTALLED_GO_VERSION}$(command -v git >/dev/null 2>&1 && printf ', %s' "$(git --version)"))."
}

go_build_garga() {
	local output="$1"
	local version commit built_at
	version="$(tr -d ' \n\r\t' <"${PROJECT_ROOT}/VERSION" 2>/dev/null || true)"
	if [[ -z "${version}" ]]; then
		version="dev"
	fi
	commit="none"
	if command -v git >/dev/null 2>&1; then
		commit="$(git -C "${PROJECT_ROOT}" rev-parse HEAD 2>/dev/null || echo none)"
	fi
	built_at="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)"
	CGO_ENABLED=0 go build -trimpath -buildvcs=false \
		-ldflags "-s -w -X main.version=${version} -X main.commit=${commit} -X main.builtAt=${built_at}" \
		-o "${output}" "${PROJECT_ROOT}/cmd/garga"
}

build_application() {
	# Prefer the local compiler when it satisfies go.mod. Distro packages often
	# lag by a patch; official Go 1.21+ can then fetch the matching toolchain.
	# Force auto so a user GOTOOLCHAIN=local cannot block a needed download.
	if ((USE_LOCAL_TOOLCHAIN)); then
		export GOTOOLCHAIN=local
	else
		export GOTOOLCHAIN=auto
		info "Using GOTOOLCHAIN=auto so Go can download toolchain ${REQUIRED_GO_VERSION}."
	fi

	info "Downloading missing Go modules. Cached modules will not be reinstalled."
	if ! go mod download; then
		if ((USE_LOCAL_TOOLCHAIN)); then
			fail "Go module download failed. Check internet access, TLS certificates, and GOPROXY, then rerun ./install.sh."
		fi
		fail "Go module or toolchain download failed. Check internet access, TLS certificates, and GOPROXY, then rerun ./install.sh."
	fi
	if ! go mod verify; then
		fail "Go module verification failed. Clear the affected module cache entry only after reviewing the error, then rerun ./install.sh."
	fi

	mkdir -p -- "$(dirname -- "${BINARY_PATH}")"
	TEMP_BINARY="$(mktemp "${BINARY_PATH}.tmp.XXXXXX")"
	info "Building garga. The existing binary will remain untouched if the build fails."
	if ! go_build_garga "${TEMP_BINARY}"; then
		fail "garga build failed. Review the compiler output, correct the reported issue, and rerun ./install.sh."
	fi
	chmod 0755 "${TEMP_BINARY}"
	mv -f -- "${TEMP_BINARY}" "${BINARY_PATH}"
	TEMP_BINARY=""

	if ! "${BINARY_PATH}" --help >/dev/null 2>&1; then
		fail "The new binary was built but failed its help smoke test. Run '${BINARY_PATH} --help' to inspect the failure."
	fi
	success "garga is ready at ${BINARY_PATH}."
}

install_prepared_binary() {
	local dest="${DESTDIR}${PREFIX}/bin"
	local installed="${dest}/garga"

	if [[ ! -x "${BINARY_PATH}" ]]; then
		fail "No prepared binary at ${BINARY_PATH}. Rerun ./install.sh to build it."
	fi

	info "Installing garga to ${installed}."
	if mkdir -p -- "${dest}" 2>/dev/null && cp -- "${BINARY_PATH}" "${installed}" && chmod 0755 "${installed}"; then
		success "Installed ${installed}. Run 'garga --help' or 'garga version'."
		return
	fi
	info "The destination is not writable; retrying with administrative privileges."
	if ! run_as_root mkdir -p -- "${dest}"; then
		fail "Could not create ${dest}. Choose a writable --prefix or rerun ./install.sh as root."
	fi
	if ! run_as_root cp -- "${BINARY_PATH}" "${installed}"; then
		fail "Could not copy garga to ${installed}."
	fi
	if ! run_as_root chmod 0755 "${installed}"; then
		fail "Could not set executable permissions on ${installed}."
	fi
	success "Installed ${installed}. Run 'garga --help' or 'garga version'."
}

prepare_application() {
	if ((FORCE_REBUILD == 0)) && binary_is_current; then
		success "Existing binary is current; dependency installation and rebuilding are not required."
		return
	fi

	if ((FORCE_REBUILD)); then
		info "A rebuild was explicitly requested."
	elif [[ -e "${BINARY_PATH}" ]]; then
		warn "The existing binary is missing executable permissions, invalid, or older than project sources."
	else
		info "No prepared garga binary was found."
	fi

	read_required_go_version
	check_build_dependencies
	install_dependencies
	verify_build_dependencies
	build_application
}

main() {
	cd -- "${PROJECT_ROOT}"
	parse_arguments "$@"

	if ((SHOW_HELP)); then
		show_install_help
		return
	fi

	detect_operating_system
	info "Detected operating system: ${OS_NAME}."
	prepare_application
	install_prepared_binary
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
	main "$@"
fi
