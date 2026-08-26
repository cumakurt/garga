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
FORCE_REBUILD=0
SETUP_ONLY=0
SHOW_LAUNCHER_HELP=0
TEMP_BINARY=""
APP_ARGS=()

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
}

trap cleanup EXIT INT TERM

show_launcher_help() {
	cat <<'EOF'
Usage:
  ./run.sh [launcher options] [--] [garga arguments]

Launcher options:
  -h, --help       Show launcher help and, when ready, garga command help.
  --setup-only     Install missing build dependencies and prepare the binary without running it.
  --rebuild        Rebuild even when the existing binary is current.
  --               Pass all remaining arguments directly to garga.

Behavior:
  With no arguments, the launcher prepares garga, prints application help, and shows examples.
  When the binary is current and executable, dependency installation and rebuilding are skipped.
EOF
}

show_examples() {
	cat <<'EOF'

Examples:
  ./run.sh
      Prepare garga and display application help.

  ./run.sh version
      Print garga version information.

  ./run.sh --setup-only
      Prepare the application without running a command.

  ./run.sh --rebuild version
      Force a clean binary replacement, then print its version.

  ./run.sh -- --help
      Prepare the application and pass --help directly to garga.

  ./bin/garga version
      Run the prepared binary directly.
EOF
}

parse_arguments() {
	while (($# > 0)); do
		case "$1" in
		-h | --help)
			SHOW_LAUNCHER_HELP=1
			shift
			;;
		--setup-only)
			SETUP_ONLY=1
			shift
			;;
		--rebuild)
			FORCE_REBUILD=1
			shift
			;;
		--)
			shift
			APP_ARGS=("$@")
			break
			;;
		*)
			APP_ARGS=("$@")
			break
			;;
		esac
	done

	if ((SHOW_LAUNCHER_HELP)) && ((${#APP_ARGS[@]} > 0)); then
		fail "--help cannot be combined with garga arguments. Use './run.sh -- --help' to pass application help explicitly."
	fi
	if ((SETUP_ONLY)) && ((${#APP_ARGS[@]} > 0)); then
		fail "--setup-only cannot be combined with garga arguments."
	fi
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

	fail "Unable to read the required Go version from ${GO_MOD_PATH}. Restore a valid go.mod file and rerun the launcher."
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

	local newer_source
	newer_source="$(find "${PROJECT_ROOT}/cmd" "${PROJECT_ROOT}/internal" -type f -name '*.go' -newer "${BINARY_PATH}" -print -quit 2>/dev/null)"
	[[ -z "${newer_source}" ]]
}

check_build_dependencies() {
	NEED_GO=0
	NEED_GIT=0

	if ! command -v go >/dev/null 2>&1; then
		NEED_GO=1
		warn "Go is not installed. Go ${REQUIRED_GO_VERSION} or newer is required to build garga."
	else
		INSTALLED_GO_VERSION="$(go env GOVERSION 2>/dev/null || true)"
		if ! go_version_is_supported "${INSTALLED_GO_VERSION}" "${REQUIRED_GO_VERSION}"; then
			NEED_GO=1
			warn "Installed ${INSTALLED_GO_VERSION:-Go version unknown} is older than required Go ${REQUIRED_GO_VERSION}."
		fi
	fi

	if ! command -v git >/dev/null 2>&1; then
		NEED_GIT=1
		warn "Git is not installed. It is required as a fallback for direct Go module downloads."
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
	fail "Administrative privileges are required, but sudo is unavailable. Run the shown package-manager command as root, then rerun ./run.sh."
}

install_apt_dependencies() {
	local packages=(ca-certificates)
	((NEED_GO)) && packages+=(golang-go)
	((NEED_GIT)) && packages+=(git)

	info "Installing missing dependencies with apt-get: ${packages[*]}"
	if ! run_as_root apt-get update; then
		fail "apt-get update failed. Check repository configuration and network access, then rerun ./run.sh."
	fi
	if ! run_as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}"; then
		fail "apt-get could not install the required packages. Install Go >= ${REQUIRED_GO_VERSION} and Git manually, then rerun ./run.sh."
	fi
}

install_dnf_dependencies() {
	local packages=(ca-certificates)
	((NEED_GO)) && packages+=(golang)
	((NEED_GIT)) && packages+=(git)
	info "Installing missing dependencies with dnf: ${packages[*]}"
	if ! run_as_root dnf install -y "${packages[@]}"; then
		fail "dnf could not install the required packages. Install Go >= ${REQUIRED_GO_VERSION} and Git manually, then rerun ./run.sh."
	fi
}

install_yum_dependencies() {
	local packages=(ca-certificates)
	((NEED_GO)) && packages+=(golang)
	((NEED_GIT)) && packages+=(git)
	info "Installing missing dependencies with yum: ${packages[*]}"
	if ! run_as_root yum install -y "${packages[@]}"; then
		fail "yum could not install the required packages. Install Go >= ${REQUIRED_GO_VERSION} and Git manually, then rerun ./run.sh."
	fi
}

install_pacman_dependencies() {
	local packages=(ca-certificates)
	((NEED_GO)) && packages+=(go)
	((NEED_GIT)) && packages+=(git)
	info "Installing missing dependencies with pacman: ${packages[*]}"
	if ! run_as_root pacman -S --needed --noconfirm "${packages[@]}"; then
		fail "pacman could not install the required packages. Update the system package database safely, install Go >= ${REQUIRED_GO_VERSION} and Git, then rerun ./run.sh."
	fi
}

install_zypper_dependencies() {
	local packages=(ca-certificates)
	((NEED_GO)) && packages+=(go)
	((NEED_GIT)) && packages+=(git)
	info "Installing missing dependencies with zypper: ${packages[*]}"
	if ! run_as_root zypper --non-interactive install "${packages[@]}"; then
		fail "zypper could not install the required packages. Install Go >= ${REQUIRED_GO_VERSION} and Git manually, then rerun ./run.sh."
	fi
}

install_apk_dependencies() {
	local packages=(ca-certificates)
	((NEED_GO)) && packages+=(go)
	((NEED_GIT)) && packages+=(git)
	info "Installing missing dependencies with apk: ${packages[*]}"
	if ! run_as_root apk add "${packages[@]}"; then
		fail "apk could not install the required packages. Install Go >= ${REQUIRED_GO_VERSION} and Git manually, then rerun ./run.sh."
	fi
}

install_brew_dependencies() {
	local packages=()
	((NEED_GO)) && packages+=(go)
	((NEED_GIT)) && packages+=(git)
	info "Installing missing dependencies with Homebrew: ${packages[*]}"
	if ! brew install "${packages[@]}"; then
		fail "Homebrew could not install the required packages. Resolve the reported error and rerun ./run.sh."
	fi
}

install_windows_dependencies() {
	if ! command -v winget.exe >/dev/null 2>&1; then
		fail "No supported Windows package manager was found. Install Go >= ${REQUIRED_GO_VERSION} from https://go.dev/dl/ and Git from https://git-scm.com/download/win, then reopen the shell and rerun ./run.sh."
	fi
	if ((NEED_GO)); then
		info "Installing Go with winget."
		if ! winget.exe install --id GoLang.Go --exact --silent --accept-package-agreements --accept-source-agreements; then
			fail "winget could not install Go. Install Go >= ${REQUIRED_GO_VERSION} from https://go.dev/dl/, reopen the shell, and rerun ./run.sh."
		fi
	fi
	if ((NEED_GIT)); then
		info "Installing Git with winget."
		if ! winget.exe install --id Git.Git --exact --silent --accept-package-agreements --accept-source-agreements; then
			fail "winget could not install Git. Install it from https://git-scm.com/download/win, reopen the shell, and rerun ./run.sh."
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

	case "${OS_KIND}" in
	linux)
		if command -v apt-get >/dev/null 2>&1; then
			install_apt_dependencies
		elif command -v dnf >/dev/null 2>&1; then
			install_dnf_dependencies
		elif command -v yum >/dev/null 2>&1; then
			install_yum_dependencies
		elif command -v pacman >/dev/null 2>&1; then
			install_pacman_dependencies
		elif command -v zypper >/dev/null 2>&1; then
			install_zypper_dependencies
		elif command -v apk >/dev/null 2>&1; then
			install_apk_dependencies
		elif command -v brew >/dev/null 2>&1; then
			install_brew_dependencies
		else
			fail "No supported Linux package manager was found. Install Go >= ${REQUIRED_GO_VERSION} and Git, ensure both commands are on PATH, then rerun ./run.sh."
		fi
		;;
	macos)
		if command -v brew >/dev/null 2>&1; then
			install_brew_dependencies
		else
			fail "Homebrew is required for automatic setup on macOS. Install it from https://brew.sh/, then rerun ./run.sh. Alternatively install Go >= ${REQUIRED_GO_VERSION} and Git manually."
		fi
		;;
	freebsd)
		local packages=()
		((NEED_GO)) && packages+=(go)
		((NEED_GIT)) && packages+=(git)
		info "Installing missing dependencies with pkg: ${packages[*]}"
		if ! run_as_root pkg install -y "${packages[@]}"; then
			fail "pkg could not install the required packages. Install Go >= ${REQUIRED_GO_VERSION} and Git manually, then rerun ./run.sh."
		fi
		;;
	openbsd)
		local packages=()
		((NEED_GO)) && packages+=(go)
		((NEED_GIT)) && packages+=(git)
		info "Installing missing dependencies with pkg_add: ${packages[*]}"
		if ! run_as_root pkg_add "${packages[@]}"; then
			fail "pkg_add could not install the required packages. Install Go >= ${REQUIRED_GO_VERSION} and Git manually, then rerun ./run.sh."
		fi
		;;
	netbsd)
		if ! command -v pkgin >/dev/null 2>&1; then
			fail "pkgin is required for automatic setup on NetBSD. Install Go >= ${REQUIRED_GO_VERSION} and Git manually, then rerun ./run.sh."
		fi
		local packages=()
		((NEED_GO)) && packages+=(go)
		((NEED_GIT)) && packages+=(git)
		info "Installing missing dependencies with pkgin: ${packages[*]}"
		if ! run_as_root pkgin -y install "${packages[@]}"; then
			fail "pkgin could not install the required packages. Install Go >= ${REQUIRED_GO_VERSION} and Git manually, then rerun ./run.sh."
		fi
		;;
	windows)
		install_windows_dependencies
		;;
	*)
		fail "Automatic dependency installation is not supported on ${OS_NAME}. Install Go >= ${REQUIRED_GO_VERSION} and Git, ensure both commands are on PATH, then rerun ./run.sh."
		;;
	esac

	hash -r
}

verify_build_dependencies() {
	if ! command -v go >/dev/null 2>&1; then
		fail "Go is still unavailable after installation. Open a new terminal or add the Go bin directory to PATH, then rerun ./run.sh."
	fi
	INSTALLED_GO_VERSION="$(go env GOVERSION 2>/dev/null || true)"
	if ! go_version_is_supported "${INSTALLED_GO_VERSION}" "${REQUIRED_GO_VERSION}"; then
		fail "${INSTALLED_GO_VERSION:-The installed Go version} does not satisfy Go ${REQUIRED_GO_VERSION}. Upgrade from https://go.dev/dl/, ensure the new go command is on PATH, then rerun ./run.sh."
	fi
	if ! command -v git >/dev/null 2>&1; then
		fail "Git is still unavailable after installation. Open a new terminal or add Git to PATH, then rerun ./run.sh."
	fi
	success "Build dependencies are ready (${INSTALLED_GO_VERSION}, $(git --version))."
}

build_application() {
	export GOTOOLCHAIN=local

	info "Downloading missing Go modules. Cached modules will not be reinstalled."
	if ! go mod download; then
		fail "Go module download failed. Check internet access, TLS certificates, and GOPROXY, then rerun ./run.sh."
	fi
	if ! go mod verify; then
		fail "Go module verification failed. Clear the affected module cache entry only after reviewing the error, then rerun ./run.sh."
	fi

	mkdir -p -- "$(dirname -- "${BINARY_PATH}")"
	TEMP_BINARY="$(mktemp "${BINARY_PATH}.tmp.XXXXXX")"
	info "Building garga. The existing binary will remain untouched if the build fails."
	if ! go build -trimpath -o "${TEMP_BINARY}" ./cmd/garga; then
		fail "garga build failed. Review the compiler output, correct the reported issue, and rerun ./run.sh."
	fi
	chmod 0755 "${TEMP_BINARY}"
	mv -f -- "${TEMP_BINARY}" "${BINARY_PATH}"
	TEMP_BINARY=""

	if ! "${BINARY_PATH}" --help >/dev/null 2>&1; then
		fail "The new binary was built but failed its help smoke test. Run '${BINARY_PATH} --help' to inspect the failure."
	fi
	success "garga is ready at ${BINARY_PATH}."
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
	detect_operating_system
	info "Detected operating system: ${OS_NAME}."

	if ((SHOW_LAUNCHER_HELP)); then
		show_launcher_help
		if binary_is_current; then
			printf '\ngarga command help:\n\n'
			"${BINARY_PATH}" --help
		else
			warn "garga is not prepared or is stale. Run './run.sh' to install missing dependencies and build it."
		fi
		show_examples
		return
	fi

	prepare_application
	if ((SETUP_ONLY)); then
		success "Setup completed. Run './run.sh' for help or './run.sh version' for version information."
		return
	fi

	if ((${#APP_ARGS[@]} > 0)); then
		exec "${BINARY_PATH}" "${APP_ARGS[@]}"
	fi

	printf '\ngarga command help:\n\n'
	"${BINARY_PATH}" --help
	show_examples
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
	main "$@"
fi
