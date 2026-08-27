GO ?= go
BINARY ?= bin/garga
GO_FILES := $(shell find cmd internal scripts -name '*.go' -type f) $(wildcard *.go)
FUZZ_TIME ?= 5s
VERSION ?=
RELEASE_COMMIT ?=
RELEASE_FLAGS := -out dist
ifneq ($(VERSION),)
RELEASE_FLAGS += -version $(VERSION)
endif
ifneq ($(RELEASE_COMMIT),)
RELEASE_FLAGS += -commit $(RELEASE_COMMIT)
endif

GOLANGCI_LINT_VERSION ?= v2.13.1
GOVULNCHECK_VERSION ?= v1.1.4
PREFIX ?= /usr/local
DESTDIR ?=
INSTALL_BINDIR = $(DESTDIR)$(PREFIX)/bin

.PHONY: check build install uninstall fmt fmt-check shell-test test test-race vet lint bench integration release fuzz-smoke vulncheck signatures-validate

check: fmt-check shell-test vet test signatures-validate build

build:
	mkdir -p $(dir $(BINARY))
	$(GO) build -o $(BINARY) ./cmd/garga

# Rebuilds, then copies the current binary onto PATH. Writing to /usr/local/bin
# typically requires `sudo make install`.
install: build
	mkdir -p "$(INSTALL_BINDIR)"
	cp "$(BINARY)" "$(INSTALL_BINDIR)/garga"
	chmod 755 "$(INSTALL_BINDIR)/garga"

uninstall:
	rm -f "$(INSTALL_BINDIR)/garga"

fmt:
	gofmt -w $(GO_FILES)

fmt-check:
	@test -z "$$(gofmt -l $(GO_FILES))" || { \
		echo "Go files require formatting; run 'make fmt'" >&2; \
		gofmt -l $(GO_FILES) >&2; \
		exit 1; \
	}

shell-test:
	bash -n install.sh tests/install_sh_test.sh
	bash tests/install_sh_test.sh

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

# Pinned analyzer; not a runtime module. Downloads on first use.
lint:
	$(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run ./...

# Microbenchmarks for docs/performance.md. Not part of check: timings are machine-specific.
BENCH_PACKAGES ?= ./internal/target ./internal/fingerprint ./internal/vulnerability ./internal/report ./internal/scanner

bench:
	$(GO) test -run='^$$' -bench=. -benchmem $(BENCH_PACKAGES)

# Opt-in Elasticsearch containers. Pulls docker.elastic.co images; not part of check.
integration:
	GARGA_INTEGRATION=1 $(GO) test -count=1 -timeout 45m ./internal/integration

# Cross-platform archives, SBOM, and SHA256SUMS. VERSION is required (for example v0.1.0).
release:
	$(GO) run ./scripts/release $(RELEASE_FLAGS)

fuzz-smoke:
	$(GO) test -fuzz=FuzzParseVersion -fuzztime=$(FUZZ_TIME) ./internal/vulnerability
	$(GO) test -fuzz=FuzzParseRange -fuzztime=$(FUZZ_TIME) ./internal/vulnerability
	$(GO) test -fuzz=FuzzParseSignature -fuzztime=$(FUZZ_TIME) ./internal/vulnerability

# Loads the bundled Elasticsearch CVE corpus through the same validator as garga scan/vuln.
SIGNATURES_DIR ?= internal/vulnerability/bundled
signatures-validate:
	$(GO) run ./scripts/validate-signatures $(SIGNATURES_DIR)

# Downloads the vulnerability database. Not part of check. Findings are reported
# against the compiling toolchain; use Go 1.26.6+ or 1.27.0+ so patched standard
# library issues are not reported as product findings.
vulncheck:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...
