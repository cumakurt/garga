GO ?= go
BINARY ?= bin/garga
GO_FILES := $(shell find cmd internal scripts -name '*.go' -type f)
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

.PHONY: check build fmt fmt-check shell-test test test-race vet bench integration release fuzz-smoke vulncheck

check: fmt-check shell-test vet test build

build:
	mkdir -p $(dir $(BINARY))
	$(GO) build -o $(BINARY) ./cmd/garga

fmt:
	gofmt -w $(GO_FILES)

fmt-check:
	@test -z "$$(gofmt -l $(GO_FILES))" || { \
		echo "Go files require formatting; run 'make fmt'" >&2; \
		gofmt -l $(GO_FILES) >&2; \
		exit 1; \
	}

shell-test:
	bash -n run.sh tests/run_sh_test.sh
	bash tests/run_sh_test.sh

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

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

# Downloads the vulnerability database. Not part of check.
vulncheck:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...
