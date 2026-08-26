GO ?= go
BINARY ?= bin/garga

.PHONY: check build fmt fmt-check shell-test test test-race vet bench integration

check: fmt-check shell-test vet test build

build:
	mkdir -p $(dir $(BINARY))
	$(GO) build -o $(BINARY) ./cmd/garga

fmt:
	gofmt -w $$(find cmd internal -name '*.go' -type f)

fmt-check:
	@test -z "$$(gofmt -l $$(find cmd internal -name '*.go' -type f))" || { \
		echo "Go files require formatting; run 'make fmt'" >&2; \
		gofmt -l $$(find cmd internal -name '*.go' -type f) >&2; \
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
