# Common tasks: "make help" lists them. The defaults below can be overridden, e.g.
# make fuzz FUZZTIME=2m
GO        ?= go
BIN       ?= weed
FUZZTIME  ?= 20s
# Platforms that "make cross" builds for, as CI does
PLATFORMS ?= linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 \
             windows/amd64 windows/arm64 freebsd/amd64 freebsd/arm64
# Container image for "make test-linux": the local Go version
GO_IMAGE  ?= golang:$(patsubst go%,%,$(firstword $(shell $(GO) env GOVERSION)))

.PHONY: all build test test-root test-linux interop check fmt vulncheck fuzz bench cross ci clean help

all: build

build: ## Build ./weed
	$(GO) build -trimpath -o $(BIN) .

test: ## Unit and end-to-end tests (those that need root are skipped)
	$(GO) test -race -count=1 ./...

test-root: ## All tests as root, including those that switch Unix identities (Linux, sudo)
	$(GO) test -exec sudo -race -count=1 ./...

test-linux: ## All tests as root in a Linux container (Docker), e.g. from macOS
	$(GO) mod download
	docker run --rm -v "$(CURDIR):/src" -v "$$($(GO) env GOMODCACHE):/go/pkg/mod" \
		-v weed-gocache:/root/.cache/go-build -w /src \
		-e GOPROXY=off -e GOFLAGS=-buildvcs=false \
		$(GO_IMAGE) go test -race -count=1 ./...

interop: ## Interoperability tests with gfal2, davix and XRootD (Docker)
	test/interop/interop.sh

check: ## gofmt and go vet
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "needs gofmt:"; echo "$$out"; exit 1; fi
	$(GO) vet ./...

fmt: ## Format the code
	gofmt -w .

vulncheck: ## Known vulnerabilities in weed and its dependencies
	$(GO) run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...

fuzz: ## Every fuzz test, FUZZTIME each
	@set -e; for spec in $$(grep -rho --include='*_test.go' '^func Fuzz[A-Za-z]*' internal | sort -u | sed 's/^func //'); do \
		pkg=$$(dirname $$(grep -rl --include='*_test.go' "^func $$spec(" internal)); \
		echo "== $$pkg $$spec"; \
		$(GO) test ./$$pkg -run '^$$' -fuzz "^$$spec\$$" -fuzztime $(FUZZTIME); \
	done

bench: ## Throughput benchmarks (WEED_BENCH_MIB sets the file size)
	$(GO) test ./internal/server -run '^$$' -bench . -benchtime 3x
	$(GO) test ./internal/digest -run '^$$' -bench Hasher

cross: ## Build and vet for every platform in PLATFORMS
	@set -e; for p in $(PLATFORMS); do \
		echo "== $$p"; \
		GOOS=$${p%/*} GOARCH=$${p#*/} $(GO) build -o /dev/null .; \
		GOOS=$${p%/*} GOARCH=$${p#*/} $(GO) vet ./...; \
	done

ci: check test cross ## What CI runs, except root tests, fuzzing, govulncheck and interop

clean: ## Remove the built binary
	rm -f $(BIN)

help: ## List the targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "} {printf "  %-11s %s\n", $$1, $$2}'
