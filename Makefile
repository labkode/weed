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

# Runs the Go toolchain in a container, with this tree and the local module cache
DOCKER_GO  = --rm -v "$(CURDIR):/src" -v "$$($(GO) env GOMODCACHE):/go/pkg/mod" \
             -v weed-gocache:/root/.cache/go-build -w /src --cap-add SYS_PTRACE \
             -e GOPROXY=off -e GOFLAGS=-buildvcs=false

.PHONY: test-systemd all build test test-root test-linux test-cgroups bench-workers interop lab lab-ssh lab-stop find-limits check fmt vulncheck fuzz bench cross ci docs clean help

all: build

build: ## Build ./weed
	$(GO) build -trimpath -o $(BIN) .

test: ## Unit and end-to-end tests (those that need root are skipped)
	$(GO) test -race -count=1 ./...

test-root: ## All tests as root, including those of worker processes and Unix accounts (Linux, sudo)
	$(GO) test -exec sudo -race -count=1 ./...

test-linux: ## All tests as root in a Linux container (Docker), e.g. from macOS
	$(GO) mod download
	docker run $(DOCKER_GO) $(GO_IMAGE) go test -race -count=1 ./...

test-cgroups: ## The cgroups of worker processes, in a privileged Linux container (Docker)
	$(GO) mod download
	docker run --privileged -e WEED_TEST_CGROUPS=1 $(DOCKER_GO) $(GO_IMAGE) \
		go test -count=1 -run TestWorkerCgroups -v ./internal/server

test-systemd: ## weed as the guide's systemd service, sandboxed, as root and as an account of its own (Docker)
	test/systemd/systemd.sh

interop: ## Interoperability tests with gfal2, davix and XRootD (Docker)
	test/interop/interop.sh

lab: ## weed with 22 Unix accounts under a load that does not stop, with Grafana (Docker)
	test/lab/lab.sh

lab-ssh: ## A shell in the running lab
	@test "$$(docker inspect -f '{{.State.Running}}' weed-lab 2>/dev/null)" = true || \
		{ echo "the lab does not run: make lab starts it" >&2; exit 1; }
	docker exec -it weed-lab bash

lab-stop: ## Stop the lab
	@test/lab/lab.sh stop

find-limits: ## The limits of weed on this machine: the lab under a load that grows until weed or the machine gives (Docker); ARGS="..." go to test/stress
	@test/lab/lab.sh find-limits $(ARGS)

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

bench-workers: ## Throughput served by worker processes and directly, in a Linux container (Docker)
	$(GO) mod download
	docker run -e WEED_BENCH_MIB $(DOCKER_GO) $(GO_IMAGE) \
		go test ./internal/server -run '^$$' -bench Workers -benchtime 3x -count 3

cross: ## Build and vet for every platform in PLATFORMS
	@set -e; for p in $(PLATFORMS); do \
		echo "== $$p"; \
		GOOS=$${p%/*} GOARCH=$${p#*/} $(GO) build -o /dev/null .; \
		GOOS=$${p%/*} GOARCH=$${p#*/} $(GO) vet ./...; \
	done

ci: check test cross ## What CI runs, except root tests, fuzzing, govulncheck, interop and docs

docs: build ## The administration guide, docs/html, from docs/src (pandoc)
	$(MAKE) -C docs/src dist WEED=$(abspath $(BIN))

clean: ## Remove the built binary
	rm -f $(BIN)
	$(MAKE) -C docs/src clean

help: ## List the targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "} {printf "  %-11s %s\n", $$1, $$2}'
