# Common tasks: "make help" lists them. The defaults below can be overridden, e.g.
# make fuzz FUZZTIME=2m
GO        ?= go
BIN       ?= weed
FUZZTIME  ?= 20s
# Platforms that "make cross" builds for, as CI does: weed runs on Linux alone
PLATFORMS ?= linux/amd64 linux/arm64

.PHONY: test-systemd test-vm dist all build test test-root test-cgroups bench-workers interop interop-storage find-limits find-limits-users check fmt vulncheck fuzz bench cross ci docs clean help

all: build

build: ## Build ./weed
	$(GO) build -trimpath -o $(BIN) .

test: ## Unit and end-to-end tests (those that need root are skipped)
	$(GO) test -race -count=1 ./...

test-root: ## All tests as root, including those of worker processes, Unix accounts and mounts (sudo)
	$(GO) test -exec sudo -race -count=1 ./...

# The test rearranges the cgroup it runs in: systemd-run gives it one of its own
test-cgroups: ## The cgroups of worker processes, as root in a cgroup of their own (sudo, systemd-run)
	$(GO) test -count=1 -v -run TestWorkerCgroups \
		-exec 'sudo systemd-run --quiet --wait --pipe --collect --same-dir -p Delegate=yes -E WEED_TEST_CGROUPS=1' \
		./internal/server

test-systemd: ## weed's RPM as the guide installs it, under systemd, as the account weed and as root (Podman, sudo); WEED=path or RPM=path tests those
	WEED="$(WEED)" RPM="$(RPM)" test/systemd/systemd.sh

test-vm: ## test-systemd's tests on an AlmaLinux 10 virtual machine, SELinux enforcing (qemu, KVM, Podman); RPM=path tests that RPM
	RPM="$(RPM)" test/vm/vm.sh

interop: ## Interoperability tests with gfal2, davix and XRootD (Podman, sudo; ROOTLESS=1 without)
	test/interop/interop.sh

interop-storage: ## Copies between weed and each storage system of test/interop/storage/, then a table of versions and results; STORAGE="dcache eos" runs those (Podman, sudo; ROOTLESS=1 without)
	test/interop/storage.sh $(STORAGE)

# weed limits reads CONFIG, /etc/weed/weed.toml if there is one; without either, it
# measures DATA, /var/tmp by default
find-limits: build ## weed limits on this machine (sudo): what weed can serve, and the settings that would let it; CONFIG=, DATA=, ACCOUNT= (yours), results in test/limits/out; ARGS="..." go to weed limits (-quick, -rtt 100ms, -- stress options)
	sudo ./$(BIN) limits -account "$(or $(ACCOUNT),$(shell id -un))" -out test/limits/out \
		$(if $(CONFIG),-config "$(CONFIG)") \
		$(if $(DATA),-dir "$(DATA)",$(if $(or $(CONFIG),$(wildcard /etc/weed/weed.toml)),,-dir /var/tmp)) $(ARGS)

find-limits-users: ## The limits of weed serving USERS accounts (100) to crowds of thousands of clients (Podman, sudo); ARGS="..." go to test/stress
	USERS="$(USERS)" METRICS_PORT="$(METRICS_PORT)" test/limits/users.sh $(ARGS)

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

bench-workers: ## Throughput served by worker processes and directly, as root (sudo)
	$(GO) test -exec 'sudo --preserve-env=WEED_BENCH_MIB' ./internal/server -run '^$$' -bench Workers -benchtime 3x -count 3

cross: ## Build and vet for every platform in PLATFORMS
	@set -e; for p in $(PLATFORMS); do \
		echo "== $$p"; \
		GOOS=$${p%/*} GOARCH=$${p#*/} $(GO) build -o /dev/null .; \
		GOOS=$${p%/*} GOARCH=$${p#*/} $(GO) vet ./...; \
	done

ci: check test cross ## What CI runs, except root tests, fuzzing, govulncheck, interop, test-systemd, test-vm and docs

docs: build ## The administration guide, docs/html, from docs/src (pandoc)
	$(MAKE) -C docs/src dist WEED=$(abspath $(BIN))

dist: ## The archives of a release in dist/, for the tag of this commit, on EL10 (release/dist.sh)
	release/dist.sh

clean: ## Remove the built binary and dist/
	rm -f $(BIN)
	rm -rf dist
	$(MAKE) -C docs/src clean

help: ## List the targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "} {printf "  %-11s %s\n", $$1, $$2}'
