# connector Makefile
SHELL := /bin/bash
.DEFAULT_GOAL := all

.PHONY: all generate build connector-ctl clean test test-integration test-all test-source-checks bench release test-release release-clean deps fmt lint vet vmlinux help
.PHONY: connector-vpp egress vpp test-native-deps test-egress

# ---------------------------------------------------------------------------
# Architecture selection
# ---------------------------------------------------------------------------
# TARGET_ARCH selects which architecture to build for. Defaults to the host
# architecture. Supported values: x86_64, aarch64 (Go-style aliases amd64 /
# arm64 are normalized below).
#
# connector-ctl is pure Go (no CGO), so cross-compiling is just GOARCH — no cross
# toolchain is needed. The committed eBPF objects ship one variant per arch
# (pkg/internal/bpf/vswitch_{x86,arm64}_bpfel.o, selected by Go build tags), so
# the right object is embedded automatically for the chosen GOARCH.
HOST_ARCH   := $(shell uname -m)
TARGET_ARCH ?= $(HOST_ARCH)

# Normalize Go-style aliases to uname -m form so the rest of the Makefile can
# switch on a single canonical name. `override` is required because TARGET_ARCH
# may come from the command line (highest precedence in Make); a plain `:=`
# assignment would be silently dropped.
ifeq ($(TARGET_ARCH),amd64)
  override TARGET_ARCH := x86_64
endif
ifeq ($(TARGET_ARCH),arm64)
  override TARGET_ARCH := aarch64
endif

ifeq ($(TARGET_ARCH),x86_64)
  GO_ARCH := amd64
else ifeq ($(TARGET_ARCH),aarch64)
  GO_ARCH := arm64
else
  $(error unsupported TARGET_ARCH=$(TARGET_ARCH); supported: x86_64, aarch64)
endif

# ---------------------------------------------------------------------------
# Build settings
# ---------------------------------------------------------------------------
# Binaries are per-arch under bin/$(TARGET_ARCH)/ so two architectures can build
# side-by-side. A native build also drops a bin/<name> symlink to the host-arch
# binary so scripts and humans can use the short path. Coverage and release
# artifacts are architecture-neutral and stay under build/.
BINARY_NAME := connector-ctl
BINDIR      := bin/$(TARGET_ARCH)
BINARY      := $(BINDIR)/$(BINARY_NAME)
BUILD_DIR   := build
COVERAGE    := $(BUILD_DIR)/coverage.out
EGRESS_TEST_DIR ?= $(CURDIR)/$(BUILD_DIR)/egress/acceptance
VERSION     ?= v0.1.0
GO          := go
CLANG       := clang
GO_BUILD_FLAGS := -trimpath
# Version is explicitly supplied by release builds; ordinary builds are dev.
BUILD_VERSION ?= dev
VERSION_TAG := $(shell git tag --points-at HEAD --list 'v[0-9]*' --sort=refname 2>/dev/null | \
	grep -E '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-preview\.[0-9]{8}(\.[1-9][0-9]*)?)?$$' | \
	awk -v preferred="$(BUILD_VERSION)" 'NR == 1 { first = $$0 } $$0 == preferred { exact = $$0 } END { print (exact != "" ? exact : first) }')
VERSION_LDFLAGS := -X github.com/kuasar-sandbox/connector/internal/version.releaseVersion=$(BUILD_VERSION) -X github.com/kuasar-sandbox/connector/internal/version.gitTag=$(VERSION_TAG)

# NOTE: builds use `-trimpath` so absolute build paths are not embedded in the
# binary. The eBPF object files committed under pkg/internal/bpf/ are the
# canonical pre-generated artifacts, so connector-ctl does NOT require clang —
# run `make generate` only when you change bpf/*.c (needs clang 12+).

# Native-only symlink helper: bin/<name> -> $(TARGET_ARCH)/<name>. Cross builds
# (HOST_ARCH != TARGET_ARCH) leave bin/<name> untouched so it keeps pointing at
# the host-arch binary the user is actually running. $(1) = basename.
define link_bin
@if [ "$(HOST_ARCH)" = "$(TARGET_ARCH)" ]; then \
   mkdir -p bin && ln -sfn $(TARGET_ARCH)/$(1) bin/$(1); \
 fi
endef

# Default target: build the control binary and matching static dataplane.
all: build

# Regenerate eBPF bytecode and Go bindings (all architectures). Requires clang.
generate:
	@echo "==> Generating eBPF bytecode..."
	$(GO) generate ./...

# All runtime files share bin/<arch>; the control-only target remains available
# for Go development and cross-compilation.
build: connector-ctl connector-vpp

connector-vpp:
	$(MAKE) -C native-deps TARGET_ARCH="$(TARGET_ARCH)" vpp

vpp egress: connector-vpp

test-native-deps:
	$(MAKE) -C native-deps test

test-egress:
	bash egress/tests/run.sh "$(CURDIR)/$(BINARY)" "$(CURDIR)/$(BINDIR)" "$(EGRESS_TEST_DIR)"

connector-ctl:
	@echo "==> Building $(BINARY_NAME) ($(TARGET_ARCH))..."
	@mkdir -p $(BINDIR)
	GOOS=linux GOARCH=$(GO_ARCH) CGO_ENABLED=0 $(GO) build $(GO_BUILD_FLAGS) -ldflags '$(VERSION_LDFLAGS)' -o $(BINARY) ./cmd/connector-ctl
	$(call link_bin,$(BINARY_NAME))
	@echo "==> Built $(BINARY)"

# go vet across the module — parallels the other repos' `vet` target so the
# umbrella can drive every repo's checks through `$(MAKE) -C <repo> vet`.
vet:
	$(GO) vet ./...

# Remove build-generated binaries and coverage. Does NOT touch release tarballs
# (use `release-clean`) or any source; only files produced by `build`/`test`.
clean:
	@echo "==> Cleaning build artifacts..."
	$(MAKE) -C native-deps TARGET_ARCH="$(TARGET_ARCH)" clean
	rm -f bin/$(BINARY_NAME) bin/*/$(BINARY_NAME) $(COVERAGE)
	-@rmdir bin/* bin 2>/dev/null || true

# Run unit tests with coverage profile (architecture-neutral output).
test:
	@echo "==> Running unit tests..."
	@mkdir -p $(BUILD_DIR)
	$(GO) test -v -coverprofile=$(COVERAGE) ./...

# Run all tests including integration tests (requires root + a BPF-capable kernel).
test-integration:
	@echo "==> Running all tests (integration; requires root + BPF)..."
	@mkdir -p $(BUILD_DIR)
	$(GO) test -tags=integration -exec sudo -v -coverprofile=$(COVERAGE) ./...

# Alias for test-integration.
test-all: test-integration

test-source-checks:
	bash scripts/ci-source-checks.sh

# Run the performance benchmark (requires root + iperf3).
bench: connector-ctl
	@echo "==> Running performance benchmark..."
	sudo bash examples/perf_bench.sh all

# ---------------------------------------------------------------------------
# Release packaging
# ---------------------------------------------------------------------------
# The release contains one target archive and release notes. Its bin directory
# carries connector-ctl alongside the fully static connector-vpp dataplane.
# Mixed release recipes run sub-makes with the jobserver on real builds. GNU
# Make executes recipes that directly reference $(MAKE) even under --dry-run.
release_make = $(MAKE)
release_recursive = $(if $(findstring n,$(filter-out -% %=%,$(firstword $(MAKEFLAGS)))),,+)

release:
	$(release_recursive)@set -e; export GOWORK=off; \
	if [[ "$(VERSION)" == *-preview.* ]]; then \
	  work="$$(mktemp -d)"; trap 'rm -rf -- "$$work"' EXIT; \
	  selected_go="$$( $(GO) env GOROOT)/bin/go"; \
	  (cd "$$work" && GOTOOLCHAIN=local "$$selected_go" work init "$(CURDIR)"); \
	  export GOWORK="$$work/go.work"; \
	fi; \
	$(release_make) _release-bundle GOWORK="$$GOWORK" BUILD_VERSION="$(VERSION)"

.PHONY: _release-bundle
_release-bundle: build
	mkdir -p $(BUILD_DIR)
	rm -rf $(BUILD_DIR)/release-bundle
	SOURCE_DATE_EPOCH="$$(git show -s --format=%ct HEAD)" \
		bash scripts/release.sh package "$(VERSION)" "$(TARGET_ARCH)" \
		$(BUILD_DIR)/release-bundle

test-release:
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/test-environment-tools.py
	bash scripts/test-release.sh

release-clean:
	@echo "==> Removing release artifacts..."
	rm -rf $(BUILD_DIR)/release-bundle

# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------
# Check build/test dependencies.
deps:
	@echo "==> Checking dependencies..."
	@which $(CLANG) > /dev/null || echo "clang not found (needed only for 'make generate'); install llvm"
	@which bpftool > /dev/null || echo "bpftool not found (needed only for 'make vmlinux')"
	$(GO) mod download

# Format Go and BPF C sources.
fmt:
	@echo "==> Formatting..."
	$(GO) fmt ./...
	clang-format -i bpf/*.c bpf/*.h 2>/dev/null || true

# Vet Go sources.
lint:
	@echo "==> Linting..."
	$(GO) vet ./...

# Regenerate bpf/vmlinux.h from the running kernel's BTF (requires bpftool).
vmlinux:
	@echo "==> Generating bpf/vmlinux.h..."
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

help:
	@echo "connector make targets:"
	@echo "  all / build      - Build $(BINARY_NAME) and connector-vpp into bin/<arch> (default)"
	@echo "  connector-ctl    - Build only the Go control binary (supports cross-compilation)"
	@echo "  connector-vpp    - Build the fully static Egress dataplane using native-deps"
	@echo "  generate         - Regenerate eBPF bytecode + Go bindings (requires clang 12+)"
	@echo "  clean            - Remove build-generated binaries + coverage (not release tarballs)"
	@echo "  test             - Run unit tests (coverage -> $(COVERAGE))"
	@echo "  test-integration - Run all tests incl. integration (requires root + BPF)"
	@echo "  test-all         - Alias for test-integration"
	@echo "  test-source-checks - Required race, real pinned-BPF stats and vet checks"
	@echo "  egress / vpp     - Aliases for connector-vpp"
	@echo "  test-native-deps - Check native source, patch and build workflow"
	@echo "  test-egress      - Isolated privileged local/remote, wire and 12288/196608 acceptance"
	@echo "  bench            - Run performance benchmark (requires root + iperf3)"
	@echo "  release          - Build a validated component release bundle"
	@echo "  test-release     - Test component release packaging"
	@echo "  release-clean    - Remove release bundle outputs"
	@echo "  deps             - Check dependencies and download Go modules"
	@echo "  fmt              - Format Go and BPF C sources"
	@echo "  lint             - go vet ./..."
	@echo "  vmlinux          - Regenerate bpf/vmlinux.h from kernel BTF"
	@echo ""
	@echo "Cross-compile Go:  make connector-ctl TARGET_ARCH=aarch64 (aliases: amd64, arm64)"
	@echo "Native VPP:        build on the matching x86_64 or aarch64 host"
	@echo "Output layout:     bin/<arch>/{connector-ctl,connector-vpp,vpp-runtime.json}"

.PHONY: check-version
# Verify the newly built clean release binaries on their native architecture.
check-version:
	@test "$(HOST_ARCH)" = "$(TARGET_ARCH)"
	@set -e; source="$(VERSION_TAG)"; \
	if [ -z "$$source" ]; then source="$$(git rev-parse HEAD | cut -c1-12)"; fi; \
	for name in connector-ctl; do \
	  binary="$(BINDIR)/$$name"; \
	  actual="$$("$$binary" --version)"; \
	  rc=0; "$$binary" --version unexpected >/dev/null 2>&1 || rc=$$?; \
	  if [ "$$rc" -ne 2 ]; then echo "$$name accepted extra version arguments" >&2; exit 1; fi; \
	  expected="$$name $(BUILD_VERSION) ($$source)"; \
	  if [ "$$actual" != "$$expected" ]; then printf 'expected %s, got %s\n' "$$expected" "$$actual" >&2; exit 1; fi; \
	done
