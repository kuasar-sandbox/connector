# sandbox-vswitch Makefile
SHELL := /bin/bash

.PHONY: all generate build build-switch build-tapfd-get tapfd-get clean test test-integration test-all test-e2e bench release release-clean deps fmt lint vet vmlinux help

# ---------------------------------------------------------------------------
# Architecture selection
# ---------------------------------------------------------------------------
# TARGET_ARCH selects which architecture to build for. Defaults to the host
# architecture. Supported values: x86_64, aarch64 (Go-style aliases amd64 /
# arm64 are normalized below).
#
# vswitch-ctl is pure Go (no CGO), so cross-compiling is just GOARCH — no cross
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
BINARY_NAME := vswitch-ctl
BINDIR      := bin/$(TARGET_ARCH)
BINARY      := $(BINDIR)/$(BINARY_NAME)
BUILD_DIR   := build
COVERAGE    := $(BUILD_DIR)/coverage.out
RELEASE_DIR := $(BUILD_DIR)/dist
VERSION     ?= v0.1
GO          := go
CLANG       := clang
GO_BUILD_FLAGS := -trimpath

# NOTE: builds use `-trimpath` so absolute build paths are not embedded in the
# binary. The eBPF object files committed under pkg/internal/bpf/ are the
# canonical pre-generated artifacts, so a normal build does NOT require clang —
# run `make generate` only when you change bpf/*.c (needs clang 12+).

# Native-only symlink helper: bin/<name> -> $(TARGET_ARCH)/<name>. Cross builds
# (HOST_ARCH != TARGET_ARCH) leave bin/<name> untouched so it keeps pointing at
# the host-arch binary the user is actually running. $(1) = basename.
define link_bin
@if [ "$(HOST_ARCH)" = "$(TARGET_ARCH)" ]; then \
   mkdir -p bin && ln -sfn $(TARGET_ARCH)/$(1) bin/$(1); \
 fi
endef

# Default target: build the binary from the committed eBPF artifacts.
all: build

# Regenerate eBPF bytecode and Go bindings (all architectures). Requires clang.
generate:
	@echo "==> Generating eBPF bytecode..."
	$(GO) generate ./...

# Build every binary this repo ships for $(TARGET_ARCH): vswitch-ctl (the
# dataplane CLI) and tapfd-get (the tapfd §5 provider helper).
build: build-switch build-tapfd-get

build-switch:
	@echo "==> Building $(BINARY_NAME) ($(TARGET_ARCH))..."
	@mkdir -p $(BINDIR)
	GOOS=linux GOARCH=$(GO_ARCH) CGO_ENABLED=0 $(GO) build $(GO_BUILD_FLAGS) -o $(BINARY) ./cmd/vswitch-ctl
	$(call link_bin,$(BINARY_NAME))
	@echo "==> Built $(BINARY)"

build-tapfd-get:
	@echo "==> Building tapfd-get ($(TARGET_ARCH))..."
	@mkdir -p $(BINDIR)
	GOOS=linux GOARCH=$(GO_ARCH) CGO_ENABLED=0 $(GO) build $(GO_BUILD_FLAGS) -o $(BINDIR)/tapfd-get ./cmd/tapfd-get
	$(call link_bin,tapfd-get)
	@echo "==> Built $(BINDIR)/tapfd-get"

# Short alias matching the umbrella's collected-binary name.
tapfd-get: build-tapfd-get

# go vet across the module — parallels the other repos' `vet` target so the
# umbrella can drive every repo's checks through `$(MAKE) -C <repo> vet`.
vet:
	$(GO) vet ./...

# Remove build-generated binaries and coverage. Does NOT touch release tarballs
# (use `release-clean`) or any source; only files produced by `build`/`test`.
clean:
	@echo "==> Cleaning build artifacts..."
	rm -f bin/$(BINARY_NAME) bin/*/$(BINARY_NAME) bin/tapfd-get bin/*/tapfd-get $(COVERAGE)
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

# Run end-to-end shell tests (requires root + a BPF-capable kernel).
test-e2e: build-switch
	@echo "==> Running end-to-end tests..."
	@for t in examples/*_test.sh; do \
		echo ""; \
		echo "========================================="; \
		echo "  $$t"; \
		echo "========================================="; \
		sudo bash $$t all || exit 1; \
	done
	@echo ""
	@echo "==> All end-to-end tests passed."

# Run the performance benchmark (requires root + iperf3).
bench: build-switch
	@echo "==> Running performance benchmark..."
	sudo bash examples/perf_bench.sh all

# ---------------------------------------------------------------------------
# Release packaging
# ---------------------------------------------------------------------------
# `make release` builds for the current TARGET_ARCH and packs the binary plus
# deployment configs, examples and docs into
#   build/dist/sandbox-vswitch-$(VERSION)-linux-$(TARGET_ARCH).tar.gz
# The arch is in the tarball name, so `make release TARGET_ARCH=x86_64` and
# `... TARGET_ARCH=aarch64` produce two non-colliding tarballs.
#
# The binary is self-contained (eBPF objects are embedded), so the tarball
# carries no bpf/ sources or shared libraries.
release: build
	@echo "==> Packaging sandbox-vswitch $(VERSION) ($(TARGET_ARCH))..."
	@rm -rf $(RELEASE_DIR)/sandbox-vswitch-$(VERSION)
	@mkdir -p $(RELEASE_DIR)/sandbox-vswitch-$(VERSION)/bin \
	          $(RELEASE_DIR)/sandbox-vswitch-$(VERSION)/docs
	cp $(BINARY) $(RELEASE_DIR)/sandbox-vswitch-$(VERSION)/bin/$(BINARY_NAME)
	cp -r dist examples $(RELEASE_DIR)/sandbox-vswitch-$(VERSION)/
	cp README.md $(RELEASE_DIR)/sandbox-vswitch-$(VERSION)/
	cp docs/PROPOSAL.md $(RELEASE_DIR)/sandbox-vswitch-$(VERSION)/docs/
	@{ echo "version: $(VERSION)"; \
	   echo "arch:    $(TARGET_ARCH)"; \
	   echo "commit:  $$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"; \
	   echo "built:   $$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
	 } > $(RELEASE_DIR)/sandbox-vswitch-$(VERSION)/VERSION
	tar -C $(RELEASE_DIR) -czf \
	    $(RELEASE_DIR)/sandbox-vswitch-$(VERSION)-linux-$(TARGET_ARCH).tar.gz \
	    sandbox-vswitch-$(VERSION)
	@echo "==> Wrote $(RELEASE_DIR)/sandbox-vswitch-$(VERSION)-linux-$(TARGET_ARCH).tar.gz"

release-clean:
	@echo "==> Removing release artifacts..."
	rm -rf $(RELEASE_DIR)

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
	@echo "sandbox-vswitch make targets:"
	@echo "  all / build      - Build $(BINARY_NAME) for TARGET_ARCH (default; uses committed eBPF objects)"
	@echo "  generate         - Regenerate eBPF bytecode + Go bindings (requires clang 12+)"
	@echo "  clean            - Remove build-generated binaries + coverage (not release tarballs)"
	@echo "  test             - Run unit tests (coverage -> $(COVERAGE))"
	@echo "  test-integration - Run all tests incl. integration (requires root + BPF)"
	@echo "  test-all         - Alias for test-integration"
	@echo "  test-e2e         - Run end-to-end shell tests (requires root + BPF)"
	@echo "  bench            - Run performance benchmark (requires root + iperf3)"
	@echo "  release          - Pack binary + configs + docs into a per-arch tarball under $(RELEASE_DIR)"
	@echo "  release-clean    - Remove $(RELEASE_DIR)"
	@echo "  deps             - Check dependencies and download Go modules"
	@echo "  fmt              - Format Go and BPF C sources"
	@echo "  lint             - go vet ./..."
	@echo "  vmlinux          - Regenerate bpf/vmlinux.h from kernel BTF"
	@echo ""
	@echo "Cross-compile:     make build TARGET_ARCH=aarch64   (aliases: amd64, arm64)"
	@echo "Output layout:     bin/<arch>/$(BINARY_NAME)  (+ bin/$(BINARY_NAME) symlink on native builds)"
