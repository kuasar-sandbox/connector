# Native dependencies use the same staged workflow as Sandboxer and Guest Runtime.
SHELL := /bin/bash
.DEFAULT_GOAL := build

HOST_ARCH := $(shell uname -m)
TARGET_ARCH ?= $(HOST_ARCH)
ifeq ($(TARGET_ARCH),amd64)
  override TARGET_ARCH := x86_64
endif
ifeq ($(TARGET_ARCH),arm64)
  override TARGET_ARCH := aarch64
endif
ifeq ($(filter $(TARGET_ARCH),x86_64 aarch64),)
  $(error unsupported TARGET_ARCH=$(TARGET_ARCH); supported: x86_64, aarch64)
endif

BINDIR ?= $(abspath ../bin/$(TARGET_ARCH))
BUILD_DIR ?= $(abspath build/$(TARGET_ARCH))
TARBALL_CACHE ?= $(abspath build/tarball)
VPP_BUILD_SRC ?= $(abspath build/src/vpp)
VPP_BUILD_OUT ?= $(BUILD_DIR)/vpp
VPP_PATCHES_DIR := $(abspath deps/vpp-patches)
VPP_TARBALL ?= $(shell python3 -c 'import json; print(json.load(open("deps/vpp-source.json"))["tarball"])')
VPP_TARBALL_SHA256 ?= $(shell python3 -c 'import json; print(json.load(open("deps/vpp-source.json"))["tarball_sha256"])')

VPP_INVOKE = TARGET_ARCH="$(TARGET_ARCH)" BINDIR="$(abspath $(BINDIR))" \
	BUILD_DIR="$(abspath $(BUILD_DIR))" TARBALL_CACHE="$(abspath $(TARBALL_CACHE))" \
	VPP_BUILD_SRC="$(abspath $(VPP_BUILD_SRC))" VPP_BUILD_OUT="$(abspath $(VPP_BUILD_OUT))" \
	VPP_PATCHES_DIR="$(VPP_PATCHES_DIR)" VPP_TARBALL="$(VPP_TARBALL)" \
	VPP_TARBALL_SHA256="$(VPP_TARBALL_SHA256)"

.PHONY: all build vpp vpp-fetch vpp-patches-apply vpp-patches vpp-patches-format vpp-build test clean help
all: build
build: vpp

vpp-fetch:
	STAGE=fetch $(VPP_INVOKE) bash deps/build-vpp.sh
vpp-patches-apply: vpp-fetch
	STAGE=patches-apply $(VPP_INVOKE) bash deps/build-vpp.sh
vpp-patches: vpp-patches-apply
vpp-patches-format:
	STAGE=patches-format $(VPP_INVOKE) bash deps/build-vpp.sh
vpp-build:
	STAGE=build $(VPP_INVOKE) bash deps/build-vpp.sh
vpp: vpp-patches-apply
	STAGE=build $(VPP_INVOKE) bash deps/build-vpp.sh

test:
	bash -n deps/*.sh
	python3 -m unittest discover -s tests -p 'test_*.py'

# Keep the imported source and download cache, including any developer work.
clean:
	rm -rf "$(VPP_BUILD_OUT)"
	rm -f "$(BINDIR)/connector-vpp" "$(BINDIR)/vpp-runtime.json"

help:
	@echo 'vpp                 Build static connector-vpp in ../bin/<arch>'
	@echo 'vpp-fetch           Fetch and verify the pinned source archive'
	@echo 'vpp-patches-apply   Apply the maintained git-format patch series'
	@echo 'vpp-patches-format Export committed source changes as patches'
	@echo 'vpp-build           Build a source tree matching the maintained patches'
	@echo 'TARGET_ARCH=x86_64|aarch64; KUASAR_BUILD_JOBS=<positive integer>'
