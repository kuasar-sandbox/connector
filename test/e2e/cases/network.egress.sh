#!/usr/bin/env bash
# e2e-requires: ["bpf-map","bpf-tc","geneve","netns"]
set -euo pipefail
source "${E2E_LIB:?}/common.sh"
require_root
require_binary connector-ctl
lib="${E2E_LIB:?}/connector/egress"
bash "$lib/run.sh" "$BIN/connector-ctl" "$BIN" "${OUT:?}/egress"
