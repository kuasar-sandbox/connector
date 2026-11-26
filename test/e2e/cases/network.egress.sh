#!/usr/bin/env bash
# e2e-requires: ["bpf-map","bpf-tc","geneve","netns"]
set -euo pipefail
source "${E2E_LIB:?}/common.sh"
require_root
require_binary connector-ctl
lib="${E2E_LIB:?}/connector/egress"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
python3 "$lib/bundle.py" extract --arch "${E2E_ARCH:?}" --bundle "$BIN/connector-egress.bundle" --runtime "$work/runtime"
bash "$lib/run.sh" "$BIN/connector-ctl" "$work/runtime" "${OUT:?}/egress"
