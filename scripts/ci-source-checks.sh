#!/usr/bin/env bash
# Required source checks run outside the prepared artifact E2E workspace.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
echo "==> connector source/helper regressions"
bash scripts/test-notify-helpers.sh
python3 -B scripts/test-vpp-runtime.py
python3 -B scripts/test-egress-wire.py
make -C native-deps test

echo "==> connector source unit, race and real BPF stats regressions"
CGO_ENABLED=1 go test -race -count=1 ./pkg/vswitch ./pkg/internal/bpfmap ./pkg/egress ./cmd/connector-ctl
CGO_ENABLED=1 go test -race -tags=integration -count=1 -v \
    -exec 'sudo -n env REQUIRE_CONNECTOR_STATS=1' \
    -run 'TestNativeStatsReal|TestVerifyCurrentSwitchWithRealPinnedMaps' ./pkg/vswitch
CGO_ENABLED=1 go test -race -tags=integration -count=1 -v \
    -exec 'sudo -n env REQUIRE_CONNECTOR_BPF=1' ./pkg/internal/bpf
CGO_ENABLED=1 go test -race -tags=integration -count=1 -v \
    -exec 'sudo -n env REQUIRE_CONNECTOR_EGRESS=1' -run TestLocalLink ./pkg/egress
CGO_ENABLED=0 go vet ./...
