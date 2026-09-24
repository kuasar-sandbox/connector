#!/usr/bin/env bash
# Required source checks run outside the prepared artifact E2E workspace.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
echo "==> connector source/helper regressions"
bash scripts/test-notify-helpers.sh

echo "==> connector source unit, race and real BPF stats regressions"
CGO_ENABLED=1 go test -race -count=1 ./pkg/vswitch ./pkg/internal/bpfmap
CGO_ENABLED=1 go test -race -tags=integration -count=1 -v \
    -exec 'sudo -n env REQUIRE_CONNECTOR_STATS=1' \
    -run 'TestNativeStatsReal|TestVerifyCurrentSwitchWithRealPinnedMaps' ./pkg/vswitch
CGO_ENABLED=0 go vet ./...
