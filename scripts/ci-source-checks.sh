#!/usr/bin/env bash
# Required source checks run outside the prepared artifact E2E workspace.
set -euo pipefail
mode="${1:---all}"
[[ "$#" -le 1 && "$mode" =~ ^--(all|ordinary|privileged)$ ]] || {
    echo "usage: ci-source-checks.sh [--ordinary|--privileged]" >&2
    exit 2
}
cd "$(dirname "${BASH_SOURCE[0]}")/.."
if [ "$mode" != --privileged ]; then
    echo "==> connector source/helper regressions"
    bash scripts/test-notify-helpers.sh
    PYTHONDONTWRITEBYTECODE=1 python3 scripts/test-source-checks.py

    echo "==> connector source unit, race and vet regressions"
    CGO_ENABLED=1 go test -race -count=1 ./pkg/vswitch ./pkg/internal/bpfmap
    CGO_ENABLED=0 go vet ./...
fi

if [ "$mode" != --ordinary ]; then
    echo "==> connector real BPF stats regressions"
    executor='env REQUIRE_CONNECTOR_STATS=1'
    if [ "$(id -u)" -ne 0 ]; then executor="sudo -n $executor"; fi
    CGO_ENABLED=1 go test -race -tags=integration -count=1 -v \
        -exec "$executor" \
        -run 'TestNativeStatsReal|TestVerifyCurrentSwitchWithRealPinnedMaps' ./pkg/vswitch
fi
