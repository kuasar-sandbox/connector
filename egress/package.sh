#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
build=${EGRESS_BUILD_DIR:-"$root/build/egress"}
arch=$(uname -m)
output="$root/bin/$arch/connector-egress.bundle"
mkdir -p "$build" "$(dirname "$output")"
work=$(mktemp -d "$build/package-XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
python3 "$root/egress/stage.py" --build "$build" --output "$work/runtime"
python3 "$root/scripts/egress-bundle.py" pack --arch "$arch" --runtime "$work/runtime" --bundle "$work/connector-egress.bundle"
mv "$work/connector-egress.bundle" "$output"
