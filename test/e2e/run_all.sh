#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${BIN:?BIN must point to the prepared platform binary directory}"
[ -x "$BIN/connector-ctl" ] || {
    echo "missing executable $BIN/connector-ctl" >&2
    exit 1
}

# Transitional owner entry used only while #172 still selects component
# run_all.sh files. Product cases themselves use the final E2E_LIB contract.
# Compose the framework common helper and this candidate's data-only helpers
# from the already prepared workspace; do not build or discover source here.
FRAMEWORK_LIB="${E2E_LIB:-$SCRIPT_DIR/../lib}"
[ -r "$FRAMEWORK_LIB/common.sh" ] || {
    echo "missing prepared framework helper: common.sh" >&2
    exit 1
}
[ -d "$SCRIPT_DIR/lib" ] || {
    echo "missing prepared connector helper directory" >&2
    exit 1
}
CASE_LIB="$(mktemp -d "${TMPDIR:-/tmp}/connector-e2e-lib.XXXXXX")"
cleanup() { rm -rf "$CASE_LIB"; }
trap cleanup EXIT INT TERM
install -m 0644 "$FRAMEWORK_LIB/common.sh" "$CASE_LIB/common.sh"
mkdir -p "$CASE_LIB/connector"
cp -a "$SCRIPT_DIR/lib/." "$CASE_LIB/connector/"

privileged=()
if [ "$(id -u)" -ne 0 ]; then privileged=(sudo -n); fi
for case in \
    network.vswitch-cleanup.sh \
    network.geneve-ethernet.sh \
    network.geneve-ip.sh \
    network.management.sh \
    network.provision.sh \
    network.tap.sh
do
    echo "==> connector/$case"
    "${privileged[@]}" env BIN="$BIN" E2E_LIB="$CASE_LIB" \
        bash "$SCRIPT_DIR/cases/$case"
done
