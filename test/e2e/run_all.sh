#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${BIN:?BIN must point to the assembled platform binary directory}"
[ -x "$BIN/connector-ctl" ] || {
    echo "missing executable $BIN/connector-ctl" >&2
    exit 1
}

privileged=()
if [ "$(id -u)" -ne 0 ]; then
    privileged=(sudo -n)
fi

for script in \
    geneve_eth_test.sh \
    mgmt_isolation_test.sh \
    provision_test.sh \
    tap_test.sh
do
    echo
    echo "========================================="
    echo "  connector/$script"
    echo "========================================="
    "${privileged[@]}" env \
        REQUIRE_CONNECTOR_E2E=1 \
        SWITCH_BIN="$BIN/connector-ctl vswitch" \
        bash "$SCRIPT_DIR/$script" all
done

for locator in port vni tlv; do
    echo
    echo "========================================="
    echo "  connector/geneve_ip_test.sh ($locator locator)"
    echo "========================================="
    "${privileged[@]}" env \
        REQUIRE_CONNECTOR_E2E=1 \
        GENEVE_LOCATOR="$locator" \
        SWITCH_BIN="$BIN/connector-ctl vswitch" \
        bash "$SCRIPT_DIR/geneve_ip_test.sh" all
done
