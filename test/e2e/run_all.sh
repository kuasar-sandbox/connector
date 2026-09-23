#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${BIN:?BIN must point to the assembled platform binary directory}"

# Transitional verification only: the trusted platform framework is injected
# into prepared workspaces by kuasar-sandbox#173. This owner entry disappears
# when #172 performs the final suite-runner cutover.
E2E_LIB="${E2E_LIB:-$SCRIPT_DIR/../lib}"
if [ -f "$E2E_LIB/common.sh" ]; then
    privileged=()
    if [ "$(id -u)" -ne 0 ]; then privileged=(sudo -n); fi
    for case in         network.vswitch-cleanup.sh         network.geneve-ethernet.sh         network.geneve-ip.sh         network.management.sh         network.provision.sh         network.tap.sh
    do
        echo "==> connector/$case"
        "${privileged[@]}" env BIN="$BIN" E2E_LIB="$E2E_LIB"             bash "$SCRIPT_DIR/cases/$case"
    done
    exit 0
fi


SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${BIN:?BIN must point to the assembled platform binary directory}"
[ -x "$BIN/connector-ctl" ] || {
    echo "missing executable $BIN/connector-ctl" >&2
    exit 1
}

bash "$SCRIPT_DIR/notify_helpers_test.sh"

privileged=()
if [ "$(id -u)" -ne 0 ]; then
    privileged=(sudo -n)
fi

echo "==> connector missing-switch-namespace isolation regression"
"${privileged[@]}" env BIN="$BIN" bash "$SCRIPT_DIR/missing_switch_netns_test.sh"

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

