#!/bin/bash
# IP-over-GENEVE transit test: two eBPF switches back-to-back
#
# Topology:
#   sandbox1 (10.1.0.1) ──veth──> sw_ns_a (switch sw-a, transit 10.0.0.1)
#                                        │
#                                   sw-transit-a ──veth── sw-transit-b
#                                        │
#   sandbox2 (10.1.0.2) ──veth──> sw_ns_b (switch sw-b, transit 10.0.0.2)
#
# Data flow (sandbox1 → sandbox2):
#   1. sandbox1 sends to 10.1.0.2
#      → eBPF on sw-a/sw-n1: IP-over-GENEVE encap; the configured locator
#        carries slot_id in UDP dst, VNI high bits, or the first option
#      → sw-transit-a → veth → sw-transit-b
#   2. eBPF on sw-b/sw-transit-b restores slot_id from the configured locator
#      → GENEVE decap (proto_type=ETH_P_IP), configured VNI matches slot 0
#      → redirect to sw-n1 → sandbox2 receives
#
# Return path (sandbox2 → sandbox1):
#   Same locator contract, with sw-b encapsulating and sw-a decapsulating.
#
# Tests:
#   1. sandbox1 → sandbox2 (10.1.0.2): PASS (IP-over-GENEVE)
#   2. sandbox2 → sandbox1 (10.1.0.1): PASS (IP-over-GENEVE)
#
# Usage:
#   sudo bash test/e2e/geneve_ip_test.sh setup [port|vni|tlv]
#   sudo bash test/e2e/geneve_ip_test.sh test [port|vni|tlv]
#   sudo bash test/e2e/geneve_ip_test.sh teardown [port|vni|tlv]
#   sudo bash test/e2e/geneve_ip_test.sh all [port|vni|tlv]

set -euo pipefail

if [ -n "${SWITCH_BIN:-}" ]; then
    : # Use environment variable
elif [ -x "bin/connector-ctl" ]; then
    SWITCH_BIN="bin/connector-ctl vswitch"
else
    SWITCH_BIN="/usr/sbin/connector-ctl vswitch"
fi

PASS=0
FAIL=0
ERRORS=""

pass() {
    echo "  PASS: $1"
    PASS=$((PASS + 1))
}

fail() {
    echo "  FAIL: $1"
    FAIL=$((FAIL + 1))
    ERRORS="${ERRORS}\n  - $1"
}

TRANSIT_IP_A="10.0.0.1"
TRANSIT_IP_B="10.0.0.2"
GENEVE_PORT_BASE=50000
GENEVE_LOCATOR="${2:-${GENEVE_LOCATOR:-port}}"
GENEVE_TLV_LOCATOR="0102:81"

case "$GENEVE_LOCATOR" in
    port)
        GENEVE_ARGS=(--geneve-locator=port --geneve-port-base=${GENEVE_PORT_BASE})
        EXPECTED_GENEVE_PORT=${GENEVE_PORT_BASE}
        ;;
    vni)
        GENEVE_ARGS=(--geneve-locator=vni)
        EXPECTED_GENEVE_PORT=6081
        ;;
    tlv)
        GENEVE_ARGS=(--geneve-locator=tlv --geneve-tlv-locator=${GENEVE_TLV_LOCATOR})
        EXPECTED_GENEVE_PORT=6081
        ;;
    *)
        echo "unsupported GENEVE_LOCATOR=$GENEVE_LOCATOR (want port, vni, or tlv)" >&2
        exit 1
        ;;
esac

setup() {
    echo "==> Creating network namespaces..."
    for ns in sw_ns_a port_ns_a sw_ns_b port_ns_b sandbox1 sandbox2; do
        ip netns add "$ns" 2>/dev/null || true
    done

    echo "==> Creating transit veth pair (sw-a ↔ sw-b)..."
    ip link add sw-transit-a type veth peer name sw-transit-b

    # Set MTU to accommodate port MTU (1500) + IP-over-GENEVE overhead (50)
    # Keep both devices DOWN - connector-ctl vswitch will bring them up after moving
    ip link set sw-transit-a mtu 1600
    ip link set sw-transit-b mtu 1600

    echo "==> Starting switch sw-a..."
    ${SWITCH_BIN} start sw-a \
        --mode=veth \
        --netns=sw_ns_a \
        --port-netns=port_ns_a \
        --ports=1 \
        --mac-addr=02:00:00:00:00:01 \
        --floating-ip-base=100.100.96.0 \
        --transit-dev=sw-transit-a \
        --transit-dev-addr=${TRANSIT_IP_A}/24:${TRANSIT_IP_B} \
        "${GENEVE_ARGS[@]}"

    echo "==> Starting switch sw-b..."
    ${SWITCH_BIN} start sw-b \
        --mode=veth \
        --netns=sw_ns_b \
        --port-netns=port_ns_b \
        --ports=1 \
        --mac-addr=02:00:00:00:00:02 \
        --floating-ip-base=100.100.97.0 \
        --transit-dev=sw-transit-b \
        --transit-dev-addr=${TRANSIT_IP_B}/24:${TRANSIT_IP_A} \
        "${GENEVE_ARGS[@]}"

    echo "==> Attaching sandbox1 to sw-a..."
    ${SWITCH_BIN} attach sw-a \
        --to-netns=sandbox1 \
        --inner-ip=10.1.0.1 \
        --transit-gateway-ip=${TRANSIT_IP_B} \
        --transit-geneve-vni=100

    echo "==> Attaching sandbox2 to sw-b..."
    ${SWITCH_BIN} attach sw-b \
        --to-netns=sandbox2 \
        --inner-ip=10.1.0.2 \
        --transit-gateway-ip=${TRANSIT_IP_A} \
        --transit-geneve-vni=100

    echo "==> Configuring sandbox interfaces..."
    ip netns exec sandbox1 ip addr add 10.1.0.1/24 dev sw-a-p1
    ip netns exec sandbox1 ip link set sw-a-p1 up
    ip netns exec sandbox1 ip route add default dev sw-a-p1

    ip netns exec sandbox2 ip addr add 10.1.0.2/24 dev sw-b-p1
    ip netns exec sandbox2 ip link set sw-b-p1 up
    ip netns exec sandbox2 ip route add default dev sw-b-p1

    echo ""
    echo "==> Setup complete."
}

run_tests() {
    echo ""
    echo "========================================="
    echo "  Running tests (IP-over-GENEVE, locator=${GENEVE_LOCATOR})"
    echo "========================================="
    echo ""

    # --- Test 1: observable locator configuration ---
    echo "[1/4] show config reports locator=${GENEVE_LOCATOR} and UDP ${EXPECTED_GENEVE_PORT}"
    config_json="$(${SWITCH_BIN} show config sw-a)"
    if CONFIG_JSON="$config_json" EXPECTED_LOCATOR="$GENEVE_LOCATOR" \
        EXPECTED_PORT="$EXPECTED_GENEVE_PORT" EXPECTED_TLV="$GENEVE_TLV_LOCATOR" \
        python3 - <<'PY'
import json
import os

cfg = json.loads(os.environ["CONFIG_JSON"])
assert cfg["geneve_locator"] == os.environ["EXPECTED_LOCATOR"]
assert cfg["geneve_port"] == int(os.environ["EXPECTED_PORT"])
if os.environ["EXPECTED_LOCATOR"] == "tlv":
    assert cfg["geneve_tlv_locator"] == os.environ["EXPECTED_TLV"]
PY
    then
        pass "show config reports the selected locator wire port"
    else
        fail "show config does not report the selected locator wire port"
    fi

    # --- Test 2: sandbox1 → sandbox2 ---
    echo "[2/4] sandbox1 → sandbox2 (10.1.0.2) via IP-over-GENEVE"
    if ip netns exec sandbox1 ping -c 2 -W 2 10.1.0.2 &>/dev/null; then
        pass "sandbox1 can reach sandbox2 via IP-over-GENEVE"
    else
        fail "sandbox1 cannot reach sandbox2 via IP-over-GENEVE"
    fi

    # --- Test 3: sandbox2 → sandbox1 ---
    echo "[3/4] sandbox2 → sandbox1 (10.1.0.1) via IP-over-GENEVE"
    if ip netns exec sandbox2 ping -c 2 -W 2 10.1.0.1 &>/dev/null; then
        pass "sandbox2 can reach sandbox1 via IP-over-GENEVE"
    else
        fail "sandbox2 cannot reach sandbox1 via IP-over-GENEVE"
    fi

    # --- Test 4: transit stats ---
    echo "[4/4] transit packet counters grow on both switches"
    stats_a="$(${SWITCH_BIN} stats sw-a)"
    stats_b="$(${SWITCH_BIN} stats sw-b)"
    if STATS_A="$stats_a" STATS_B="$stats_b" python3 - <<'PY'
import json
import os

for name in ("STATS_A", "STATS_B"):
    port = json.loads(os.environ[name])["ports"][0]
    assert port["transit_tx_packets"] > 0
    assert port["transit_rx_packets"] > 0
PY
    then
        pass "transit TX/RX counters increased on both switches"
    else
        fail "transit TX/RX counters did not increase on both switches"
    fi

    # --- Port stats ---
    echo ""
    echo "========================================="
    echo "  Port Stats (sw-a)"
    echo "========================================="
    printf '%s\n' "$stats_a"

    echo ""
    echo "========================================="
    echo "  Port Stats (sw-b)"
    echo "========================================="
    printf '%s\n' "$stats_b"

    # --- Summary ---
    echo ""
    echo "========================================="
    echo "  Results: ${PASS} passed, ${FAIL} failed"
    echo "========================================="
    if [ "$FAIL" -gt 0 ]; then
        echo -e "  Failures:${ERRORS}"
        echo ""
        return 1
    fi
    echo ""
}

teardown() {
    echo "==> Stopping switches..."
    ${SWITCH_BIN} stop sw-a --force --force-clean || [ $? = 3 ]
    ${SWITCH_BIN} stop sw-b --force --force-clean || [ $? = 3 ]

    echo "==> Removing transit veth..."
    ip link del sw-transit-a 2>/dev/null || true

    echo "==> Removing network namespaces..."
    for ns in sandbox1 sandbox2 sw_ns_a port_ns_a sw_ns_b port_ns_b; do
        ip netns del "$ns" 2>/dev/null || true
    done

    echo "==> Teardown complete."
}

case "${1:-}" in
    setup)    setup ;;
    test)     run_tests ;;
    teardown) teardown ;;
    all)
        trap teardown EXIT
        setup
        run_tests
        ;;
    *)
        echo "Usage: $0 {setup|test|teardown|all}"
        exit 1
        ;;
esac
