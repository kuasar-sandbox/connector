#!/bin/bash
# Management plane connectivity + sandbox isolation test
#
# Topology:
#   sandbox1 (169.254.1.1) ──veth──> sw_ns (eBPF switch sw1) ──veth──> mgmt_ns (metadata svc)
#   sandbox2 (169.254.1.1) ──veth──>                                   169.254.169.254
#
# Tests:
#   1. sandbox1 → mgmt service (169.254.169.254): PASS (SNAT via floating IP)
#   2. sandbox2 → mgmt service (169.254.169.254): PASS (SNAT via floating IP)
#   3. mgmt service → sandbox1 (via floating IP):  PASS (DNAT to inner_ip)
#   4. mgmt service → sandbox2 (via floating IP):  PASS (DNAT to inner_ip)
#   5. sandbox1 → sandbox2 (169.254.1.1):          FAIL (no forwarding path)
#   6. sandbox1 → floating_ip of sandbox2:          FAIL (no forwarding path)
#
# Usage:
#   sudo bash tests/mgmt_isolation_test.sh setup
#   sudo bash tests/mgmt_isolation_test.sh test
#   sudo bash tests/mgmt_isolation_test.sh teardown
#   sudo bash tests/mgmt_isolation_test.sh all    # setup + test + teardown

set -euo pipefail

if [ -n "${SWITCH_BIN:-}" ]; then
    : # Use environment variable
elif [ -x "bin/vswitch-ctl" ]; then
    SWITCH_BIN="bin/vswitch-ctl"
else
    SWITCH_BIN="/usr/sbin/vswitch-ctl"
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

SW_NAME="sw1"
FLOATING_IP_BASE="100.100.96.0"
MGMT_IP="169.254.169.254"

setup() {
    echo "==> Creating network namespaces..."
    for ns in sw_ns port_ns mgmt_ns sandbox1 sandbox2; do
        ip netns add "$ns" 2>/dev/null || true
    done

    echo "==> Starting vswitch-ctl..."
    ${SWITCH_BIN} start ${SW_NAME} \
        --netns=sw_ns \
        --port-netns=port_ns \
        --ports=2 \
        --mac-addr=02:00:00:00:00:01 \
        --floating-ip-base=${FLOATING_IP_BASE} \
        --mgmt-extract=mgmt_ns:eth0:${MGMT_IP}

    echo "==> Attaching sandbox1..."
    ${SWITCH_BIN} attach ${SW_NAME} \
        --to-netns=sandbox1 \
        --inner-ip=169.254.1.1

    echo "==> Attaching sandbox2..."
    ${SWITCH_BIN} attach ${SW_NAME} \
        --to-netns=sandbox2 \
        --inner-ip=169.254.1.1

    echo "==> Configuring sandbox1 interface..."
    ip netns exec sandbox1 ip addr add 169.254.1.1/32 dev sw1-p1
    ip netns exec sandbox1 ip link set sw1-p1 up
    ip netns exec sandbox1 ip route add default dev sw1-p1

    echo "==> Configuring sandbox2 interface..."
    ip netns exec sandbox2 ip addr add 169.254.1.1/32 dev sw1-p2
    ip netns exec sandbox2 ip link set sw1-p2 up
    ip netns exec sandbox2 ip route add default dev sw1-p2

    echo "==> Configuring mgmt namespace..."
    ip netns exec mgmt_ns ip link set lo up

    echo ""
    echo "==> Setup complete."
}

run_tests() {
    echo ""
    echo "========================================="
    echo "  Running tests"
    echo "========================================="
    echo ""

    # --- Test 1: sandbox1 -> mgmt service ---
    echo "[1/6] sandbox1 -> mgmt service (${MGMT_IP})"
    if ip netns exec sandbox1 ping -c 2 -W 2 ${MGMT_IP} &>/dev/null; then
        pass "sandbox1 can reach mgmt service"
    else
        fail "sandbox1 cannot reach mgmt service"
    fi

    # --- Test 2: sandbox2 -> mgmt service ---
    echo "[2/6] sandbox2 -> mgmt service (${MGMT_IP})"
    if ip netns exec sandbox2 ping -c 2 -W 2 ${MGMT_IP} &>/dev/null; then
        pass "sandbox2 can reach mgmt service"
    else
        fail "sandbox2 cannot reach mgmt service"
    fi

    # --- Test 3: mgmt service -> sandbox1 via floating IP ---
    echo "[3/6] mgmt service -> sandbox1 (100.100.96.0)"
    if ip netns exec mgmt_ns ping -c 2 -W 2 100.100.96.0 &>/dev/null; then
        pass "mgmt service can reach sandbox1 via floating IP"
    else
        fail "mgmt service cannot reach sandbox1 via floating IP"
    fi

    # --- Test 4: mgmt service -> sandbox2 via floating IP ---
    echo "[4/6] mgmt service -> sandbox2 (100.100.96.1)"
    if ip netns exec mgmt_ns ping -c 2 -W 2 100.100.96.1 &>/dev/null; then
        pass "mgmt service can reach sandbox2 via floating IP"
    else
        fail "mgmt service cannot reach sandbox2 via floating IP"
    fi

    # --- Test 5: sandbox1 -> sandbox2 inner IP (must fail) ---
    echo "[5/6] sandbox1 -> sandbox2 inner IP (169.254.1.1) [expect FAIL]"
    if ip netns exec sandbox1 ping -c 2 -W 2 169.254.1.1 &>/dev/null; then
        fail "sandbox1 can reach sandbox2 inner IP (isolation broken!)"
    else
        pass "sandbox1 cannot reach sandbox2 (isolation OK)"
    fi

    # --- Test 6: sandbox1 -> sandbox2 floating IP (must fail) ---
    echo "[6/6] sandbox1 -> sandbox2 floating IP (100.100.96.1) [expect FAIL]"
    if ip netns exec sandbox1 ping -c 2 -W 2 100.100.96.1 &>/dev/null; then
        fail "sandbox1 can reach sandbox2 floating IP (isolation broken!)"
    else
        pass "sandbox1 cannot reach sandbox2 floating IP (isolation OK)"
    fi

    # --- Port stats ---
    echo ""
    echo "========================================="
    echo "  Port Stats"
    echo "========================================="
    ${SWITCH_BIN} stats ${SW_NAME}

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
    echo "==> Stopping vswitch-ctl..."
    ${SWITCH_BIN} stop ${SW_NAME} --force --force-clean || [ $? = 3 ]

    echo "==> Removing network namespaces..."
    for ns in sandbox1 sandbox2 mgmt_ns sw_ns port_ns; do
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
