#!/bin/bash
# Management plane connectivity + sandbox isolation test
#
# Topology:
#   sandbox1 (169.254.1.1) ──veth──> sw_ns (eBPF switch sw1) ──veth──> mgmt_ns (metadata svc)
#   sandbox2 (169.254.1.1) ──veth──>                                   169.254.169.254
#                                                                        (assigned by this test)
#
# Tests:
#   1. sandbox1 → mgmt service (169.254.169.254): PASS (SNAT via floating IP)
#   2. sandbox2 → mgmt service (169.254.169.254): PASS (SNAT via floating IP)
#   3. mgmt service → sandbox1 (via floating IP):  PASS (DNAT to inner_ip)
#   4. mgmt service → sandbox2 (via floating IP):  PASS (DNAT to inner_ip)
#   5. sandbox1 → sandbox2 (169.254.1.1):          FAIL (no forwarding path)
#   6. sandbox1 → floating_ip of sandbox2:          FAIL (no forwarding path)
#   7. sandbox1 → VIP:80 (--mgmt-service):          PASS (DNAT to 127.0.0.1:18080
#                                                    + reverse SNAT back to VIP:80)
#
# Test 7 covers --mgmt-service: a sandbox TCP connection to 169.254.169.254:80 is
# translated to a backend listening on 127.0.0.1:18080 in mgmt_ns. A successful
# TCP handshake proves BOTH directions of the service NAT: the forward DNAT
# (VIP:80 → 127.0.0.1:18080) and the reverse SNAT (127.0.0.1:18080 → VIP:80) —
# without the reverse rewrite, the SYN-ACK source would not match the sandbox's
# connection tuple and the handshake would be RST. The loopback backend requires
# route_localnet=1 on the mgmt device, which this test sets (the tool does not).
#
# Usage:
#   sudo bash tests/mgmt_isolation_test.sh setup
#   sudo bash tests/mgmt_isolation_test.sh test
#   sudo bash tests/mgmt_isolation_test.sh teardown
#   sudo bash tests/mgmt_isolation_test.sh all    # setup + test + teardown

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

SW_NAME="sw1"
FLOATING_IP_BASE="100.100.96.0"
MGMT_IP="169.254.169.254"

# --mgmt-service test parameters: sandbox connects to ${SVC_VIP}:${SVC_VPORT},
# which is translated to a backend on ${SVC_TARGET}:${SVC_TARGET_PORT} in mgmt_ns.
# SVC_VIP must fall within the --mgmt-extract route (reuse MGMT_IP here).
SVC_VIP="${MGMT_IP}"
SVC_VPORT="80"
SVC_TARGET="127.0.0.1"
SVC_TARGET_PORT="18080"
SVC_MGMT_DEV="eth0"               # mgmt-side peer in mgmt_ns (from --mgmt-extract=mgmt_ns:eth0:...)
SVC_PIDFILE="/tmp/mgmt_svc_test_server.pid"

setup() {
    echo "==> Creating network namespaces..."
    for ns in sw_ns port_ns mgmt_ns sandbox1 sandbox2; do
        ip netns add "$ns" 2>/dev/null || true
    done

    echo "==> Starting connector-ctl vswitch..."
    ${SWITCH_BIN} start ${SW_NAME} \
        --mode=veth \
        --netns=sw_ns \
        --port-netns=port_ns \
        --ports=2 \
        --mac-addr=02:00:00:00:00:01 \
        --floating-ip-base=${FLOATING_IP_BASE} \
        --mgmt-extract=mgmt_ns:eth0:${MGMT_IP} \
        --mgmt-service=${SVC_VIP}:${SVC_VPORT}:${SVC_TARGET}:${SVC_TARGET_PORT}

    echo "==> Verifying extraction setup before management address assignment..."
    local ipv4_addrs
    ipv4_addrs="$(ip netns exec mgmt_ns ip -4 -o addr show dev "${SVC_MGMT_DEV}")"
    if [ -n "${ipv4_addrs}" ]; then
        echo "ERROR: connector assigned an IPv4 address to ${SVC_MGMT_DEV}: ${ipv4_addrs}" >&2
        return 1
    fi

    local return_route
    return_route="$(ip netns exec mgmt_ns ip -4 -o route show "${FLOATING_IP_BASE}/20")"
    if [[ "${return_route}" != *"dev ${SVC_MGMT_DEV}"* || "${return_route}" != *"metric 100"* ]]; then
        echo "ERROR: floating-IP return route is missing: ${return_route:-<empty>}" >&2
        return 1
    fi

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
    ip netns exec mgmt_ns ip addr replace "${MGMT_IP}/32" dev "${SVC_MGMT_DEV}"

    echo "==> Enabling route_localnet for loopback --mgmt-service backend..."
    # Required so the mgmt netns accepts the DNAT'd packet (dst=127.0.0.1) on a
    # non-lo device and lets the reply (src=127.0.0.1) leave it. The vswitch tool
    # deliberately does not touch this sysctl; deployment (here, the test) does.
    ip netns exec mgmt_ns sysctl -qw "net.ipv4.conf.${SVC_MGMT_DEV}.route_localnet=1"
    ip netns exec mgmt_ns sysctl -qw "net.ipv4.conf.all.route_localnet=1"

    echo "==> Starting --mgmt-service backend (${SVC_TARGET}:${SVC_TARGET_PORT} in mgmt_ns)..."
    if command -v python3 &>/dev/null; then
        ip netns exec mgmt_ns python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("'"${SVC_TARGET}"'", '"${SVC_TARGET_PORT}"'))
s.listen(8)
while True:
    c, _ = s.accept()
    try:
        c.sendall(b"OK\n")
    finally:
        c.close()
' &
        echo $! > "${SVC_PIDFILE}"
        # Give the listener a moment to bind.
        sleep 0.5
    else
        if [ "${REQUIRE_CONNECTOR_E2E:-0}" = "1" ]; then
            fail "python3 not found — service NAT backend is required"
        fi
        echo "    python3 not found — service NAT backend skipped (test 7 will SKIP)"
    fi

    echo ""
    echo "==> Setup complete."
}

run_tests() {
    echo ""
    echo "========================================="
    echo "  Running tests"
    echo "========================================="
    echo ""

    # Before other traffic, compare distinct UDP payload sizes with both
    # sandbox-view counters at the existing service management observation.
    if python3 "$(dirname "${BASH_SOURCE[0]}")/stats_management.py" \
        "$SWITCH_BIN" "$SW_NAME" "$SVC_VIP" "$SVC_VPORT" "$SVC_TARGET" "$SVC_TARGET_PORT"; then
        pass "management stats preserve sandbox RX/TX direction and exact frame bytes"
    else
        fail "management stats direction or byte observation mismatch"
    fi

    # --- Test 1: sandbox1 -> mgmt service ---
    echo "[1/7] sandbox1 -> mgmt service (${MGMT_IP})"
    if ip netns exec sandbox1 ping -c 2 -W 2 ${MGMT_IP} &>/dev/null; then
        pass "sandbox1 can reach mgmt service"
    else
        fail "sandbox1 cannot reach mgmt service"
    fi

    # --- Test 2: sandbox2 -> mgmt service ---
    echo "[2/7] sandbox2 -> mgmt service (${MGMT_IP})"
    if ip netns exec sandbox2 ping -c 2 -W 2 ${MGMT_IP} &>/dev/null; then
        pass "sandbox2 can reach mgmt service"
    else
        fail "sandbox2 cannot reach mgmt service"
    fi

    # --- Test 3: mgmt service -> sandbox1 via floating IP ---
    echo "[3/7] mgmt service -> sandbox1 (100.100.96.0)"
    if ip netns exec mgmt_ns ping -c 2 -W 2 100.100.96.0 &>/dev/null; then
        pass "mgmt service can reach sandbox1 via floating IP"
    else
        fail "mgmt service cannot reach sandbox1 via floating IP"
    fi

    # --- Test 4: mgmt service -> sandbox2 via floating IP ---
    echo "[4/7] mgmt service -> sandbox2 (100.100.96.1)"
    if ip netns exec mgmt_ns ping -c 2 -W 2 100.100.96.1 &>/dev/null; then
        pass "mgmt service can reach sandbox2 via floating IP"
    else
        fail "mgmt service cannot reach sandbox2 via floating IP"
    fi

    # --- Test 5: sandbox1 -> sandbox2 inner IP (must fail) ---
    echo "[5/7] sandbox1 -> sandbox2 inner IP (169.254.1.1) [expect blocked]"
    if ip netns exec sandbox1 ping -c 2 -W 2 169.254.1.1 &>/dev/null; then
        fail "sandbox1 can reach sandbox2 inner IP (isolation broken!)"
    else
        pass "sandbox1 cannot reach sandbox2 (isolation OK)"
    fi

    # --- Test 6: sandbox1 -> sandbox2 floating IP (must fail) ---
    echo "[6/7] sandbox1 -> sandbox2 floating IP (100.100.96.1) [expect blocked]"
    if ip netns exec sandbox1 ping -c 2 -W 2 100.100.96.1 &>/dev/null; then
        fail "sandbox1 can reach sandbox2 floating IP (isolation broken!)"
    else
        pass "sandbox1 cannot reach sandbox2 floating IP (isolation OK)"
    fi

    # --- Test 7: sandbox1 -> VIP:vport (--mgmt-service) ---
    echo "[7/7] sandbox1 -> ${SVC_VIP}:${SVC_VPORT} (--mgmt-service -> ${SVC_TARGET}:${SVC_TARGET_PORT})"
    if ! command -v python3 &>/dev/null; then
        if [ "${REQUIRE_CONNECTOR_E2E:-0}" = "1" ]; then
            fail "python3 unavailable, cannot run service NAT backend"
        fi
        echo "  SKIP: python3 unavailable, cannot run service NAT backend"
    elif ip netns exec sandbox1 timeout -k 2s 5 bash -c '
        exec 3<>/dev/tcp/'"${SVC_VIP}"'/'"${SVC_VPORT}"' || exit 1
        read -t 3 resp <&3
        [ "$resp" = "OK" ]
    ' &>/dev/null; then
        # A completed TCP handshake + payload proves forward DNAT AND reverse SNAT
        # (the SYN-ACK source was rewritten back to VIP:vport, else it would RST).
        pass "sandbox1 reached backend via service VIP (fwd DNAT + reverse SNAT OK)"
    else
        fail "sandbox1 could not reach backend via service VIP:${SVC_VPORT}"
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
    echo "==> Stopping --mgmt-service backend..."
    if [ -f "${SVC_PIDFILE}" ]; then
        kill "$(cat "${SVC_PIDFILE}")" 2>/dev/null || true
        rm -f "${SVC_PIDFILE}"
    fi

    echo "==> Stopping connector-ctl vswitch..."
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
