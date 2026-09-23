#!/bin/bash
# GENEVE transit test (Ether-over-GENEVE via gateway bridge)
#
# Topology:
#   sandbox1 (10.1.0.1) ──veth──> sw_ns (eBPF switch sw1)
#   sandbox2 (10.1.0.2) ──veth──>        │
#                                    sw-transit (10.0.0.1/24)
#                                        │ veth pair
#                                    gw-transit (10.0.0.2/24)
#                                        │
#                                      br-gw (bridge)
#                                     /       \
#                              geneve0         geneve1
#                           dstport=50000    dstport=50001  (for sending back to switch)
#                           VNI=100          VNI=101
#                           remote=10.0.0.1
#
# Each sandbox has a dedicated GENEVE port (no standard 6081):
#   sandbox1: geneve_port = 50000 (geneve_port_base + 0)
#   sandbox2: geneve_port = 50001 (geneve_port_base + 1)
#
# Linux GENEVE dstport sets BOTH the listen port AND send destination port.
# So geneve0 (dstport=50000) listens on UDP 50000 and sends to UDP 50000.
#
# Data flow (sandbox1 → sandbox2):
#   1. sandbox1 pings 10.1.0.2
#      → eBPF on sw-n1: no mgmt match, GENEVE encap
#        outer: src=10.0.0.1 dst=10.0.0.2, UDP src=50000 dst=50000, VNI=100
#      → transit-dev → veth → gw_ns
#   2. gw_ns: GENEVE decap via geneve0 (VNI=100, listen on 50000)
#      → inner packet on br-gw: 10.1.0.1 → 10.1.0.2
#   3. br-gw: ARP/MAC learning forwards to geneve1
#      → geneve1 encaps: dstport=50001, VNI=101, dst=10.0.0.1
#      → gw-transit → veth → transit-dev
#   4. eBPF on transit-dev: udp->dest=50001 → slot_id=1
#      → GENEVE decap, VNI=101 matches slot 1
#      → redirect to sw-n2 → sandbox2 receives
#
# Note: This test uses --geneve-encap-eth (Ether-over-GENEVE) because
# Linux GENEVE devices expect Ethernet-encapsulated inner frames.
#
# Tests:
#   1. sandbox1 → sandbox2 (10.1.0.2): IPv4 GENEVE via gateway bridge
#   2. sandbox2 → sandbox1 (10.1.0.1): IPv4 GENEVE via gateway bridge
#   3. sandbox1 → sandbox2 (fd00::2):  IPv6 GENEVE via gateway bridge
#   4. sandbox2 → sandbox1 (fd00::1):  IPv6 GENEVE via gateway bridge
#   5. sandbox1 → sandbox2 TCP (10.1.0.2:9000): TCP data transfer via GENEVE
#   6. sandbox2 → sandbox1 TCP (10.1.0.1:9000): TCP data transfer via GENEVE
#
# Environment variables:
#   TRANSIT_ADDR_MODE=auto   Use DHCP for transit device address
#   TRANSIT_ADDR_MODE=static Use static address (default)
#
# Usage:
#   sudo bash tests/geneve_test_env.sh setup
#   sudo bash tests/geneve_test_env.sh test
#   sudo bash tests/geneve_test_env.sh teardown
#   sudo bash tests/geneve_test_env.sh all    # setup + test + teardown (runs both static and auto modes)

set -euo pipefail

source "${E2E_LIB:?E2E_LIB is required}/common.sh"
require_root
require_command ip
require_command python3
require_binary connector-ctl
SWITCH_BIN="$BIN/connector-ctl vswitch"


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
TRANSIT_IP="10.0.0.1"
GW_IP="10.0.0.2"
GENEVE_PORT_BASE=50000

# Transit address mode: "static" or "auto" (DHCP)
TRANSIT_ADDR_MODE="${TRANSIT_ADDR_MODE:-static}"
DHCP_PID=""

setup() {
    echo "==> Creating network namespaces..."
    for ns in sw_ns port_ns gw_ns sandbox1 sandbox2; do
        ip netns add "$ns" 2>/dev/null || true
    done

    echo "==> Creating transit veth pair (host ↔ gw_ns)..."
    ip link add sw-transit type veth peer name gw-transit
    ip link set gw-transit netns gw_ns

    # Configure host side (will be moved into sw_ns by connector-ctl vswitch start)
    # Set MTU to accommodate port MTU (1500) + Ether-over-GENEVE overhead (64)
    # Keep the device DOWN - connector-ctl vswitch will bring it up after moving
    ip link set sw-transit mtu 1600

    # Configure gateway side
    ip netns exec gw_ns ip link set gw-transit mtu 1600
    ip netns exec gw_ns ip addr add ${GW_IP}/24 dev gw-transit
    ip netns exec gw_ns ip link set gw-transit up
    ip netns exec gw_ns ip link set lo up

    echo "==> Creating bridge in gw_ns..."
    ip netns exec gw_ns ip link add br-gw type bridge
    ip netns exec gw_ns ip link set br-gw up
    # Assign an IP to the bridge for inner traffic (optional, for debugging)
    ip netns exec gw_ns ip addr add 10.1.0.254/24 dev br-gw

    # gw-transit stays as a standalone device with IP for GENEVE underlay.
    # Do NOT add it to the bridge — GENEVE needs kernel UDP stack processing.

    echo "==> Creating GENEVE tunnel devices in gw_ns..."
    # geneve0: for sandbox1 (slot 0), dstport=50000, VNI=100
    ip netns exec gw_ns \
        ip link add geneve0 type geneve id 100 remote ${TRANSIT_IP} dstport ${GENEVE_PORT_BASE}
    ip netns exec gw_ns ip link set geneve0 master br-gw
    ip netns exec gw_ns ip link set geneve0 up

    # geneve1: for sandbox2 (slot 1), dstport=50001, VNI=101
    ip netns exec gw_ns \
        ip link add geneve1 type geneve id 101 remote ${TRANSIT_IP} dstport $((GENEVE_PORT_BASE + 1))
    ip netns exec gw_ns ip link set geneve1 master br-gw
    ip netns exec gw_ns ip link set geneve1 up

    if [ "$TRANSIT_ADDR_MODE" == "auto" ]; then
        echo "==> Starting DHCP server in gw_ns..."
        # DHCP server listens on gw-transit, serves TRANSIT_IP to clients
        ip netns exec gw_ns ${SWITCH_BIN} dhcp serve \
            --dev=gw-transit \
            --server-ip=${GW_IP} \
            --pool="${TRANSIT_IP}-${TRANSIT_IP}" \
            --gateway=${GW_IP} \
            --lease-time=1h &
        DHCP_PID=$!
        sleep 1

        if ! kill -0 "$DHCP_PID" 2>/dev/null; then
            echo "ERROR: DHCP server failed to start"
            exit 1
        fi
        echo "  DHCP server started (PID: $DHCP_PID)"
    fi

    echo "==> Starting connector-ctl vswitch..."
    if [ "$TRANSIT_ADDR_MODE" == "auto" ]; then
        TRANSIT_ADDR_ARG="--transit-dev-addr=auto"
    else
        TRANSIT_ADDR_ARG="--transit-dev-addr=${TRANSIT_IP}/24:${GW_IP}"
    fi

    ${SWITCH_BIN} start ${SW_NAME} \
        --mode=veth \
        --netns=sw_ns \
        --port-netns=port_ns \
        --ports=2 \
        --mac-addr=02:00:00:00:00:01 \
        --floating-ip-base=100.100.96.0 \
        --transit-dev=sw-transit \
        ${TRANSIT_ADDR_ARG} \
        --geneve-port-base=${GENEVE_PORT_BASE} \
        --geneve-encap-eth

    echo "==> Attaching sandbox1..."
    ${SWITCH_BIN} attach ${SW_NAME} \
        --to-netns=sandbox1 \
        --inner-ip=10.1.0.1 \
        --transit-gateway-ip=${GW_IP} \
        --transit-geneve-vni=100

    echo "==> Attaching sandbox2..."
    ${SWITCH_BIN} attach ${SW_NAME} \
        --to-netns=sandbox2 \
        --inner-ip=10.1.0.2 \
        --transit-gateway-ip=${GW_IP} \
        --transit-geneve-vni=101

    echo "==> Configuring sandbox interfaces..."
    ip netns exec sandbox1 ip addr add 10.1.0.1/24 dev sw1-p1
    ip netns exec sandbox1 ip link set sw1-p1 up
    ip netns exec sandbox1 ip route add default dev sw1-p1

    ip netns exec sandbox2 ip addr add 10.1.0.2/24 dev sw1-p2
    ip netns exec sandbox2 ip link set sw1-p2 up
    ip netns exec sandbox2 ip route add default dev sw1-p2

    # IPv6 addresses for transit test (nodad skips DAD to avoid timing issues)
    ip netns exec sandbox1 ip -6 addr add fd00::1/64 dev sw1-p1 nodad
    ip netns exec sandbox2 ip -6 addr add fd00::2/64 dev sw1-p2 nodad

    echo ""
    echo "==> Setup complete."
}

run_tests() {
    echo ""
    echo "========================================="
    echo "  Running tests"
    echo "========================================="
    echo ""

    # --- Test 1: sandbox1 → sandbox2 via IPv4 GENEVE ---
    echo "[1/6] sandbox1 → sandbox2 (10.1.0.2) via IPv4 GENEVE"
    if ip netns exec sandbox1 ping -c 2 -W 2 10.1.0.2 &>/dev/null; then
        pass "sandbox1 can reach sandbox2 via IPv4 GENEVE"
    else
        fail "sandbox1 cannot reach sandbox2 via IPv4 GENEVE"
    fi

    # --- Test 2: sandbox2 → sandbox1 via IPv4 GENEVE ---
    echo "[2/6] sandbox2 → sandbox1 (10.1.0.1) via IPv4 GENEVE"
    if ip netns exec sandbox2 ping -c 2 -W 2 10.1.0.1 &>/dev/null; then
        pass "sandbox2 can reach sandbox1 via IPv4 GENEVE"
    else
        fail "sandbox2 cannot reach sandbox1 via IPv4 GENEVE"
    fi

    # --- Test 3: sandbox1 → sandbox2 via IPv6 GENEVE ---
    echo "[3/6] sandbox1 → sandbox2 (fd00::2) via IPv6 GENEVE"
    if ip netns exec sandbox1 ping -6 -c 2 -W 2 fd00::2 &>/dev/null; then
        pass "sandbox1 can reach sandbox2 via IPv6 GENEVE"
    else
        fail "sandbox1 cannot reach sandbox2 via IPv6 GENEVE"
    fi

    # --- Test 4: sandbox2 → sandbox1 via IPv6 GENEVE ---
    echo "[4/6] sandbox2 → sandbox1 (fd00::1) via IPv6 GENEVE"
    if ip netns exec sandbox2 ping -6 -c 2 -W 2 fd00::1 &>/dev/null; then
        pass "sandbox2 can reach sandbox1 via IPv6 GENEVE"
    else
        fail "sandbox2 cannot reach sandbox1 via IPv6 GENEVE"
    fi

    # --- Test 5: sandbox1 → sandbox2 TCP data transfer ---
    echo "[5/6] sandbox1 → sandbox2 TCP (10.1.0.2:9000) via GENEVE"
    EXPECT_DATA="hello-from-sandbox1-$(date +%s)"
    # Start TCP listener in sandbox2 using Python
    ip netns exec sandbox2 python3 -c "
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.settimeout(5)
s.bind(('0.0.0.0', 9000))
s.listen(1)
try:
    conn, _ = s.accept()
    data = conn.recv(4096)
    open('/tmp/tcp_test5.out', 'wb').write(data)
    conn.close()
except: pass
s.close()
" &
    sleep 0.3
    # Send data from sandbox1
    ip netns exec sandbox1 python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3)
try:
    s.connect(('10.1.0.2', 9000))
    s.sendall(b'${EXPECT_DATA}\n')
except: pass
s.close()
" || true
    sleep 0.5
    if [ -f /tmp/tcp_test5.out ] && grep -q "${EXPECT_DATA}" /tmp/tcp_test5.out 2>/dev/null; then
        pass "sandbox1 → sandbox2 TCP data transfer via GENEVE"
    else
        fail "sandbox1 → sandbox2 TCP data transfer via GENEVE"
    fi
    rm -f /tmp/tcp_test5.out

    # --- Test 6: sandbox2 → sandbox1 TCP data transfer ---
    echo "[6/6] sandbox2 → sandbox1 TCP (10.1.0.1:9000) via GENEVE"
    EXPECT_DATA="hello-from-sandbox2-$(date +%s)"
    ip netns exec sandbox1 python3 -c "
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.settimeout(5)
s.bind(('0.0.0.0', 9000))
s.listen(1)
try:
    conn, _ = s.accept()
    data = conn.recv(4096)
    open('/tmp/tcp_test6.out', 'wb').write(data)
    conn.close()
except: pass
s.close()
" &
    sleep 0.3
    ip netns exec sandbox2 python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3)
try:
    s.connect(('10.1.0.1', 9000))
    s.sendall(b'${EXPECT_DATA}\n')
except: pass
s.close()
" || true
    sleep 0.5
    if [ -f /tmp/tcp_test6.out ] && grep -q "${EXPECT_DATA}" /tmp/tcp_test6.out 2>/dev/null; then
        pass "sandbox2 → sandbox1 TCP data transfer via GENEVE"
    else
        fail "sandbox2 → sandbox1 TCP data transfer via GENEVE"
    fi
    rm -f /tmp/tcp_test6.out

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
    echo "==> Stopping connector-ctl vswitch..."
    ${SWITCH_BIN} stop ${SW_NAME} --force --force-clean || [ $? = 3 ]

    # Kill DHCP server if running
    if [ -n "${DHCP_PID:-}" ] && kill -0 "$DHCP_PID" 2>/dev/null; then
        echo "==> Stopping DHCP server..."
        kill "$DHCP_PID" 2>/dev/null || true
        wait "$DHCP_PID" 2>/dev/null || true
    fi
    DHCP_PID=""

    echo "==> Removing transit veth..."
    ip link del sw-transit 2>/dev/null || true

    echo "==> Removing network namespaces..."
    for ns in sandbox1 sandbox2 gw_ns sw_ns port_ns; do
        ip netns del "$ns" 2>/dev/null || true
    done

    echo "==> Teardown complete."
}

reset_test_counters() {
    PASS=0
    FAIL=0
    ERRORS=""
}

echo "==> static transit address"
TRANSIT_ADDR_MODE=static
trap teardown EXIT
setup
run_tests
teardown
trap - EXIT
reset_test_counters
echo "==> automatic transit address"
TRANSIT_ADDR_MODE=auto
trap teardown EXIT
setup
run_tests
