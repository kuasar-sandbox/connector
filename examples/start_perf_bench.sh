#!/bin/bash
# Start() Performance Test
#
# Measures the time to start vswitch-ctl with various port counts.
# Tests the batch netns optimization effectiveness.
#
# Usage:
#   sudo bash examples/start_perf_test.sh
#   sudo bash examples/start_perf_test.sh --ports 128,256,512,1024
#
# Requirements: root privileges, network namespaces support

set -euo pipefail

# --- Binary resolution ---
if [ -n "${SWITCH_BIN:-}" ]; then
    : # Use environment variable
elif [ -x "bin/vswitch-ctl" ]; then
    SWITCH_BIN="bin/vswitch-ctl"
else
    SWITCH_BIN="/usr/sbin/vswitch-ctl"
fi

# --- Defaults ---
SW_NAME="sw-perf"
PORT_COUNTS="2,16,64,128,256,512"

# --- Parse arguments ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ports)
            PORT_COUNTS="$2"; shift 2 ;;
        --ports=*)
            PORT_COUNTS="${1#*=}"; shift ;;
        *)
            echo "Unknown argument: $1"
            echo "Usage: $0 [--ports N,N,N,...]"
            exit 1 ;;
    esac
done

# --- Helpers ---
cleanup() {
    local silent="${1:-false}"
    if [ "$silent" != "true" ]; then
        echo "==> Cleaning up..."
    fi
    ${SWITCH_BIN} stop ${SW_NAME} >/dev/null 2>&1 || true
    ip link del sw-transit >/dev/null 2>&1 || true
    ip link del sw-transit-peer >/dev/null 2>&1 || true
    for ns in sw_ns port_ns; do
        ip netns del "$ns" >/dev/null 2>&1 || true
    done
    rm -rf /sys/fs/bpf/${SW_NAME} >/dev/null 2>&1 || true
}

setup_namespaces() {
    # Create namespaces
    ip netns add sw_ns 2>/dev/null || true
    ip netns add port_ns 2>/dev/null || true

    # Create dummy transit device (kept DOWN for switch to use)
    ip link add sw-transit type veth peer name sw-transit-peer 2>/dev/null || true
    ip link set sw-transit mtu 1600
    ip link set sw-transit-peer up
    ip addr add 10.0.0.2/24 dev sw-transit-peer 2>/dev/null || true
}

run_start_test() {
    local ports="$1"
    local run="$2"
    local start_time end_time elapsed_ms

    # Clean any previous state
    ${SWITCH_BIN} stop ${SW_NAME} >/dev/null 2>&1 || true
    rm -rf /sys/fs/bpf/${SW_NAME} 2>/dev/null || true

    # Measure start time
    start_time=$(date +%s%N)

    ${SWITCH_BIN} start ${SW_NAME} \
        --netns=sw_ns \
        --port-netns=port_ns \
        --ports="${ports}" \
        --mac-addr=02:00:00:00:00:01 \
        --floating-ip-base=100.100.96.0 \
        --transit-dev=sw-transit \
        --transit-dev-addr=10.0.0.1/24:10.0.0.2 \
        --geneve-port-base=50000 \
        >/dev/null 2>&1

    end_time=$(date +%s%N)
    elapsed_ms=$(( (end_time - start_time) / 1000000 ))

    echo "${elapsed_ms}"
}

# --- Main ---
trap cleanup EXIT

echo "=== vswitch-ctl Start() Performance Test ==="
echo "Binary: ${SWITCH_BIN}"
echo ""

# Setup
cleanup "true"
setup_namespaces

echo "Port Count | Run 1 (ms) | Run 2 (ms) | Run 3 (ms) | Avg (ms) | ms/port"
echo "-----------|------------|------------|------------|----------|--------"

IFS=',' read -ra COUNTS <<< "$PORT_COUNTS"
results=()

for count in "${COUNTS[@]}"; do
    count=$(echo "$count" | tr -d ' ')

    # Run 3 times for average
    t1=$(run_start_test "$count" "1")
    t2=$(run_start_test "$count" "2")
    t3=$(run_start_test "$count" "3")

    # Calculate average
    avg=$(( (t1 + t2 + t3) / 3 ))
    per_port=$(echo "scale=2; $avg / $count" | bc)

    printf "%10s | %10s | %10s | %10s | %8s | %s\n" \
        "$count" "$t1" "$t2" "$t3" "$avg" "$per_port"

    results+=("{\"ports\": $count, \"times_ms\": [$t1, $t2, $t3], \"avg_ms\": $avg, \"ms_per_port\": $per_port}")
done

echo ""
echo "=== JSON Results ==="
echo "["
for i in "${!results[@]}"; do
    if [ $i -eq $((${#results[@]} - 1)) ]; then
        echo "  ${results[$i]}"
    else
        echo "  ${results[$i]},"
    fi
done
echo "]"
