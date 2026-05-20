#!/bin/bash
# vswitch-ctl Performance Benchmark
#
# Topology (same as geneve_eth_test.sh):
#   sandbox1 (10.1.0.1) ──veth──> sw_ns (eBPF switch sw1)
#   sandbox2 (10.1.0.2) ──veth──>        │
#                                    sw-transit (10.0.0.1/24)
#                                        │ veth pair
#                                    gw-transit (10.0.0.2/24)
#                                        │
#                                      br-gw (bridge)
#                                     /       \
#                              geneve0         geneve1
#
# Additionally, N "background" ports are attached to fill port density.
#
# Usage:
#   sudo bash examples/perf_bench.sh all                 # default 2 ports
#   sudo bash examples/perf_bench.sh all --ports 128      # 128 port density
#   sudo bash examples/perf_bench.sh setup --ports 1024   # setup only
#   sudo bash examples/perf_bench.sh bench                # run benchmarks only
#   sudo bash examples/perf_bench.sh teardown             # cleanup only
#
# Requirements: iperf3, netperf (optional), bpftool (optional)

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
SW_NAME="sw-bench"
TRANSIT_IP="10.0.0.1"
GW_IP="10.0.0.2"
GENEVE_PORT_BASE=50000
BENCH_DURATION=30
PING_COUNT=100
PORT_DENSITY=2          # total ports (minimum 2 for test pair)
RESULT_FILE=""          # optional JSON output path

# --- Parse arguments ---
ACTION=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        setup|bench|teardown|all)
            ACTION="$1"; shift ;;
        --ports)
            PORT_DENSITY="$2"; shift 2 ;;
        --ports=*)
            PORT_DENSITY="${1#*=}"; shift ;;
        --duration)
            BENCH_DURATION="$2"; shift 2 ;;
        --duration=*)
            BENCH_DURATION="${1#*=}"; shift ;;
        --output)
            RESULT_FILE="$2"; shift 2 ;;
        --output=*)
            RESULT_FILE="${1#*=}"; shift ;;
        *)
            echo "Unknown argument: $1"
            echo "Usage: $0 {setup|bench|teardown|all} [--ports N] [--duration S] [--output FILE]"
            exit 1 ;;
    esac
done

if [ -z "$ACTION" ]; then
    echo "Usage: $0 {setup|bench|teardown|all} [--ports N] [--duration S] [--output FILE]"
    exit 1
fi

# Ensure minimum 2 ports
if [ "$PORT_DENSITY" -lt 2 ]; then
    PORT_DENSITY=2
fi

# --- Helpers ---
has_cmd() { command -v "$1" &>/dev/null; }

# Parse iperf3 JSON output for bitrate (Gbps)
parse_iperf3_tcp_gbps() {
    python3 -c "
import json, sys
d = json.load(sys.stdin)
bps = d.get('end', {}).get('sum_received', {}).get('bits_per_second', 0)
print(f'{bps / 1e9:.2f}')
" 2>/dev/null || echo "N/A"
}

# Parse iperf3 UDP JSON output for PPS (Kpps) and throughput (Gbps)
parse_iperf3_udp() {
    python3 -c "
import json, sys
d = json.load(sys.stdin)
s = d.get('end', {}).get('sum', {})
pkts = s.get('packets', 0)
secs = s.get('seconds', 1)
bps = s.get('bits_per_second', 0)
pps = pkts / secs / 1000 if secs > 0 else 0
gbps = bps / 1e9
print(f'{gbps:.2f} {pps:.1f}')
" 2>/dev/null || echo "N/A N/A"
}

# Parse ping output for average RTT (ms)
parse_ping_rtt() {
    # Extract avg from "min/avg/max/mdev = ..." line
    awk -F'/' '/rtt min\/avg\/max/ {print $5}' 2>/dev/null || echo "N/A"
}

# Parse netperf TCP_RR for latency (us)
parse_netperf_rr() {
    # netperf TCP_RR outputs transactions/sec on last line
    python3 -c "
import sys
for line in sys.stdin:
    parts = line.strip().split()
    if len(parts) >= 1:
        last = parts
try:
    tps = float(last[-1])
    us = 1e6 / tps if tps > 0 else 0
    print(f'{us:.1f}')
except:
    print('N/A')
" 2>/dev/null || echo "N/A"
}

# --- Setup ---
setup() {
    echo "==> Setting up benchmark environment (${PORT_DENSITY} ports)..."

    echo "==> Creating network namespaces..."
    for ns in sw_ns port_ns gw_ns sandbox1 sandbox2; do
        ip netns add "$ns" 2>/dev/null || true
    done

    # Create background sandbox namespaces
    for i in $(seq 3 "$PORT_DENSITY"); do
        ip netns add "sandbox${i}" 2>/dev/null || true
    done

    echo "==> Creating transit veth pair..."
    ip link add sw-transit type veth peer name gw-transit
    ip link set gw-transit netns gw_ns

    # Keep sw-transit DOWN - vswitch-ctl will bring it up after moving
    ip link set sw-transit mtu 1600

    ip netns exec gw_ns ip link set gw-transit mtu 1600
    ip netns exec gw_ns ip addr add ${GW_IP}/24 dev gw-transit
    ip netns exec gw_ns ip link set gw-transit up
    ip netns exec gw_ns ip link set lo up

    echo "==> Creating bridge in gw_ns..."
    ip netns exec gw_ns ip link add br-gw type bridge
    ip netns exec gw_ns ip link set br-gw up
    ip netns exec gw_ns ip addr add 10.1.0.254/24 dev br-gw

    echo "==> Creating GENEVE tunnel devices in gw_ns..."
    ip netns exec gw_ns \
        ip link add geneve0 type geneve id 100 remote ${TRANSIT_IP} dstport ${GENEVE_PORT_BASE}
    ip netns exec gw_ns ip link set geneve0 master br-gw
    ip netns exec gw_ns ip link set geneve0 up

    ip netns exec gw_ns \
        ip link add geneve1 type geneve id 101 remote ${TRANSIT_IP} dstport $((GENEVE_PORT_BASE + 1))
    ip netns exec gw_ns ip link set geneve1 master br-gw
    ip netns exec gw_ns ip link set geneve1 up

    echo "==> Starting vswitch-ctl (${PORT_DENSITY} ports)..."
    ${SWITCH_BIN} start ${SW_NAME} \
        --netns=sw_ns \
        --port-netns=port_ns \
        --ports=${PORT_DENSITY} \
        --mac-addr=02:00:00:00:00:01 \
        --floating-ip-base=100.100.96.0 \
        --transit-dev=sw-transit \
        --transit-dev-addr=${TRANSIT_IP}/24:${GW_IP} \
        --geneve-port-base=${GENEVE_PORT_BASE} \
        --geneve-encap-eth

    echo "==> Attaching sandbox1 (test endpoint)..."
    ${SWITCH_BIN} attach ${SW_NAME} \
        --to-netns=sandbox1 \
        --inner-ip=10.1.0.1 \
        --transit-gateway-ip=${GW_IP} \
        --transit-geneve-vni=100

    echo "==> Attaching sandbox2 (test endpoint)..."
    ${SWITCH_BIN} attach ${SW_NAME} \
        --to-netns=sandbox2 \
        --inner-ip=10.1.0.2 \
        --transit-gateway-ip=${GW_IP} \
        --transit-geneve-vni=101

    # Attach background ports to fill density
    if [ "$PORT_DENSITY" -gt 2 ]; then
        echo "==> Attaching $((PORT_DENSITY - 2)) background ports..."
        for i in $(seq 3 "$PORT_DENSITY"); do
            ${SWITCH_BIN} attach ${SW_NAME} \
                --to-netns="sandbox${i}" \
                --inner-ip="10.1.$((i / 256)).$((i % 256))" \
                --transit-gateway-ip=${GW_IP} \
                --transit-geneve-vni=$((99 + i)) 2>/dev/null || true
        done
    fi

    echo "==> Configuring test sandbox interfaces..."
    ip netns exec sandbox1 ip addr add 10.1.0.1/24 dev ${SW_NAME}-p1
    ip netns exec sandbox1 ip link set ${SW_NAME}-p1 up
    ip netns exec sandbox1 ip route add default dev ${SW_NAME}-p1

    ip netns exec sandbox2 ip addr add 10.1.0.2/24 dev ${SW_NAME}-p2
    ip netns exec sandbox2 ip link set ${SW_NAME}-p2 up
    ip netns exec sandbox2 ip route add default dev ${SW_NAME}-p2

    # Create a direct veth pair for baseline measurement (no BPF)
    echo "==> Creating baseline veth pair..."
    ip link add bench-veth0 type veth peer name bench-veth1
    ip link set bench-veth0 netns sandbox1
    ip link set bench-veth1 netns sandbox2

    ip netns exec sandbox1 ip addr add 10.2.0.1/24 dev bench-veth0
    ip netns exec sandbox1 ip link set bench-veth0 up

    ip netns exec sandbox2 ip addr add 10.2.0.2/24 dev bench-veth1
    ip netns exec sandbox2 ip link set bench-veth1 up

    # Verify connectivity
    echo "==> Verifying GENEVE connectivity..."
    if ip netns exec sandbox1 ping -c 2 -W 3 10.1.0.2 &>/dev/null; then
        echo "    OK: sandbox1 -> sandbox2 via GENEVE"
    else
        echo "    WARN: GENEVE connectivity check failed, benchmark results may be incomplete"
    fi

    echo "==> Setup complete."
}

# --- Benchmark ---
run_bench() {
    echo ""
    echo "=== vswitch-ctl Performance Report ==="
    echo "Port density: ${PORT_DENSITY} allocated"
    echo "Encap mode: Ether-over-GENEVE"
    echo "Duration: ${BENCH_DURATION}s per test"
    echo ""

    # JSON accumulator
    local json_parts=()
    json_parts+=("\"port_density\": ${PORT_DENSITY}")
    json_parts+=("\"encap_mode\": \"ether-over-geneve\"")
    json_parts+=("\"duration\": ${BENCH_DURATION}")

    # -------------------------------------------------------
    # Phase 1: Baseline (bare veth, no BPF)
    # -------------------------------------------------------
    echo "--- Phase 1: Baseline (bare veth, no BPF) ---"

    local baseline_tcp_gbps="N/A"
    local baseline_udp_gbps="N/A"
    local baseline_udp_kpps="N/A"

    if has_cmd iperf3; then
        # Start iperf3 server in sandbox2
        ip netns exec sandbox2 iperf3 -s -p 5201 -D --pidfile /tmp/iperf3-base.pid 2>/dev/null
        sleep 0.5

        echo "  [1/2] TCP throughput (baseline)..."
        local tcp_json
        tcp_json=$(ip netns exec sandbox1 iperf3 -c 10.2.0.2 -p 5201 -t "$BENCH_DURATION" -J 2>/dev/null | tr -d '\0' || echo "{}")
        baseline_tcp_gbps=$(echo "$tcp_json" | parse_iperf3_tcp_gbps)

        echo "  [2/2] UDP 64B PPS (baseline)..."
        local udp_json
        udp_json=$(ip netns exec sandbox1 iperf3 -c 10.2.0.2 -p 5201 -u -l 64 -b 0 -t "$BENCH_DURATION" -J 2>/dev/null | tr -d '\0' || echo "{}")
        read -r baseline_udp_gbps baseline_udp_kpps <<< "$(echo "$udp_json" | parse_iperf3_udp)"

        # Stop server
        ip netns exec sandbox2 kill "$(tr -d '\0' < /tmp/iperf3-base.pid 2>/dev/null)" 2>/dev/null || true
        sleep 0.5
    else
        echo "  SKIP: iperf3 not found"
    fi

    echo "  TCP throughput:    ${baseline_tcp_gbps} Gbps"
    echo "  UDP 64B PPS:       ${baseline_udp_kpps} Kpps"
    echo ""

    json_parts+=("\"baseline\": {\"tcp_gbps\": \"${baseline_tcp_gbps}\", \"udp_gbps\": \"${baseline_udp_gbps}\", \"udp_kpps\": \"${baseline_udp_kpps}\"}")

    # -------------------------------------------------------
    # Phase 2: GENEVE path (via eBPF switch + gateway)
    # -------------------------------------------------------
    echo "--- Phase 2: GENEVE path (eBPF switch + gateway) ---"

    local geneve_tcp_gbps="N/A"
    local geneve_udp_gbps="N/A"
    local geneve_udp_kpps="N/A"
    local geneve_rtt_avg="N/A"
    local geneve_rr_us="N/A"

    if has_cmd iperf3; then
        ip netns exec sandbox2 iperf3 -s -p 5202 -D --pidfile /tmp/iperf3-geneve.pid 2>/dev/null
        sleep 0.5

        echo "  [1/4] TCP throughput (GENEVE)..."
        local tcp_json
        tcp_json=$(ip netns exec sandbox1 iperf3 -c 10.1.0.2 -p 5202 -t "$BENCH_DURATION" -J 2>/dev/null | tr -d '\0' || echo "{}")
        geneve_tcp_gbps=$(echo "$tcp_json" | parse_iperf3_tcp_gbps)

        echo "  [2/4] UDP 64B PPS (GENEVE)..."
        local udp_json
        udp_json=$(ip netns exec sandbox1 iperf3 -c 10.1.0.2 -p 5202 -u -l 64 -b 0 -t "$BENCH_DURATION" -J 2>/dev/null | tr -d '\0' || echo "{}")
        read -r geneve_udp_gbps geneve_udp_kpps <<< "$(echo "$udp_json" | parse_iperf3_udp)"

        ip netns exec sandbox2 kill "$(tr -d '\0' < /tmp/iperf3-geneve.pid 2>/dev/null)" 2>/dev/null || true
        sleep 0.5
    else
        echo "  SKIP: iperf3 not found"
    fi

    echo "  [3/4] Ping RTT (${PING_COUNT} pings)..."
    local ping_out
    ping_out=$(ip netns exec sandbox1 ping -c "$PING_COUNT" -i 0.01 10.1.0.2 2>/dev/null || echo "")
    geneve_rtt_avg=$(echo "$ping_out" | parse_ping_rtt)

    echo "  [4/4] TCP_RR latency..."
    if has_cmd netperf; then
        # Start netserver in sandbox2
        ip netns exec sandbox2 netserver -p 12865 &>/dev/null || true
        sleep 0.5
        local rr_out
        rr_out=$(ip netns exec sandbox1 netperf -H 10.1.0.2 -p 12865 -t TCP_RR -l "$BENCH_DURATION" 2>/dev/null || echo "")
        geneve_rr_us=$(echo "$rr_out" | parse_netperf_rr)
        ip netns exec sandbox2 pkill -f "netserver.*12865" 2>/dev/null || true
    else
        echo "    SKIP: netperf not found"
    fi

    echo "  TCP throughput:    ${geneve_tcp_gbps} Gbps"
    echo "  UDP 64B PPS:       ${geneve_udp_kpps} Kpps"
    echo "  Ping RTT (avg):    ${geneve_rtt_avg} ms"
    echo "  TCP_RR latency:    ${geneve_rr_us} us"
    echo ""

    json_parts+=("\"geneve\": {\"tcp_gbps\": \"${geneve_tcp_gbps}\", \"udp_gbps\": \"${geneve_udp_gbps}\", \"udp_kpps\": \"${geneve_udp_kpps}\", \"rtt_avg_ms\": \"${geneve_rtt_avg}\", \"tcp_rr_us\": \"${geneve_rr_us}\"}")

    # -------------------------------------------------------
    # Phase 3: BPF program stats
    # -------------------------------------------------------
    echo "--- Phase 3: BPF program stats ---"

    local bpf_stats_json=""
    if has_cmd bpftool; then
        # Enable BPF stats
        local prev_bpf_stats
        prev_bpf_stats=$(sysctl -n kernel.bpf_stats_enabled 2>/dev/null || echo "0")
        sysctl -qw kernel.bpf_stats_enabled=1 2>/dev/null || true

        # Snapshot before
        local before
        before=$(bpftool prog show -j 2>/dev/null || echo "[]")

        # Generate traffic for 10s
        echo "  Generating traffic for 10s..."
        if has_cmd iperf3; then
            ip netns exec sandbox2 iperf3 -s -p 5203 -D --pidfile /tmp/iperf3-bpf.pid 2>/dev/null
            sleep 0.5
            ip netns exec sandbox1 iperf3 -c 10.1.0.2 -p 5203 -t 10 >/dev/null 2>&1 || true
            ip netns exec sandbox2 kill "$(tr -d '\0' < /tmp/iperf3-bpf.pid 2>/dev/null)" 2>/dev/null || true
        else
            ip netns exec sandbox1 ping -c 100 -i 0.1 10.1.0.2 &>/dev/null || true
        fi

        # Snapshot after
        local after
        after=$(bpftool prog show -j 2>/dev/null || echo "[]")

        # Restore
        sysctl -qw kernel.bpf_stats_enabled="$prev_bpf_stats" 2>/dev/null || true

        # Calculate per-program stats
        bpf_stats_json=$(python3 -c "
import json, sys

before = json.loads('''${before}''')
after = json.loads('''${after}''')

# Build lookup by id
b_map = {p['id']: p for p in before if isinstance(p, dict)}
a_map = {p['id']: p for p in after if isinstance(p, dict)}

# BPF program names are truncated to 15 chars by the kernel:
#   tc_ingress_nx      -> tc_ingress_nx      (13, ok)
#   tc_ingress_mx      -> tc_ingress_mx      (13, ok)
#   tc_ingress_transit -> tc_ingress_tran    (18 -> 15, truncated)
# Map truncated name to display name for readability.
name_map = {
    'tc_ingress_nx':   'tc_ingress_nx',
    'tc_ingress_mx':   'tc_ingress_mx',
    'tc_ingress_tran': 'tc_ingress_transit',
}
targets = set(name_map.keys())
results = {}

# Aggregate across duplicate program instances (same name, different IDs).
# Multiple instances exist when programs are shared or from prior runs.
# We sum runs and time_ns, then compute a single avg.
for pid, prog in a_map.items():
    bpf_name = prog.get('name', '')
    if bpf_name not in targets:
        continue
    display = name_map[bpf_name]
    bp = b_map.get(pid, {})
    runs = prog.get('run_cnt', 0) - bp.get('run_cnt', 0)
    time_ns = prog.get('run_time_ns', 0) - bp.get('run_time_ns', 0)
    if display in results:
        results[display]['runs'] += runs
        results[display]['total_ns'] += time_ns
    else:
        results[display] = {'runs': runs, 'total_ns': time_ns}

for display in ['tc_ingress_nx', 'tc_ingress_transit', 'tc_ingress_mx']:
    if display not in results:
        continue
    r = results[display]
    r['avg_ns'] = round(r['total_ns'] / r['runs'], 1) if r['runs'] > 0 else 0
    print(f'  {display:25s} avg {r[\"avg_ns\"]:>8.1f} ns/run  ({r[\"runs\"]:,} runs)')

if not results:
    print('  No matching BPF programs found')

# Output JSON fragment
print('---JSON---')
print(json.dumps(results))
" 2>/dev/null || echo "  BPF stats collection failed")

    else
        echo "  SKIP: bpftool not found"
    fi
    echo ""

    # Extract JSON fragment if available
    local bpf_json_fragment="{}"
    if echo "$bpf_stats_json" | grep -qF -- '---JSON---'; then
        bpf_json_fragment=$(echo "$bpf_stats_json" | sed -n '/---JSON---/{n;p;}')
        # Print only non-JSON lines
        echo "$bpf_stats_json" | sed '/---JSON---/,$d'
    fi
    json_parts+=("\"bpf_stats\": ${bpf_json_fragment}")

    # -------------------------------------------------------
    # Phase 4: Overhead calculation
    # -------------------------------------------------------
    echo "--- Overhead ---"
    python3 -c "
baseline_tcp = '${baseline_tcp_gbps}'
geneve_tcp = '${geneve_tcp_gbps}'
baseline_pps = '${baseline_udp_kpps}'
geneve_pps = '${geneve_udp_kpps}'

try:
    bt = float(baseline_tcp)
    gt = float(geneve_tcp)
    if bt > 0:
        loss = (bt - gt) / bt * 100
        print(f'  TCP throughput loss:   {loss:.1f}%')
    else:
        print(f'  TCP throughput loss:   N/A')
except:
    print(f'  TCP throughput loss:   N/A')

try:
    bp = float(baseline_pps)
    gp = float(geneve_pps)
    if bp > 0:
        loss = (bp - gp) / bp * 100
        print(f'  PPS loss:             {loss:.1f}%')
    else:
        print(f'  PPS loss:             N/A')
except:
    print(f'  PPS loss:             N/A')
" 2>/dev/null || true
    echo ""

    # -------------------------------------------------------
    # JSON output
    # -------------------------------------------------------
    if [ -n "$RESULT_FILE" ]; then
        local json_str
        json_str=$(printf '{%s}' "$(IFS=','; echo "${json_parts[*]}")")
        echo "$json_str" | python3 -m json.tool > "$RESULT_FILE" 2>/dev/null || echo "$json_str" > "$RESULT_FILE"
        echo "Results written to: ${RESULT_FILE}"
    fi
}

# --- Teardown ---
teardown() {
    echo "==> Tearing down benchmark environment..."

    ${SWITCH_BIN} stop ${SW_NAME} 2>/dev/null || true

    ip link del sw-transit 2>/dev/null || true
    ip link del bench-veth0 2>/dev/null || true

    for ns in gw_ns sw_ns port_ns; do
        ip netns del "$ns" 2>/dev/null || true
    done

    for i in $(seq 1 "$PORT_DENSITY"); do
        ip netns del "sandbox${i}" 2>/dev/null || true
    done

    # Cleanup any leftover sandbox namespaces from previous runs with larger density
    for ns in $(ip netns list 2>/dev/null | grep -oP 'sandbox\d+' || true); do
        ip netns del "$ns" 2>/dev/null || true
    done

    rm -rf /sys/fs/bpf/${SW_NAME} 2>/dev/null || true

    # Kill any leftover iperf3/netperf
    pkill -f "iperf3.*520[1-3]" 2>/dev/null || true
    pkill -f "netserver.*12865" 2>/dev/null || true

    echo "==> Teardown complete."
}

# --- Dispatch ---
case "$ACTION" in
    setup)    setup ;;
    bench)    run_bench ;;
    teardown) teardown ;;
    all)
        trap teardown EXIT
        setup
        run_bench
        ;;
esac
