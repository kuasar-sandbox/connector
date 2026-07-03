#!/bin/bash
# Control-plane E2E test: provision / reserve / serve / stop --force
#
# Topology: sw_ns + port_ns + sandbox1 (minimal, no transit, no GENEVE)
#   - Group E/C/D/A: 4 ports
#   - Group B: 16 ports (provision batch/partial/specific)
#
# Usage:
#   sudo bash examples/provision_test.sh setup
#   sudo bash examples/provision_test.sh test
#   sudo bash examples/provision_test.sh teardown
#   sudo bash examples/provision_test.sh all    # setup + test + teardown

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
SERVE_PID=""

# --- JSON helpers (python3, no jq dependency) ---

count_slots_by_ip() {
    local ip="$1"
    ${SWITCH_BIN} show slots ${SW_NAME} | python3 -c "
import json, sys
slots = json.load(sys.stdin)
print(sum(1 for s in slots if s['inner_ip'] == '${ip}'))
"
}

get_slot_field() {
    local slot_id="$1"
    local field="$2"
    ${SWITCH_BIN} show slots ${SW_NAME} ${slot_id} | python3 -c "
import json, sys
slots = json.load(sys.stdin)
print(slots[0]['${field}'])
"
}

json_field() {
    local json_str="$1"
    local field="$2"
    echo "${json_str}" | python3 -c "
import json, sys
data = json.load(sys.stdin)
print(data['${field}'])
"
}

# --- Switch lifecycle helpers ---

start_switch() {
    local num_ports="${1:-4}"
    ${SWITCH_BIN} start ${SW_NAME} \
        --mode=veth \
        --netns=sw_ns \
        --port-netns=port_ns \
        --ports=${num_ports} \
        --mac-addr=02:00:00:00:00:01 \
        --floating-ip-base=100.100.96.0 > /dev/null
}

start_switch_reserved() {
    local num_ports="${1:-16}"
    ${SWITCH_BIN} start ${SW_NAME} \
        --mode=veth \
        --netns=sw_ns \
        --port-netns=port_ns \
        --ports=${num_ports} \
        --mac-addr=02:00:00:00:00:01 \
        --floating-ip-base=100.100.96.0 \
        --reserved > /dev/null
}

stop_switch() {
    ${SWITCH_BIN} stop ${SW_NAME} --force --force-clean || [ $? = 3 ]
}

wait_switch_ready() {
    local max_wait=30
    local i=0
    while [ $i -lt $max_wait ]; do
        if ${SWITCH_BIN} status ${SW_NAME} --ready &>/dev/null; then
            return 0
        fi
        sleep 1
        i=$((i + 1))
    done
    echo "  ERROR: switch not ready after ${max_wait}s"
    return 1
}

recreate_namespaces() {
    for ns in sw_ns port_ns sandbox1; do
        ip netns del "$ns" 2>/dev/null || true
        ip netns add "$ns"
    done
}

# --- Setup / Teardown ---

setup() {
    echo "==> Creating network namespaces..."
    for ns in sw_ns port_ns sandbox1; do
        ip netns add "$ns" 2>/dev/null || true
    done
    echo "==> Setup complete."
}

teardown() {
    echo "==> Teardown..."
    # Kill any lingering serve process
    if [ -n "${SERVE_PID:-}" ] && kill -0 "$SERVE_PID" 2>/dev/null; then
        kill "$SERVE_PID" 2>/dev/null || true
        wait "$SERVE_PID" 2>/dev/null || true
    fi
    pkill -f "connector-ctl vswitch serve ${SW_NAME}" 2>/dev/null || true
    ${SWITCH_BIN} stop ${SW_NAME} --force --force-clean || [ $? = 3 ]
    for ns in sandbox1 sw_ns port_ns; do
        ip netns del "$ns" 2>/dev/null || true
    done
    rm -f /tmp/test-notify-data /tmp/test-notify-*.sock 2>/dev/null || true
    echo "==> Teardown complete."
}

# =========================================================================
#  Group E: Backward compatibility (baseline)
# =========================================================================

test_e1_start_attach_detach_stop() {
    echo "[E1] start → attach → detach → stop"
    start_switch 4

    # All 4 slots should be Free (inner_ip == 0.0.0.0)
    local free_count
    free_count=$(count_slots_by_ip "0.0.0.0")
    if [ "$free_count" -eq 4 ]; then
        pass "E1: 4 slots Free after start"
    else
        fail "E1: expected 4 Free slots, got ${free_count}"
    fi

    # Attach
    local attach_out
    attach_out=$(${SWITCH_BIN} attach ${SW_NAME} \
        --to-netns=sandbox1 \
        --inner-ip=169.254.1.1)
    local port
    port=$(json_field "$attach_out" "port")
    if [ -n "$port" ] && [ "$port" -gt 0 ]; then
        pass "E1: attach succeeded (port=${port})"
    else
        fail "E1: attach failed"
        stop_switch
        return
    fi

    # Verify slot is allocated
    local slot_ip
    slot_ip=$(get_slot_field $((port - 1)) "inner_ip")
    if [ "$slot_ip" = "169.254.1.1" ]; then
        pass "E1: slot allocated with correct inner_ip"
    else
        fail "E1: expected inner_ip=169.254.1.1, got ${slot_ip}"
    fi

    # Detach
    if ${SWITCH_BIN} detach ${SW_NAME} --port=${port} --from-netns=sandbox1 &>/dev/null; then
        pass "E1: detach succeeded"
    else
        fail "E1: detach failed"
    fi

    # Verify slot is Free again
    slot_ip=$(get_slot_field $((port - 1)) "inner_ip")
    if [ "$slot_ip" = "0.0.0.0" ]; then
        pass "E1: slot restored to Free after detach"
    else
        fail "E1: expected inner_ip=0.0.0.0 after detach, got ${slot_ip}"
    fi

    stop_switch
}

# =========================================================================
#  Group B: start --reserved + provision (16 ports)
# =========================================================================

test_b1_start_reserved_all() {
    echo "[B1] start --reserved → all Reserved"
    start_switch_reserved 16

    local reserved_count
    reserved_count=$(count_slots_by_ip "255.255.255.255")
    if [ "$reserved_count" -eq 16 ]; then
        pass "B1: 16 slots Reserved after start --reserved"
    else
        fail "B1: expected 16 Reserved slots, got ${reserved_count}"
    fi

    # Attach should fail (no Free slot)
    if ${SWITCH_BIN} attach ${SW_NAME} --to-netns=sandbox1 --inner-ip=169.254.1.1 &>/dev/null; then
        fail "B1: attach should fail with no Free slots"
    else
        pass "B1: attach correctly refused (no Free slot)"
    fi

    stop_switch
}

test_b2_provision_count() {
    echo "[B2] provision --count=4 partial"
    start_switch_reserved 16

    local prov_out
    prov_out=$(${SWITCH_BIN} provision ${SW_NAME} --count=4 --mode=veth)
    local provisioned
    provisioned=$(json_field "$prov_out" "provisioned")
    if [ "$provisioned" -eq 4 ]; then
        pass "B2: provisioned == 4"
    else
        fail "B2: expected provisioned=4, got ${provisioned}"
    fi

    local free_count reserved_count
    free_count=$(count_slots_by_ip "0.0.0.0")
    reserved_count=$(count_slots_by_ip "255.255.255.255")
    if [ "$free_count" -eq 4 ] && [ "$reserved_count" -eq 12 ]; then
        pass "B2: 4 Free + 12 Reserved"
    else
        fail "B2: expected 4 Free + 12 Reserved, got ${free_count} Free + ${reserved_count} Reserved"
    fi

    # Attach should succeed on a Free slot
    if ${SWITCH_BIN} attach ${SW_NAME} --to-netns=sandbox1 --inner-ip=169.254.1.1 &>/dev/null; then
        pass "B2: attach succeeded on provisioned slot"
    else
        fail "B2: attach failed on provisioned slot"
    fi

    stop_switch
}

test_b3_provision_all() {
    echo "[B3] provision all"
    start_switch_reserved 16

    local prov_out
    prov_out=$(${SWITCH_BIN} provision ${SW_NAME} --mode=veth)
    local provisioned
    provisioned=$(json_field "$prov_out" "provisioned")
    if [ "$provisioned" -eq 16 ]; then
        pass "B3: provisioned == 16"
    else
        fail "B3: expected provisioned=16, got ${provisioned}"
    fi

    local free_count
    free_count=$(count_slots_by_ip "0.0.0.0")
    if [ "$free_count" -eq 16 ]; then
        pass "B3: all 16 slots Free"
    else
        fail "B3: expected 16 Free, got ${free_count}"
    fi

    stop_switch
}

test_b4_provision_port() {
    echo "[B4] provision --port=10"
    start_switch_reserved 16

    local prov_out
    prov_out=$(${SWITCH_BIN} provision ${SW_NAME} --port=10 --mode=veth)
    local provisioned
    provisioned=$(json_field "$prov_out" "provisioned")
    if [ "$provisioned" -eq 1 ]; then
        pass "B4: provisioned == 1"
    else
        fail "B4: expected provisioned=1, got ${provisioned}"
    fi

    # slot 9 (port 10, 0-based index) should be Free
    local slot_ip
    slot_ip=$(get_slot_field 9 "inner_ip")
    if [ "$slot_ip" = "0.0.0.0" ]; then
        pass "B4: slot 9 (port 10) is Free"
    else
        fail "B4: expected slot 9 inner_ip=0.0.0.0, got ${slot_ip}"
    fi

    # All other 15 slots should be Reserved
    local reserved_count
    reserved_count=$(count_slots_by_ip "255.255.255.255")
    if [ "$reserved_count" -eq 15 ]; then
        pass "B4: 15 slots still Reserved"
    else
        fail "B4: expected 15 Reserved, got ${reserved_count}"
    fi

    stop_switch
}

# =========================================================================
#  Group C: reserve / reserve --force
# =========================================================================

test_c1_reserve_free_port() {
    echo "[C1] reserve isolates Free port"
    start_switch 4

    if ${SWITCH_BIN} reserve ${SW_NAME} --port=1 &>/dev/null; then
        pass "C1: reserve port 1 succeeded"
    else
        fail "C1: reserve port 1 failed"
        stop_switch
        return
    fi

    # slot 0 (port 1) should be Reserved
    local slot_ip
    slot_ip=$(get_slot_field 0 "inner_ip")
    if [ "$slot_ip" = "255.255.255.255" ]; then
        pass "C1: slot 0 is Reserved"
    else
        fail "C1: expected inner_ip=255.255.255.255, got ${slot_ip}"
    fi

    # Normal attach to port 1 should fail
    if ${SWITCH_BIN} attach ${SW_NAME} --inner-ip=169.254.1.1 --port=1 &>/dev/null; then
        fail "C1: attach to Reserved port should fail"
    else
        pass "C1: attach to Reserved port correctly refused"
    fi

    stop_switch
}

test_c2_reserve_already_reserved() {
    echo "[C2] reserve on already Reserved port fails"
    start_switch_reserved 4

    if ${SWITCH_BIN} reserve ${SW_NAME} --port=1 &>/dev/null; then
        fail "C2: reserve on already Reserved port should fail"
    else
        pass "C2: reserve on already Reserved port correctly refused"
    fi

    stop_switch
}

test_c3_force_reserve_repair() {
    echo "[C3] reserve --force + provision (idempotent) + attach/detach --skip-device"
    start_switch 4

    # 1. Attach port 2 to sandbox1
    if ! ${SWITCH_BIN} attach ${SW_NAME} --to-netns=sandbox1 --inner-ip=169.254.1.1 --port=2 &>/dev/null; then
        fail "C3: initial attach port 2 failed"
        stop_switch
        return
    fi
    pass "C3: attach port 2 succeeded"

    # 2. Force-reserve port 2 (veth still exists — not deleted)
    if ${SWITCH_BIN} reserve ${SW_NAME} --port=2 --force &>/dev/null; then
        pass "C3: force-reserve port 2 succeeded"
    else
        fail "C3: force-reserve port 2 failed"
        stop_switch
        return
    fi

    # slot 1 should be Reserved
    local slot_ip
    slot_ip=$(get_slot_field 1 "inner_ip")
    if [ "$slot_ip" = "255.255.255.255" ]; then
        pass "C3: slot 1 is Reserved after force-reserve"
    else
        fail "C3: expected inner_ip=255.255.255.255, got ${slot_ip}"
    fi

    # 3. Provision port 2 — detects veth exists, validates ifindex/TC, skips creation
    if ${SWITCH_BIN} provision ${SW_NAME} --port=2 --mode=veth &>/dev/null; then
        pass "C3: provision port 2 succeeded (idempotent)"
    else
        fail "C3: provision port 2 failed"
        stop_switch
        return
    fi

    slot_ip=$(get_slot_field 1 "inner_ip")
    if [ "$slot_ip" = "0.0.0.0" ]; then
        pass "C3: slot 1 restored to Free after provision"
    else
        fail "C3: expected inner_ip=0.0.0.0 after provision, got ${slot_ip}"
    fi

    # 4. Attach --skip-device (pure BPF slot operation, device stays in sandbox1)
    if ${SWITCH_BIN} attach ${SW_NAME} --skip-device --port=2 --inner-ip=169.254.2.1 &>/dev/null; then
        pass "C3: attach --skip-device port 2 succeeded"
    else
        fail "C3: attach --skip-device port 2 failed"
        stop_switch
        return
    fi

    # 5. Verify slot 1 inner_ip == "169.254.2.1"
    slot_ip=$(get_slot_field 1 "inner_ip")
    if [ "$slot_ip" = "169.254.2.1" ]; then
        pass "C3: slot 1 inner_ip == 169.254.2.1 after --skip-device attach"
    else
        fail "C3: expected inner_ip=169.254.2.1, got ${slot_ip}"
    fi

    # 6. Detach --skip-device (release slot without moving device)
    if ${SWITCH_BIN} detach ${SW_NAME} --skip-device --port=2 &>/dev/null; then
        pass "C3: detach --skip-device port 2 succeeded"
    else
        fail "C3: detach --skip-device port 2 failed"
    fi

    # 7. Verify slot 1 inner_ip == "0.0.0.0"
    slot_ip=$(get_slot_field 1 "inner_ip")
    if [ "$slot_ip" = "0.0.0.0" ]; then
        pass "C3: slot 1 restored to Free after --skip-device detach"
    else
        fail "C3: expected inner_ip=0.0.0.0 after detach, got ${slot_ip}"
    fi

    stop_switch
}

test_c5_detach_skip_device() {
    echo "[C5] detach --skip-device (device stays in sandbox)"
    start_switch 4

    # 1. Attach port 1 to sandbox1
    if ! ${SWITCH_BIN} attach ${SW_NAME} --to-netns=sandbox1 --inner-ip=169.254.1.1 --port=1 &>/dev/null; then
        fail "C5: initial attach port 1 failed"
        stop_switch
        return
    fi
    pass "C5: attach port 1 succeeded"

    # 2. Detach --skip-device (slot released, device stays in sandbox1)
    if ${SWITCH_BIN} detach ${SW_NAME} --skip-device --port=1 &>/dev/null; then
        pass "C5: detach --skip-device port 1 succeeded"
    else
        fail "C5: detach --skip-device port 1 failed"
        stop_switch
        return
    fi

    # 3. Verify slot 0 inner_ip == "0.0.0.0" (slot released)
    local slot_ip
    slot_ip=$(get_slot_field 0 "inner_ip")
    if [ "$slot_ip" = "0.0.0.0" ]; then
        pass "C5: slot 0 released (inner_ip == 0.0.0.0)"
    else
        fail "C5: expected inner_ip=0.0.0.0, got ${slot_ip}"
    fi

    # 4. Verify device still in sandbox1
    if ip netns exec sandbox1 ip link show ${SW_NAME}-p1 &>/dev/null; then
        pass "C5: device ${SW_NAME}-p1 still in sandbox1"
    else
        fail "C5: device ${SW_NAME}-p1 not found in sandbox1"
    fi

    stop_switch
}

test_c4_reserve_missing_port() {
    echo "[C4] reserve without --port fails"
    start_switch 4

    if ${SWITCH_BIN} reserve ${SW_NAME} &>/dev/null; then
        fail "C4: reserve without --port should fail"
    else
        pass "C4: reserve without --port correctly refused"
    fi

    stop_switch
}

# =========================================================================
#  Group D: stop / stop --force
# =========================================================================

test_d1_normal_stop() {
    echo "[D1] normal stop"
    start_switch 4

    if ${SWITCH_BIN} stop ${SW_NAME} &>/dev/null; then
        pass "D1: stop exit 0"
    else
        fail "D1: stop failed"
    fi

    # status should exit 3 (not running)
    if ${SWITCH_BIN} status ${SW_NAME} &>/dev/null; then
        fail "D1: status should fail after stop"
    else
        pass "D1: status correctly reports not running"
    fi

}

test_d2_stop_force() {
    echo "[D2] stop --force cleans corrupted switch"
    start_switch 4

    # Corrupt: remove metadata but keep slots pin (bpfMapsExist=true, Open fails)
    rm -f /sys/fs/bpf/${SW_NAME}/metadata

    # Normal stop should fail
    if ${SWITCH_BIN} stop ${SW_NAME} &>/dev/null; then
        fail "D2: stop should fail on corrupted switch"
    else
        pass "D2: stop correctly fails on corrupted switch"
    fi

    # Force-clean stop should succeed (corrupted switch can't Open, needs --force-clean)
    if ${SWITCH_BIN} stop ${SW_NAME} --force-clean &>/dev/null; then
        pass "D2: stop --force-clean succeeded"
    else
        fail "D2: stop --force-clean failed"
    fi

    # BPF pin directory should be cleaned
    if [ ! -d "/sys/fs/bpf/${SW_NAME}" ]; then
        pass "D2: BPF pin directory cleaned"
    else
        fail "D2: BPF pin directory still exists"
    fi

    # Recreate namespaces to clear residual veth devices
    recreate_namespaces
}

# =========================================================================
#  Group A: serve command
# =========================================================================

test_a1_serve_lifecycle() {
    echo "[A1] serve lifecycle + sd_notify"

    # Create unixgram socket to receive sd_notify
    local notify_sock="/tmp/test-notify-$$.sock"
    rm -f "$notify_sock" /tmp/test-notify-data

    python3 -c "
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.bind('${notify_sock}')
s.settimeout(30)
try:
    data = s.recv(256)
    open('/tmp/test-notify-data', 'w').write(data.decode())
except socket.timeout:
    open('/tmp/test-notify-data', 'w').write('TIMEOUT')
s.close()
" &
    local notify_pid=$!

    # Start serve in background
    NOTIFY_SOCKET="${notify_sock}" ${SWITCH_BIN} serve ${SW_NAME} \
        --mode=veth \
        --netns=sw_ns \
        --port-netns=port_ns \
        --ports=4 \
        --mac-addr=02:00:00:00:00:01 \
        --floating-ip-base=100.100.96.0 &
    SERVE_PID=$!

    # Wait for switch to become ready
    if wait_switch_ready; then
        pass "A1: switch became ready"
    else
        fail "A1: switch did not become ready"
        kill "$SERVE_PID" 2>/dev/null || true
        kill "$notify_pid" 2>/dev/null || true
        wait "$SERVE_PID" 2>/dev/null || true
        wait "$notify_pid" 2>/dev/null || true
        stop_switch
        rm -f "$notify_sock" /tmp/test-notify-data
        return
    fi

    # Wait for notify listener to finish
    wait "$notify_pid" 2>/dev/null || true

    # Check sd_notify received READY=1
    if [ -f /tmp/test-notify-data ] && grep -q "READY=1" /tmp/test-notify-data; then
        pass "A1: sd_notify READY=1 received"
    else
        fail "A1: sd_notify READY=1 not received (got: $(cat /tmp/test-notify-data 2>/dev/null || echo 'none'))"
    fi

    # All 4 slots should be Free (provisioned)
    local free_count
    free_count=$(count_slots_by_ip "0.0.0.0")
    if [ "$free_count" -eq 4 ]; then
        pass "A1: 4 slots Free after provision"
    else
        fail "A1: expected 4 Free slots, got ${free_count}"
    fi

    # Attach should work
    local attach_out
    attach_out=$(${SWITCH_BIN} attach ${SW_NAME} \
        --to-netns=sandbox1 \
        --inner-ip=169.254.1.1)
    local port
    port=$(json_field "$attach_out" "port")
    if [ -n "$port" ] && [ "$port" -gt 0 ]; then
        pass "A1: attach succeeded (port=${port})"
        # Detach
        ${SWITCH_BIN} detach ${SW_NAME} --port=${port} --from-netns=sandbox1 &>/dev/null || true
    else
        fail "A1: attach failed"
    fi

    # Graceful shutdown
    kill -TERM "$SERVE_PID" 2>/dev/null || true
    if wait "$SERVE_PID" 2>/dev/null; then
        pass "A1: serve exited cleanly"
    else
        pass "A1: serve process terminated"
    fi
    SERVE_PID=""

    stop_switch
    rm -f "$notify_sock" /tmp/test-notify-data
}

test_a2_serve_start_equivalence() {
    echo "[A2] serve and start produce equivalent config"

    # Round 1: start
    start_switch 4
    local start_config
    start_config=$(${SWITCH_BIN} show config ${SW_NAME})
    stop_switch

    # Recreate namespaces (stop may leave stale veth)
    recreate_namespaces

    # Round 2: serve
    ${SWITCH_BIN} serve ${SW_NAME} \
        --mode=veth \
        --netns=sw_ns \
        --port-netns=port_ns \
        --ports=4 \
        --mac-addr=02:00:00:00:00:01 \
        --floating-ip-base=100.100.96.0 &
    SERVE_PID=$!

    if wait_switch_ready; then
        pass "A2: serve switch ready"
    else
        fail "A2: serve switch did not become ready"
        kill "$SERVE_PID" 2>/dev/null || true
        wait "$SERVE_PID" 2>/dev/null || true
        stop_switch
        return
    fi

    local serve_config
    serve_config=$(${SWITCH_BIN} show config ${SW_NAME})

    # Compare configs (extract key fields that should match)
    local start_ports serve_ports start_mac serve_mac start_fip serve_fip
    start_ports=$(json_field "$start_config" "n_ports")
    serve_ports=$(json_field "$serve_config" "n_ports")
    start_mac=$(json_field "$start_config" "switch_mac")
    serve_mac=$(json_field "$serve_config" "switch_mac")
    start_fip=$(json_field "$start_config" "floating_ip_base")
    serve_fip=$(json_field "$serve_config" "floating_ip_base")

    if [ "$start_ports" = "$serve_ports" ] && \
       [ "$start_mac" = "$serve_mac" ] && \
       [ "$start_fip" = "$serve_fip" ]; then
        pass "A2: start and serve configs match"
    else
        fail "A2: config mismatch (start: ports=${start_ports} mac=${start_mac} fip=${start_fip}, serve: ports=${serve_ports} mac=${serve_mac} fip=${serve_fip})"
    fi

    kill -TERM "$SERVE_PID" 2>/dev/null || true
    wait "$SERVE_PID" 2>/dev/null || true
    SERVE_PID=""

    stop_switch
}

# =========================================================================
#  Test runner
# =========================================================================

run_tests() {
    echo ""
    echo "========================================="
    echo "  Running control-plane E2E tests"
    echo "========================================="
    echo ""

    # Group E: Backward compatibility (baseline)
    echo "--- Group E: Backward compatibility ---"
    test_e1_start_attach_detach_stop

    # Group B: start --reserved + provision
    echo ""
    echo "--- Group B: start --reserved + provision ---"
    test_b1_start_reserved_all
    test_b2_provision_count
    test_b3_provision_all
    test_b4_provision_port

    # Group C: reserve / reserve --force
    echo ""
    echo "--- Group C: reserve / reserve --force ---"
    test_c1_reserve_free_port
    test_c2_reserve_already_reserved
    test_c3_force_reserve_repair
    test_c4_reserve_missing_port
    test_c5_detach_skip_device

    # Group D: stop / stop --force
    echo ""
    echo "--- Group D: stop / stop --force ---"
    test_d1_normal_stop
    test_d2_stop_force

    # Group A: serve (background processes, most complex)
    echo ""
    echo "--- Group A: serve ---"
    test_a1_serve_lifecycle
    # Recreate namespaces for A2
    recreate_namespaces
    test_a2_serve_start_equivalence

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
