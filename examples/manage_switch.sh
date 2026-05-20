#!/bin/bash
# Generic JSON-config-driven switch management script.
#
# Usage:
#   sudo bash examples/manage_switch.sh <config.json> setup
#   sudo bash examples/manage_switch.sh <config.json> teardown
#   sudo bash examples/manage_switch.sh <config.json> status
#   sudo bash examples/manage_switch.sh <config.json> exec [--switch=<name|index>] <sandbox_index> -- <cmd...>
#   bash examples/manage_switch.sh example
#   bash examples/manage_switch.sh help

set -euo pipefail

if [ -n "${SWITCH_BIN:-}" ]; then
    : # Use environment variable
elif [ -x "bin/vswitch-ctl" ]; then
    SWITCH_BIN="bin/vswitch-ctl"
else
    SWITCH_BIN="/usr/sbin/vswitch-ctl"
fi

# ─── JSON helpers ───────────────────────────────────────────────────────────

json_query() {
    # $1=json_file, $2=python expression (variable 'data' holds parsed JSON)
    python3 -c "import json,sys; data=json.load(open('$1')); $2"
}

# ─── 辅助函数 ───────────────────────────────────────────────────────────────

strip_at() { echo "${1#@}"; }

show_usage() {
    cat <<'USAGE'
Usage:
  sudo bash manage_switch.sh <config.json> {setup|teardown|status}
  sudo bash manage_switch.sh <config.json> exec [--switch=<name|index>] <sandbox_index> -- <cmd...>
  bash manage_switch.sh example
  bash manage_switch.sh help

Subcommands:
  setup       Create netns, interfaces, start switches, attach sandboxes
  teardown    Stop switches, delete interfaces and auto-created netns (reverse order)
  status      Show switch status, stats, and namespace liveness
  exec        Execute a command inside a sandbox netns
  example     Print a complete example JSON config to stdout
  help        Show this help message

JSON config structure:
  {
    "instances": [
      {
        "switch_config": {        Switch daemon configuration (passed to switch binary)
          "switch_name": "...",       Unique name for this switch instance
          "switch_ns": "...",         Netns where the switch runs
          "transit_iface": "...",     Transit-facing interface device name
          ...                         Other switch-specific fields
        },
        "netns": [                List of netns to create before setup
          "ns_a",                     Plain name: just create the netns
          "@ns_b"                     @-prefixed: create netns AND bring up loopback (lo)
        ],
        "interfaces": [           Network interfaces to set up
          {
            "dev": "...",             Device name
            "type": "present|ipvlan|veth",
            "netns": "...",           (optional) Move device into this netns
            "mtu": 9000,             (optional) Set MTU
            "state": "up|down",       (optional) Set link state; omit to leave unchanged
            "ipvlan_parent": "...",   (ipvlan only) Parent device
            "peer_dev": "...",        (veth only) Peer device name
            "peer_netns": "...",      (veth only, optional) Peer netns
            "peer_state": "up|down"   (veth only, optional) Set peer link state
          }
        ],
        "sandboxes": [            Sandboxes to attach to the switch
          {
            "ip": "10.0.0.1",        Inner IP address for the sandbox
            "netns": "...",           (optional) Use existing netns; omit to auto-create
            "vni": 100,              (optional) GENEVE VNI
            "gateway_ip": "10.0.0.254" (optional) Transit gateway IP
          }
        ]
      }
    ]
  }

Interface types:
  present   Expect an already-existing device; verify it exists (optionally set MTU)
  ipvlan    Create an ipvlan L2 interface on the specified parent
  veth      Create a veth pair

Netns @ prefix:
  Prefix a netns name with "@" (e.g. "@mgmt_ns") to automatically run
  "ip link set lo up" inside that netns after creation. The actual netns name
  will be "mgmt_ns" (without the @).

Sandbox auto-created netns:
  When a sandbox omits "netns", the script auto-creates "<switch_name>_sb<index>"
  and automatically brings up loopback inside it.
USAGE
}

show_example() {
    python3 -c '
import json

example = {
    "instances": [
        {
            "switch_config": {
                "switch_name": "sw_test",
                "switch_netns": "sw_test_ns",
                "port_netns": "sw_test_ports",
                "num_ports": 128,
                "mac_addr": "02:00:00:00:00:01",
                "floating_ip_base": "100.100.96.0",
                "mgmt_extracts": ["sw_test_mgmt:mgmt0:169.254.169.254"],
                "transit_dev": "eth0sub10",
                "transit_dev_addr": "10.100.0.2/24:10.100.0.1",
                "geneve_port_base": 50000,
                "geneve_encap_eth": True
            },
            "netns": ["sw_test_ns", "sw_test_ports", "@sw_test_mgmt"],
            "interfaces": [
                { "dev": "eth0sub10", "type": "ipvlan", "ipvlan_parent": "eth0", "mtu": 1564 }
            ],
            "sandboxes": [
                { "ip": "10.100.0.1", "vni": 100, "gateway_ip": "10.100.0.254" },
                { "ip": "10.100.0.2" }
            ]
        }
    ]
}

print(json.dumps(example, indent=2))
'
}

# ─── 参数解析 ───────────────────────────────────────────────────────────────

# Handle no-config subcommands first
case "${1:-}" in
    example)
        show_example
        exit 0
        ;;
    help|--help|-h)
        show_usage
        exit 0
        ;;
esac

CONFIG_FILE="${1:-}"
ACTION="${2:-}"

if [[ -z "$CONFIG_FILE" || -z "$ACTION" ]]; then
    show_usage
    exit 1
fi

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "Error: config file '${CONFIG_FILE}' not found"
    exit 1
fi

# Resolve to absolute path
CONFIG_FILE="$(cd "$(dirname "$CONFIG_FILE")" && pwd)/$(basename "$CONFIG_FILE")"

NUM_INSTANCES=$(json_query "$CONFIG_FILE" "print(len(data['instances']))")

# ─── 单实例函数 ─────────────────────────────────────────────────────────────

get_switch_name() {
    # $1=instance_index
    json_query "$CONFIG_FILE" "print(data['instances'][$1]['switch_config']['switch_name'])"
}

setup_instance() {
    local cfg="$1" idx="$2"
    local sw_name
    sw_name=$(get_switch_name "$idx")

    echo "==> [${sw_name}] Setting up instance ${idx}..."

    # 1. Create netns list
    local ns_count
    ns_count=$(json_query "$cfg" "print(len(data['instances'][$idx].get('netns', [])))")
    for ((n=0; n<ns_count; n++)); do
        local raw_ns
        raw_ns=$(json_query "$cfg" "print(data['instances'][$idx]['netns'][$n])")
        local ns
        ns=$(strip_at "$raw_ns")
        echo "    Creating netns: ${ns}"
        ip netns add "$ns" 2>/dev/null || true
        if [[ "$raw_ns" == @* ]]; then
            ip netns exec "$ns" ip link set lo up
        fi
    done

    # 2. Create sandbox netns
    local sb_count
    sb_count=$(json_query "$cfg" "print(len(data['instances'][$idx].get('sandboxes', [])))")
    for ((s=0; s<sb_count; s++)); do
        local sb_ns
        sb_ns=$(json_query "$cfg" "
ns = data['instances'][$idx]['sandboxes'][$s].get('netns', '')
print(ns if ns else '${sw_name}_sb${s}')
")
        local sb_ns_custom
        sb_ns_custom=$(json_query "$cfg" "print(data['instances'][$idx]['sandboxes'][$s].get('netns', ''))")
        if [[ -z "$sb_ns_custom" ]]; then
            echo "    Creating sandbox netns: ${sb_ns}"
            ip netns add "$sb_ns" 2>/dev/null || true
            ip netns exec "$sb_ns" ip link set lo up
        else
            echo "    Using existing sandbox netns: ${sb_ns}"
        fi
    done

    # 3. Create interfaces
    local iface_count
    iface_count=$(json_query "$cfg" "print(len(data['instances'][$idx].get('interfaces', [])))")
    for ((f=0; f<iface_count; f++)); do
        local iface_json
        iface_json=$(json_query "$cfg" "
import json
print(json.dumps(data['instances'][$idx]['interfaces'][$f]))
")
        local dev type_val mtu_val netns_val
        dev=$(echo "$iface_json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['dev'])")
        type_val=$(echo "$iface_json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['type'])")
        mtu_val=$(echo "$iface_json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('mtu', 0))")
        netns_val=$(echo "$iface_json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('netns', ''))")

        case "$type_val" in
            present)
                local state_val
                state_val=$(echo "$iface_json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('state', '').lower())")
                echo "    Checking present interface: ${dev}"
                if [[ -n "$netns_val" ]]; then
                    if ! ip netns exec "$netns_val" ip link show "$dev" &>/dev/null; then
                        echo "Error: device ${dev} not found in netns ${netns_val}"
                        exit 1
                    fi
                    if [[ "$mtu_val" -gt 0 ]]; then
                        ip netns exec "$netns_val" ip link set "$dev" mtu "$mtu_val"
                    fi
                    if [[ "$state_val" == "up" ]]; then
                        ip netns exec "$netns_val" ip link set "$dev" up
                    elif [[ "$state_val" == "down" ]]; then
                        ip netns exec "$netns_val" ip link set "$dev" down
                    fi
                else
                    if ! ip link show "$dev" &>/dev/null; then
                        echo "Error: device ${dev} not found"
                        exit 1
                    fi
                    if [[ "$mtu_val" -gt 0 ]]; then
                        ip link set "$dev" mtu "$mtu_val"
                    fi
                    if [[ "$state_val" == "up" ]]; then
                        ip link set "$dev" up
                    elif [[ "$state_val" == "down" ]]; then
                        ip link set "$dev" down
                    fi
                fi
                ;;
            ipvlan)
                local ipvlan_parent state_val
                ipvlan_parent=$(echo "$iface_json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['ipvlan_parent'])")
                state_val=$(echo "$iface_json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('state', '').lower())")
                echo "    Creating ipvlan: ${dev} (parent: ${ipvlan_parent})"
                ip link del "$dev" 2>/dev/null || true
                ip link add "$dev" link "$ipvlan_parent" type ipvlan mode l2
                if [[ "$mtu_val" -gt 0 ]]; then
                    ip link set "$dev" mtu "$mtu_val"
                fi
                if [[ -n "$netns_val" ]]; then
                    ip link set "$dev" netns "$netns_val"
                    if [[ "$state_val" == "up" ]]; then
                        ip netns exec "$netns_val" ip link set "$dev" up
                    elif [[ "$state_val" == "down" ]]; then
                        ip netns exec "$netns_val" ip link set "$dev" down
                    fi
                else
                    if [[ "$state_val" == "up" ]]; then
                        ip link set "$dev" up
                    elif [[ "$state_val" == "down" ]]; then
                        ip link set "$dev" down
                    fi
                fi
                ;;
            veth)
                local peer_dev peer_netns state_val peer_state_val
                peer_dev=$(echo "$iface_json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['peer_dev'])")
                peer_netns=$(echo "$iface_json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('peer_netns', ''))")
                state_val=$(echo "$iface_json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('state', '').lower())")
                peer_state_val=$(echo "$iface_json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('peer_state', '').lower())")
                echo "    Creating veth pair: ${dev} <-> ${peer_dev}"
                ip link del "$dev" 2>/dev/null || true
                ip link add "$dev" type veth peer name "$peer_dev"
                if [[ "$mtu_val" -gt 0 ]]; then
                    ip link set "$dev" mtu "$mtu_val"
                    ip link set "$peer_dev" mtu "$mtu_val"
                fi
                # Set dev state (before moving to netns if applicable)
                if [[ -n "$netns_val" ]]; then
                    ip link set "$dev" netns "$netns_val"
                    if [[ "$state_val" == "up" ]]; then
                        ip netns exec "$netns_val" ip link set "$dev" up
                    elif [[ "$state_val" == "down" ]]; then
                        ip netns exec "$netns_val" ip link set "$dev" down
                    fi
                else
                    if [[ "$state_val" == "up" ]]; then
                        ip link set "$dev" up
                    elif [[ "$state_val" == "down" ]]; then
                        ip link set "$dev" down
                    fi
                fi
                # Set peer_dev state
                if [[ -n "$peer_netns" ]]; then
                    ip link set "$peer_dev" netns "$peer_netns"
                    if [[ "$peer_state_val" == "up" ]]; then
                        ip netns exec "$peer_netns" ip link set "$peer_dev" up
                    elif [[ "$peer_state_val" == "down" ]]; then
                        ip netns exec "$peer_netns" ip link set "$peer_dev" down
                    fi
                else
                    if [[ "$peer_state_val" == "up" ]]; then
                        ip link set "$peer_dev" up
                    elif [[ "$peer_state_val" == "down" ]]; then
                        ip link set "$peer_dev" down
                    fi
                fi
                ;;
            *)
                echo "Error: unknown interface type '${type_val}'"
                exit 1
                ;;
        esac
    done

    # 4. Write switch_config to temp file and start switch
    local tmpfile
    tmpfile=$(mktemp /tmp/switch_config_XXXXXX.json)
    json_query "$cfg" "
import json
print(json.dumps(data['instances'][$idx]['switch_config'], indent=2))
" > "$tmpfile"

    echo "    Starting switch ${sw_name}..."
    ${SWITCH_BIN} start --config "$tmpfile"
    rm -f "$tmpfile"

    # 5. Attach sandboxes
    for ((s=0; s<sb_count; s++)); do
        local sb_ns sb_ip vni gateway_ip
        sb_ns=$(json_query "$cfg" "
ns = data['instances'][$idx]['sandboxes'][$s].get('netns', '')
print(ns if ns else '${sw_name}_sb${s}')
")
        sb_ip=$(json_query "$cfg" "print(data['instances'][$idx]['sandboxes'][$s]['ip'])")
        vni=$(json_query "$cfg" "print(data['instances'][$idx]['sandboxes'][$s].get('vni', ''))")
        gateway_ip=$(json_query "$cfg" "print(data['instances'][$idx]['sandboxes'][$s].get('gateway_ip', ''))")

        local attach_args=()
        attach_args+=(attach "$sw_name")
        attach_args+=(--to-netns="$sb_ns")
        attach_args+=(--inner-ip="$sb_ip")
        if [[ -n "$vni" ]]; then
            attach_args+=(--transit-geneve-vni="$vni")
        fi
        if [[ -n "$gateway_ip" ]]; then
            attach_args+=(--transit-gateway-ip="$gateway_ip")
        fi

        echo "    Attaching sandbox ${sb_ns} (ip=${sb_ip})..."
        ${SWITCH_BIN} "${attach_args[@]}"

        # 6. Configure IP and default route in sandbox netns
        local port_num=$((s + 1))
        local port_dev="${sw_name}-p${port_num}"
        ip netns exec "$sb_ns" ip addr add "${sb_ip}/32" dev "$port_dev"
        ip netns exec "$sb_ns" ip link set "$port_dev" up
        ip netns exec "$sb_ns" ip route add default dev "$port_dev"
    done

    echo "==> [${sw_name}] Setup complete. ${sb_count} sandbox(es) attached."
}

teardown_instance() {
    local cfg="$1" idx="$2"
    local sw_name
    sw_name=$(get_switch_name "$idx")

    echo "==> [${sw_name}] Tearing down instance ${idx}..."

    # 1. Stop switch
    echo "    Stopping switch ${sw_name}..."
    ${SWITCH_BIN} stop "$sw_name" || true

    # 2. Delete interfaces (skip present)
    local iface_count
    iface_count=$(json_query "$cfg" "print(len(data['instances'][$idx].get('interfaces', [])))")
    for ((f=0; f<iface_count; f++)); do
        local dev type_val
        dev=$(json_query "$cfg" "print(data['instances'][$idx]['interfaces'][$f]['dev'])")
        type_val=$(json_query "$cfg" "print(data['instances'][$idx]['interfaces'][$f]['type'])")
        if [[ "$type_val" != "present" ]]; then
            echo "    Deleting interface: ${dev}"
            ip link del "$dev" 2>/dev/null || true
        fi
    done

    # 3. Delete auto-created sandbox netns
    local sb_count
    sb_count=$(json_query "$cfg" "print(len(data['instances'][$idx].get('sandboxes', [])))")
    for ((s=0; s<sb_count; s++)); do
        local sb_ns_custom
        sb_ns_custom=$(json_query "$cfg" "print(data['instances'][$idx]['sandboxes'][$s].get('netns', ''))")
        if [[ -z "$sb_ns_custom" ]]; then
            local sb_ns="${sw_name}_sb${s}"
            echo "    Deleting sandbox netns: ${sb_ns}"
            ip netns del "$sb_ns" 2>/dev/null || true
        fi
    done

    # 4. Delete netns list (reverse order)
    local ns_count
    ns_count=$(json_query "$cfg" "print(len(data['instances'][$idx].get('netns', [])))")
    for ((n=ns_count-1; n>=0; n--)); do
        local raw_ns
        raw_ns=$(json_query "$cfg" "print(data['instances'][$idx]['netns'][$n])")
        local ns
        ns=$(strip_at "$raw_ns")
        echo "    Deleting netns: ${ns}"
        ip netns del "$ns" 2>/dev/null || true
    done

    # 5. Clean up BPF maps
    echo "    Cleaning BPF maps: /sys/fs/bpf/${sw_name}"
    rm -rf "/sys/fs/bpf/${sw_name}" 2>/dev/null || true

    echo "==> [${sw_name}] Teardown complete."
}

status_instance() {
    local cfg="$1" idx="$2"
    local sw_name
    sw_name=$(get_switch_name "$idx")

    echo "==> [${sw_name}] Status (instance ${idx}):"
    echo ""

    echo "--- Switch Status ---"
    ${SWITCH_BIN} status "$sw_name" 2>/dev/null || echo "Switch not running"
    echo ""

    echo "--- Switch Stats ---"
    ${SWITCH_BIN} stats "$sw_name" 2>/dev/null || echo "No stats available"
    echo ""

    echo "--- Namespace Check ---"
    local ns_count
    ns_count=$(json_query "$cfg" "print(len(data['instances'][$idx].get('netns', [])))")
    for ((n=0; n<ns_count; n++)); do
        local raw_ns
        raw_ns=$(json_query "$cfg" "print(data['instances'][$idx]['netns'][$n])")
        local ns
        ns=$(strip_at "$raw_ns")
        if ip netns list | grep -qw "$ns"; then
            echo "    ${ns}: alive"
        else
            echo "    ${ns}: MISSING"
        fi
    done

    local sb_count
    sb_count=$(json_query "$cfg" "print(len(data['instances'][$idx].get('sandboxes', [])))")
    for ((s=0; s<sb_count; s++)); do
        local sb_ns
        sb_ns=$(json_query "$cfg" "
ns = data['instances'][$idx]['sandboxes'][$s].get('netns', '')
print(ns if ns else '${sw_name}_sb${s}')
")
        if ip netns list | grep -qw "$sb_ns"; then
            echo "    ${sb_ns}: alive"
        else
            echo "    ${sb_ns}: MISSING"
        fi
    done
    echo ""
}

# ─── 编排层 ─────────────────────────────────────────────────────────────────

do_setup() {
    for ((i=0; i<NUM_INSTANCES; i++)); do
        setup_instance "$CONFIG_FILE" "$i"
    done
}

do_teardown() {
    for ((i=NUM_INSTANCES-1; i>=0; i--)); do
        teardown_instance "$CONFIG_FILE" "$i"
    done
}

do_status() {
    for ((i=0; i<NUM_INSTANCES; i++)); do
        status_instance "$CONFIG_FILE" "$i"
    done
}

do_exec() {
    shift 2  # remove config_file and "exec"
    local switch_selector="0"

    # Parse --switch=<name|index>
    if [[ "${1:-}" == --switch=* ]]; then
        switch_selector="${1#--switch=}"
        shift
    fi

    local sandbox_index="${1:-}"
    shift || true

    if [[ -z "$sandbox_index" ]]; then
        echo "Usage: $0 <config.json> exec [--switch=<name|index>] <sandbox_index> -- <cmd...>"
        exit 1
    fi

    # Skip "--" separator
    if [[ "${1:-}" == "--" ]]; then
        shift
    fi

    if [[ $# -eq 0 ]]; then
        echo "Error: no command specified after '--'"
        exit 1
    fi

    # Resolve switch selector to instance index
    local instance_idx
    if [[ "$switch_selector" =~ ^[0-9]+$ ]]; then
        instance_idx="$switch_selector"
    else
        # Search by switch_name
        instance_idx=$(json_query "$CONFIG_FILE" "
found = -1
for i, inst in enumerate(data['instances']):
    if inst['switch_config']['switch_name'] == '${switch_selector}':
        found = i
        break
print(found)
")
        if [[ "$instance_idx" -lt 0 ]]; then
            echo "Error: switch '${switch_selector}' not found"
            exit 1
        fi
    fi

    local sw_name
    sw_name=$(get_switch_name "$instance_idx")

    # Resolve sandbox netns
    local sb_ns
    sb_ns=$(json_query "$CONFIG_FILE" "
ns = data['instances'][$instance_idx]['sandboxes'][$sandbox_index].get('netns', '')
print(ns if ns else '${sw_name}_sb${sandbox_index}')
")

    echo "==> Executing in ${sb_ns}: $*"
    ip netns exec "$sb_ns" "$@"
}

# ─── main ───────────────────────────────────────────────────────────────────

case "$ACTION" in
    setup)    do_setup ;;
    teardown) do_teardown ;;
    status)   do_status ;;
    exec)     do_exec "$@" ;;
    *)
        show_usage
        exit 1
        ;;
esac
