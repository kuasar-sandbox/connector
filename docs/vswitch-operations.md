[English](vswitch-operations.md) | [简体中文](vswitch-operations_zh.md)

# vSwitch operations

Deploy a switch, allocate a sandbox port, hand off its TAP queue, inspect traffic and recover owned resources. The [network contract](vswitch.md) defines identity, forwarding, ABI and concurrency; [TAPFD](tapfd.md) defines the independently implementable provider/consumer protocol. Source builds and validation strategy belong to [Contributing](../CONTRIBUTING.md).

## Deployment and prerequisites

### System requirements

- Documented kernel baseline: Linux **5.10+**, with the needed TC/BPF features and BTF available at `/sys/kernel/btf/vmlinux`. Verify the actual kernel configuration and privileged tests; a version number alone is insufficient.
- bpffs mounted at `/sys/fs/bpf`, for example `mount -t bpf bpf /sys/fs/bpf`.
- Root execution for the privileged BPF/network/namespace paths, with capability requirements discussed in [required privileges](vswitch.md#required-privileges).
- Network namespaces, TAP, veth, routing and TC support. Running a prebuilt binary does not require Go or Clang; source toolchains are covered by [Contributing](../CONTRIBUTING.md#build-and-validation).


Deferred publication uses ordinary BPF loads and an explicit address dependency on AMD64/ARM64, not fetch-atomic instructions or `-mcpu=v3`. The documented Linux 5.10 baseline is unchanged. The generated and kernel-rewritten instructions must retain the flag-to-address dependency and the post-up InnerIP load; privileged packet and TAP-FD tests verify the resulting behavior.

### Obtain a matching binary

Install `connector-ctl` and `dist/` templates from the selected component or aggregate release. Follow [platform installation](https://github.com/kuasar-sandbox/kuasar-sandbox/blob/main/docs/installation.md) for exact-asset verification, and [source builds](../CONTRIBUTING.md#build-and-validation) when producing the component. Keep the userspace binary and its embedded BPF objects from the same source revision.

### systemd integration

The [dist directory](../dist) supplies three templates:

| Template | Installation location | Purpose |
|---|---|---|
| [connector-vswitch.service](../dist/connector-vswitch.service) | `/etc/systemd/system/` | Type=notify service. |
| [connector-switch.conf](../dist/connector-switch.conf) | `/etc/connector/switch.conf` | EnvironmentFile syntax. |
| [NetworkManager-connector.conf](../dist/NetworkManager-connector.conf) | `/usr/lib/systemd/system/NetworkManager.service.d/` | Optional NetworkManager ordering after the switch service. |

Key service structure; ellipses abbreviate the actual template and are not a complete installable unit:

```ini
[Service]
Type=notify
WatchdogSec=60
EnvironmentFile=/etc/connector/switch.conf
ExecStartPre=...   # Create SWITCH/PORT/MGMT namespaces idempotently, skipping empty values
ExecStartPre=...   # If switch is absent, wait for TRANSIT_DEV in a 120-iteration loop
ExecStart=/usr/sbin/connector-ctl vswitch serve ${SWITCH_NAME} ... --mgmt-extract=...:${MGMT_EXTRACT_CIDRS}
ExecStartPost=...  # Apply MGMT_ADDRS with idempotent ip addr replace
ExecStartPost=...  # Enable route_localnet on the management device
TimeoutStartSec=60
Restart=on-failure
LimitMEMLOCK=infinity
```

The first ExecStartPre creates namespaces. The second waits for the transit device when the switch is absent, for example while its driver loads. Its 120 one-second iterations are also bounded by the unit's **TimeoutStartSec=60**, so they do not promise a 120-second systemd startup allowance.

Management extraction and interface ownership are explicitly separate:

```ini
MGMT_EXTRACT_CIDRS=169.254.169.254/32
MGMT_ADDRS=169.254.169.254/32
```

`MGMT_EXTRACT_CIDRS` supplies extraction matches. The first ExecStartPost splits comma-separated `MGMT_ADDRS` and applies each with `ip addr replace`; an empty value leaves the extraction peer without configured IPv4 addresses. It runs in host or named namespace according to MGMT_NETNS. The second post-start command enables `net.ipv4.conf.<dev>.route_localnet`, allowing a separately configured management-service mapping to target loopback.

The shipped ExecStart passes extraction flags; it does **not** automatically pass `--mgmt-service` merely because a backend or route_localnet is present. Add the intended static mapping to the service's actual command/configuration when using it, and retain the listener/address/routing setup.

**Host-namespace management:** leave `MGMT_NETNS=` empty when metadata or management services run on the host. The resulting `--mgmt-extract=:<dev>:<cidrs>` leaves the veth peer in the caller namespace, and namespace creation skips the empty value. Nonempty MGMT_ADDRS is assigned there; empty means an addressless peer.

### First startup

1. Install the binary at the template's `/usr/sbin/connector-ctl` path and the selected templates at the locations above. Identify the dedicated transit device with `ip -br link`, then edit `/etc/connector/switch.conf`, including TRANSIT_DEV and TRANSIT_DEV_ADDR.
2. Put that unused transit device DOWN with `ip link set "$TRANSIT_DEV" down`; startup moves it into switch-netns. Confirm the physical underlay supports the configured encapsulation MTU.
3. Run `sudo systemctl daemon-reload`, then `sudo systemctl start connector-vswitch` for the supplied **connector-vswitch.service** filename.
4. Check that `systemctl status connector-vswitch` is active, `connector-ctl vswitch status sw0 --ready` returns zero, and `ip netns list` shows the configured namespaces. READY=1 can precede complete port provisioning ([Two-phase startup](vswitch.md#two-phase-startup)).
5. Enable boot startup with `sudo systemctl enable connector-vswitch`.

### Stop the service or remove the switch

`systemctl stop connector-vswitch` stops the resident `serve` process and its
optional TAPFD listener. The shipped unit has no `ExecStop`, and `serve` does not
call switch teardown on SIGTERM/SIGINT. Pinned BPF state, TC attachments and
devices can keep forwarding; a stopped service is not proof of stopped traffic.

For teardown, first stop new admission through the owning control plane and
coordinate the consumers to drain/detach their bindings and close TAP queue
references. Stop the resident service before removing its switch resources, then
run `connector-ctl vswitch stop <name>` from the namespace that should receive
the transit device. Check the result and remaining owned resources. For a
control-service restart with intact state, restart the same service/configuration
without treating switch destruction as a restart step; see [Recovery by failure
domain](#recovery-by-failure-domain).

## Manual first switch

The following illustrates a fresh switch in Bash with `jq`. Run as root with a dedicated, unused `eth1` that can safely be moved into `sw_ns`; the underlay must support the resulting transit MTU. All three names (`sw1`, `sw_ns`, `mgmt_ns`) must be unused. A TAPFD-capable VMM receiver must already be listening at the run-owned private path supplied in `TAPFD_SOCKET` before `open-port`. Production values depend on the deployment network:

```bash
set -euo pipefail
: "${TAPFD_SOCKET:?Set the existing run-owned VMM receiver socket path}"
ip netns add sw_ns
ip netns add mgmt_ns
ip link set eth1 down

connector-ctl vswitch start sw1 \
    --netns=sw_ns \
    --ports=128 \
    --mac-addr=02:00:00:00:00:01 \
    --floating-ip-base=100.100.96.0 \
    --mgmt-extract=mgmt_ns:eth0:169.254.169.254/32 \
    --transit-dev=eth1 \
    --transit-dev-addr=10.0.0.1/24:10.0.0.2 \
    --transit-dev-mtu=auto

ip netns exec mgmt_ns ip addr replace 169.254.169.254/32 dev eth0

attach_json="$(connector-ctl vswitch attach sw1 \
    --inner-ip=169.254.1.1 \
    --transit-gateway-ip=10.0.0.2 \
    --transit-geneve-vni=100)"
port="$(printf '%s\n' "$attach_json" \
    | jq -er '.port | select(type == "number" and . >= 1 and . <= 128 and floor == .)')"

TAPFD_SOCKET="$TAPFD_SOCKET" connector-ctl vswitch open-port sw1 --port="$port"
```

Keep `attach_json` and the actual `port` for observation and cleanup; retain any returned attachment generation. The switch and VMM are now available for the [two-ended acceptance checks](#two-ended-acceptance). Complete those checks before cleanup. After testing, stop the VMM/consumer and close its TAP queue references through that owner, then run the following commands in the same shell:

```bash
connector-ctl vswitch detach sw1 --port="$port"
connector-ctl vswitch stop sw1
ip netns del mgmt_ns
ip netns del sw_ns
```

These addresses are documentation values, not a production topology. Run `stop` from the namespace that should receive the returned transit device. Inspect actual port and transit MTUs: the current two-phase provision path does not propagate `--mtu` to newly created TAP/veth ports. The complete command reference and deployment procedures are in [vSwitch operations](vswitch-operations.md); forwarding and lifecycle constraints are defined in [vSwitch design](vswitch.md).

This is a manual sequence, not an automatic failure-cleanup helper. Stop at any
failed command, inspect the actual allocation, and remove only resources created
by this run. Never force-stop a pre-existing switch or delete a foreign namespace.

## Command-line and configuration reference

Most query and one-shot commands emit JSON; `serve` stays resident and reports health/progress. Run privileged network/BPF operations as root with the required kernel capabilities ([Required privileges](vswitch.md#required-privileges)).

### Subcommands

| Command | Purpose |
|---|---|
| `start [switch_name]` | StartReserved followed by synchronous ProvisionPorts, then exit. |
| `serve [switch_name]` | Resident systemd service: StartReserved, optional TAPFD listen, READY=1, background ProvisionPorts and health/watchdog loop. |
| `stop <name>` | Release ports and switch resources, unpin maps, delete owned devices and move transit into the stop caller's namespace. |
| `attach <name>` | Allocate a slot by CAS Free→IP; optionally move a veth peer into the sandbox namespace. |
| `set-port-up <name> --port=N` | Commit the complete final configuration of an allocated/down attachment and enable traffic. |
| `detach <name> --port=N` | CAS Allocated→Free; Reserved is not a temporary detach state. |
| `reserve <name> --port=N` | Mark a slot Reserved to prevent subsequent attachment, for upgrade/drain. |
| `provision <name>` | Create devices for Reserved slots, in bulk or for one repair. |
| `open-port <name> --port=N` | Open a TAP queue and send its descriptor to `TAPFD_SOCKET`; provider helper in [Dynamic acquisition contract (normative)](tapfd.md#dynamic-acquisition-contract-normative). |
| `status <name>` | Conditions-based status; `--ready` expresses readiness as an exit code. |
| `stats <name>` | Management/transit × rx/tx × packets/bytes per port. |
| `show slots\|config <name>` | Dump slots or in-kernel configuration. |
| `dhcp request\|serve` | Embedded DHCP client/server for debugging and test topologies. |


### `connector-ctl vswitch start` / `serve`

`start` finishes initialization synchronously and exits; `serve` implements resident systemd `Type=notify` operation ([Two-phase startup](vswitch.md#two-phase-startup)). `switch_name` can be omitted when provided by `--config` ([Configuration file (`--config`)](#configuration-file---config)).

| Flag | Required | Meaning |
|---|---|---|
| `--netns` | Yes | Existing internal switch namespace. |
| `--mac-addr` | Yes | Switch MAC base used by MAC derivation ([MAC derivation](vswitch.md#mac-derivation)); the first four bytes are retained. |
| `--ports` | Yes | Number of ports, 1–4096. |
| `--floating-ip-base` | Yes | Floating-IP base; attachment address is `base + (generation << 12) + slot_id`, with zero-based `slot_id`. |
| `--generation-bits` | No | Bits above the fixed 12-bit slot identity, 0–20; default 0 permits generation 0 only. The complete FloatingIP window must fit IPv4. |
| `--port-netns` | For veth provisioning | Initial location of veth peers. TAP does not need it. Reserved-only startup may omit it, but it must be supplied at start if later veth provisioning is planned. |
| `--mode` | No | Automatic provision mode: `tap` (default) or `veth`. With `--reserved`, it validates the intended startup mode but does not persist a mode override for a future provision invocation. |
| `--mgmt-extract` | No | Repeatable `<netns>:<dev>:<cidr1>,<cidr2>,...`, within the per-slot extraction limit ([Boundaries](vswitch.md#boundaries)). CIDRs do not configure interface addresses. Empty namespace (`:<dev>:<cidrs>`) leaves the management peer in the caller/host namespace. |
| `--mgmt-service` | No | Repeatable `<VIP>:<vport>:<targetIP>:<targetPort>`. VIP must match extraction; target IP/port must be globally unique. Applies to TCP and UDP ([Packet paths](vswitch.md#packet-paths)). A loopback target needs `route_localnet=1` on the management device. |
| `--transit-dev` | No | Uplink moved from the start caller's namespace into the switch. It must be **DOWN** to avoid taking over an active interface. Stop moves it into the stop caller's namespace. |
| `--transit-dev-addr` | No | `<ip>/<prefix>:<nexthop>` or `auto` for DHCP ([DHCP gateway inference](vswitch.md#dhcp-gateway-inference)). |
| `--transit-dev-mtu` | No | `auto` or an explicit MTU; default leaves it unchanged and validates ([MTU validation](vswitch.md#mtu-validation)). |
| `--geneve-locator` | No | `port` (default), `vni` or `tlv`; encodes zero-based slot ID ([GENEVE tunnels](vswitch.md#geneve-tunnels)). |
| `--geneve-port-base` | No | GENEVE UDP destination base for `port` locator; default 50000. |
| `--geneve-tlv-locator` | For `tlv` | Exact wire `CLASS:TYPE`, for example `0102:81` ([GENEVE tunnels](vswitch.md#geneve-tunnels)). |
| `--geneve-encap-eth` | No | Ether-over-GENEVE; default is IP-over-GENEVE. |
| `--mtu` | No | Requested startup MTU used for management devices and transit-budget checks. Current two-phase provision does not propagate it to new TAP/veth ports; inspect actual port MTU ([MTU validation](vswitch.md#mtu-validation)). |
| `--port-mac-addr` | No | `fixed` (default), `per-port`, or an explicit MAC ([MAC derivation](vswitch.md#mac-derivation)). |
| `--reserved` | No | StartReserved only. The saved switch configuration supplies port-netns, and provision has no independent override; provide `--port-netns` now if later using veth. |
| `--config` | No | Load JSON configuration ([Configuration file (`--config`)](#configuration-file---config)). |

`serve` shares the switch flags but has no `--reserved`. Additional flags:

| Flag | Meaning |
|---|---|
| `--watch-interval` | Health-check interval, default 30s. |
| `--tapfd-listen` | Persistent switch/TAPFD Unix socket. Accepts `TAPFD/1 INFO`, `PREPARE`, `OPEN`, `SET_PORT_UP`, `RELEASE`; OPEN returns `TAPFD/1 OK`, metadata and SCM_RIGHTS. See [Persistent provider socket (normative)](tapfd.md#persistent-provider-socket-normative). |

Example `start` output (illustrative configured values, not output from a command run in this document):

```json
{
  "switch": "sw1",
  "switch_netns": "netns_switch",
  "switch_maps": {
    "slots":           "/sys/fs/bpf/sw1/slots_v2",
    "config":          "/sys/fs/bpf/sw1/config",
    "stats":           "/sys/fs/bpf/sw1/stats",
    "ifindex_to_slot": "/sys/fs/bpf/sw1/ifindex_to_slot",
    "geneve_opts":     "/sys/fs/bpf/sw1/geneve_opts",
    "metadata":        "/sys/fs/bpf/sw1/metadata",
    "mgmt_svc_fwd":    "/sys/fs/bpf/sw1/mgmt_svc_fwd",
    "mgmt_svc_rev":    "/sys/fs/bpf/sw1/mgmt_svc_rev"
  },
  "port_netns": "netns_ports",
  "ports": 4096, "ports_used": 0, "ports_available": 4096,
  "floating_ip_base": "100.100.96.0",
  "mgmt_planes": [
    { "index": 0, "mgmt_netns": "netns_mgmt", "mgmt_dev": "eth0",
      "service_routes": ["169.254.169.254/32"], "return_route_metric": 100 }
  ],
  "mgmt_services": [
    { "vip": "169.254.169.254", "vport": 80,
      "target_ip": "127.0.0.1", "target_port": 19254, "protocols": "tcp,udp" }
  ],
  "transit_type": "overlay-geneve",
  "transit_dev": "eth1",
  "transit_dev_ip": "10.200.12.3",
  "geneve_locator": "port",
  "geneve_port": 50000,
  "geneve_port_base": 50000
}
```

`mgmt_services` appears only when configured. `status` and `show config` also report `mgmt_planes`/`mgmt_services` from the metadata map. The retained name `mgmt_planes[].service_routes` means extraction-match CIDRs, not addresses already assigned to the management interface.

### `connector-ctl vswitch stop`

If the configured switch namespace is no longer addressable by name, stop releases stale slot bookkeeping and unpins the switch without applying its saved interface indices to the caller namespace. It does not delete caller links or try to move a transit device from there. A deliberately empty namespace setting retains caller-namespace cleanup; other namespace lookup errors are returned. Removing a namespace name does not prove that no process still holds the old namespace: inspect any retained namespace and orphaned devices separately.

Stop uses ReleasePorts then StopReleased: remove owned ports, management/dummy devices and TC references, unpin BPF maps, and move transit into the **stop caller's namespace**. To return it to the original host namespace, invoke stop there; the implementation does not restore a separately remembered origin namespace.

Without `--force`, detecting allocated ports returns exit code **4**. The initial
allocated-port check happens before reserving Free slots. Do not treat refusal,
or the CLI's current “Free ports have been reserved” diagnostic, as proof that
new admission is blocked. Stop admission through the owner, drain active bindings,
inspect actual state and retry. A switch that does not exist returns exit code 3.

| Flag | Meaning |
|---|---|
| `--force` | Release in-use ports before stopping, using two cleanup passes. |
| `--force-clean` | Attempt normal Stop first; only a recognized corrupted-switch error enables the pin-only cleanup fallback. A healthy switch still receives normal cleanup, and this flag alone does not override in-use ports. The fallback leaves device/TC cleanup and transit restoration to the operator; unpinning alone does not prove forwarding has stopped. |

### `connector-ctl vswitch attach`

Allocate a port by CAS Free→IP; veth mode can also move the peer into a sandbox namespace. A port that is not yet provisioned cannot be used; callers of asynchronous startup should handle the not-provisioned/no-available-port state and retry according to readiness ([Two-phase startup](vswitch.md#two-phase-startup)).

| Flag | Meaning |
|---|---|
| `--inner-ip=IP` | Required sandbox internal IPv4 address. |
| `--generation=N` | Caller-supplied attachment generation, default 0; require `0 <= N < 2^generation_bits`, or only 0 when no generation bits are configured. It is independent of the internal statistics generation. |
| `--port=N` | Select a one-based slot; omitted/zero means automatic allocation. |
| `--to-netns=NS` | Move the peer into this namespace, veth only. |
| `--transit-gateway-ip=IP` | GENEVE outer destination IPv4 address. |
| `--transit-geneve-vni=N` | Configured VNI, subject to the locator's range. |
| `--transit-geneve-opt=CLASS:TYPE:DATA` | Repeatable outbound opaque option. Hex data length must be a multiple of four bytes; `CLASS:TYPE:` represents empty data ([GENEVE tunnels](vswitch.md#geneve-tunnels)). |
| `--transit-mac-addr=MAC` | Inner Ethernet destination for Ether-over-GENEVE; default broadcast. |
| `--skip-device` | Skip veth namespace movement and retain slot control updates. Rejected for TAP attachment. |
| `--open-port` | TAP only: after allocation, send the queue through `TAPFD_SOCKET`. Transfer failure triggers a detach/rollback attempt; verify state before retry if cleanup also fails. |
| `--admin-down` | Allocate and prepare the attachment while leaving traffic disabled. After handoff and guest configuration, use `set-port-up` with all final network fields. Default false. |

Example veth output, showing selected fields:

```json
{
  "port": 4, "port_dev": "sw1-p4", "port_netns": "sandbox_ns_4",
  "port_mac": "02:00:00:00:80:01",
  "inner_ip": "169.254.1.1",
  "floating_ip": "100.100.96.3",
  "transit_type": "overlay-geneve",
  "geneve_port": 50003,
  "geneve_locator": "port",
  "transit_gateway_ip": "10.200.12.1",
  "transit_geneve_vni": 1004,
  "wire_geneve_vni": 1004
}
```

In attach/show JSON, `geneve_opts_len` is the **total wire option length**, including an automatic TLV locator, and zero is omitted. The raw slot field of the same name stores only opaque-option bytes ([Data-plane ABI](vswitch.md#data-plane-abi)).

Combined `attach --open-port` output, selected fields:

```json
{
  "port": 4, "port_dev": "sw1-t4",
  "port_mac": "02:00:00:00:80:01",
  "inner_ip": "169.254.4.1",
  "tap_sent_to": "/tmp/recv.sock"
}
```

Attach accepts repeated opaque options:

```bash
connector-ctl vswitch attach sw0 --inner-ip=169.254.1.1 \
    --transit-gateway-ip=10.0.0.2 --transit-geneve-vni=42 \
    --transit-geneve-opt=0102:02:0000002a \
    --transit-geneve-opt=0102:83:1122334455667788
```

### `connector-ctl vswitch detach`

For a PORT_F_UP-capable switch, Attach/Detach take no switch-wide lock, even while management holds LOCK_EX. Detach completes fallible device work, revokes publication, clears the options hint and CASes Allocated→Free last; it performs no per-slot writes after release. Management takeover is intentional. Reserved→Free has a separate management entry/exit boundary, not arbitrary reuse racing an old request. Switch-wide attachment locking was an implementation defect and has no compatibility fallback. Attach/Detach reject old pinned switches lacking PORT_F_UP before any mutation; rebuild through the management workflow. Inspection and management cleanup remain available. Fixed options values may remain inactive; the next Attach overwrites them before publication.

TAP detach performs no device move. For veth, `--from-netns` moves the peer back into port-netns; without it, detach verifies that the peer is already there. Device/namespace failure can prevent completion; inspect the error and slot state.

| Flag | Meaning |
|---|---|
| `--port=N` | Required one-based port. |
| `--from-netns=NS` | Current sandbox namespace containing the veth peer. |
| `--skip-device` | Skip device movement/checks, for either veth or TAP. |

### `connector-ctl vswitch reserve`

Mark a port Reserved to prevent new attachment, for upgrade/drain or before changing its device kind with provision ([Port modes: veth and TAP](vswitch.md#port-modes-veth-and-tap)).

| Flag | Required | Meaning |
|---|---|---|
| `--port=N` | Yes | One-based port. |
| `--force` | No | Allow Allocated→Reserved; default permits only Free→Reserved. |

### `connector-ctl vswitch provision`

Create devices for Reserved slots and expose them to Attach. Free/Allocated slots are skipped; failed Reserved slots can be repaired individually.

| Flag | Meaning |
|---|---|
| `--port=N` | Repair only this slot; mutually exclusive with `--count`. |
| `--count=N` | Limit devices created in this invocation; zero means all. Mutually exclusive with `--port`. |
| `--mode=tap\|veth` | Device kind, default TAP. For a Reserved slot changing kind, create the new device, commit the new ifindex, then remove the old device. |

### `connector-ctl vswitch open-port`

The helper implementing [TAPFD dynamic acquisition](tapfd.md#dynamic-acquisition-contract-normative) enters switch-netns and opens the persistent TAP with `open(/dev/net/tun)` and `TUNSETIFF(IFF_TAP|IFF_NO_PI|IFF_VNET_HDR)`. It sends the queue descriptor and metadata with SCM_RIGHTS to `TAPFD_SOCKET`, either `fd=N` or a path ([Advertising the socket: `TAPFD_SOCKET`](tapfd.md#advertising-the-socket-tapfd_socket) of tapfd.md). A truthy `TAPFD_WANT_NETNS` appends the switch namespace descriptor after the TAP descriptor and sets `netns_fd=1` ([Requesting a netns descriptor: `TAPFD_WANT_NETNS`](tapfd.md#requesting-a-netns-descriptor-tapfd_want_netns)).

| Flag | Required | Meaning |
|---|---|---|
| `--port=N` | Yes | One-based TAP port. |

Before touching the socket or TAP, the helper requires a TAP-kind slot, a provisioned ifindex and an attached real inner IP. A switch that does not exist yields exit code 3.

```bash
# First start a receiver that implements TAPFD metadata and SCM_RIGHTS (tapfd.md).
TAPFD_SOCKET=/run/vm1.sock connector-ctl vswitch open-port sw0 --port=3
TAPFD_SOCKET=fd=3 connector-ctl vswitch open-port sw0 --port=3      # Inherited Unix socket
```

Selected output fields:

```json
{
  "port": 3, "tap_dev": "sw0-t3", "sent_to": "/run/vm1.sock",
  "mac": "02:00:00:00:80:01", "inner_ip": "169.254.3.1",
  "netns_sent": false
}
```

### `connector-ctl vswitch status`

Status reports Conditions including `Ready`, `PortDevicesReady`, `MgmtDevicesReady` and `TransitDeviceReady`. While ports remain Reserved, including after `start --reserved`, it can also report `PortReserved`.

`PortReserved` is informational. The device checks skip Reserved slots, so even when all ports are Reserved, `Ready` and `PortDevicesReady` can be True. Inspect `ports_available`/`ports_reserved` or the selected slot before assuming attachment capacity; `status --ready` alone does not establish it. See [status implementation](../pkg/vswitch/status.go).

| Flag | Meaning |
|---|---|
| `--ready` | Suppress JSON and return 0 for Ready, 3 for NotExist, or 4 for NotReady. |

Selected JSON fields:

```json
{
  "switch": "sw1",
  "state": "running",
  "conditions": [
    { "type": "Ready",              "status": "True" },
    { "type": "PortDevicesReady",   "status": "True" },
    { "type": "MgmtDevicesReady",   "status": "True" },
    { "type": "TransitDeviceReady", "status": "True" }
  ],
  "ports": 4096, "ports_used": 128, "ports_available": 3968,
  "mgmt_planes": [{ "index": 0, "mgmt_netns": "netns_mgmt", "mgmt_dev": "eth0",
                    "service_routes": ["169.254.169.254/32"], "return_route_metric": 100 }],
  "transit_dev": "eth1", "transit_dev_ip": "10.200.12.3"
}
```

Conditions fragment when all 4096 ports are still Reserved and there are no non-Reserved devices to check:

```json
"conditions": [
  { "type": "Ready", "status": "True" },
  { "type": "PortDevicesReady", "status": "True",
    "message": "0 ports to check (all reserved)" },
  { "type": "PortReserved", "status": "True", "message": "4096 ports reserved" }
]
```

### `connector-ctl vswitch stats`

Per-port counters from the sandbox's viewpoint: management/transit × receive/transmit × packets/bytes.

| Flag | Meaning |
|---|---|
| `--port=N` | Repeatable; omitted lists allocated ports. |

```json
{
  "switch": "sw1",
  "ports": [
    { "port": 1,
      "mgmt_rx_packets": 42,  "mgmt_rx_bytes": 3528,
      "mgmt_tx_packets": 42,  "mgmt_tx_bytes": 3528,
      "transit_rx_packets": 100, "transit_rx_bytes": 8400,
      "transit_tx_packets": 100, "transit_tx_bytes": 8400 }
  ]
}
```

`rx` means delivery toward the sandbox; `tx` means traffic from it. Packets are counted at the existing BPF observation points, not as application requests or rates. Management bytes use the observed Ethernet frame length at port/management ingress. Transit TX uses the original frame length; transit RX subtracts the outer GENEVE headers and retains the Ethernet header. These are observed bytes, not a sum of physical-link overheads. Management and transit remain separate; do not add overlapping observations into a universal traffic total.

`pkg/vswitch.Stats(name, ports)` and `Interface.Stats(ports)` provide the same bounded-by-port-list read without starting CLI subprocesses. Consumers should group current bindings per switch and bound batch size. A busy lifecycle lock, replaced switch, failed map read or unconfirmed attach reset fails the whole read; never substitute zeros or retained samples. Free/reserved ports are not current observations. Detach does not erase the map, but its counters cannot be queried as a live attachment. Reset failure does not fail attach; Stats remains unavailable for that attachment. Reattach with a successful reset publishes valid zero counters. The new counter ARRAY uses a kernel lock and internal generation to isolate concurrent TC writes; recreate old PERCPU_ARRAY switches before collecting. Map identity is checked before and after reading, including invalidation by force cleanup during a read.

### `connector-ctl vswitch show`

- `show slots <name> [slot_id]`: dump one zero-based slot or the complete slot table as JSON.
- `show config <name>`: dump in-kernel switch_config plus metadata's transit device, management planes and management services.

For allocated slots, show reports configured `transit_geneve_vni` and total wire `geneve_opts_len`, including the locator; opaque option bytes are not printed by default. A TLV configuration includes:

```json
{
  "geneve_locator": "tlv",
  "geneve_port": 6081,
  "geneve_tlv_locator": "0102:81"
}
```

### `connector-ctl vswitch dhcp`

The embedded DHCP client/server supports debugging transit `auto` addressing and E2E topologies.

- `dhcp request --dev=<iface> [--timeout=5s] [--retries=3]`: make a DHCP request on the interface and print the result.
- `dhcp serve --dev=<iface> --server-ip=<ip> --pool=<a.b.c.d-a.b.c.e> [--gateway=<ip>] [--dns=<ip,...>] [--lease-time=1h]`: run a simple DHCP server; gateway defaults to server-ip.

### `connector-ctl tapfd get`

This **subcommand of the same connector-ctl binary** is independent of switch state. It opens a TAP and sends its IFF_VNET_HDR queue descriptor through TAPFD_SOCKET with SCM_RIGHTS. Use it when a consumer only needs a TAP descriptor, without the vswitch data plane, such as simple/test topologies. Before handoff it always brings the TAP UP, including an existing device; `--host-cidr` additionally assigns an address. It is not a read-only open of an existing TAP.

```text
connector-ctl tapfd get <tap>            # Open an existing TAP and hand off its queue
connector-ctl tapfd get --new [<tap>]    # Create if absent; kernel chooses an omitted name
```

| Flag | Meaning |
|---|---|
| `--new` | Create the named TAP if missing; default requires an existing device. |
| `--host-cidr=IP/N` | Assign the optional host-side IP/CIDR for point-to-point connectivity tests. TAP bring-up happens even without this flag. |
| `--mac=...` | Guest MAC in handoff metadata. |
| `--ip=...` | Guest inner IP in metadata, with or without a CIDR prefix. |

A TAP created by `--new` is **not persistent**: the handed-off descriptor keeps it alive, and it disappears when all references close. This differs from persistent vswitch TAP ports ([Port modes: veth and TAP](vswitch.md#port-modes-veth-and-tap)).

### Configuration file (`--config`)

`start` / `serve` accept JSON with these field/flag mappings:

| JSON field | CLI counterpart |
|---|---|
| `switch_name` | Positional switch_name. |
| `switch_netns` | `--netns`. |
| `port_netns` | `--port-netns`. |
| `num_ports` | `--ports`. |
| `mac_addr` | `--mac-addr`. |
| `floating_ip_base` | `--floating-ip-base`. |
| `generation_bits` | `--generation-bits`; default 0. |
| `mgmt_extracts` (array) | `--mgmt-extract`. |
| `mgmt_services` (array) | `--mgmt-service`. |
| `transit_dev` / `transit_dev_addr` / `transit_dev_mtu` | Corresponding `--transit-dev*` flags. |
| `geneve_locator` / `geneve_port_base` / `geneve_tlv_locator` / `geneve_encap_eth` | Corresponding `--geneve-*` flags. |
| `mtu` | `--mtu`. |
| `port_mac_addr` | `--port-mac-addr`. |

With `--config`, the positional switch name overrides the file's name, but ordinary switch flags are not merged as field-by-field overrides. `--mode` still selects the CLI's auto-provision mode; use `provision --mode` for a later reserved-slot operation. Keep the **total extraction CIDRs across planes within three**: the slot ABI holds only three, and current provisioning stops adding routes at that limit. A successful JSON parse is not evidence that additional routes reached the data plane; inspect slots when checking deployment.

```json
{
  "switch_name": "sw0",
  "switch_netns": "sw0_vswitch",
  "num_ports": 4096,
  "mac_addr": "02:00:00:00:00:01",
  "floating_ip_base": "100.100.96.0",
  "mgmt_extracts": [":sw0_m0:169.254.169.254/32"],
  "mgmt_services": ["169.254.169.254:80:127.0.0.1:19254"],
  "transit_dev": "eth1",
  "transit_dev_addr": "auto",
  "transit_dev_mtu": "auto",
  "geneve_locator": "tlv",
  "geneve_tlv_locator": "0102:81"
}
```


### `connector-ctl vswitch set-port-up`

`attach --admin-down` returns an allocated port with traffic blocked (`admin_down: true`). Omit the flag for ordinary immediately-up Attach. A down TAP port still permits `open-port`/SCM_RIGHTS handoff. Then commit the entire final network configuration:

```bash
connector-ctl vswitch attach sw0 --port=3 --inner-ip=169.254.1.1 --admin-down
# The owner may now hand off the TAP FD and prepare the guest's final address.
connector-ctl vswitch set-port-up sw0 --port=3 --inner-ip=169.254.2.2 \
  --transit-gateway-ip=10.0.0.2 --transit-geneve-vni=42 \
  --transit-geneve-opt=0102:02:0000002a --transit-mac-addr=02:00:00:00:00:09
connector-ctl vswitch show slots sw0 2
```

`--port` and `--inner-ip` are required. The transit flags are optional final values; omission clears provisional transit values/options. `set-port-up` returns success without reallocation or another FD. It rejects Free, Reserved and already-up ports. Preparation failures retain down; a lost success reply does not undo publication. Same-port calls must be ordered by the owner; no switch-wide lock is added. Detach accepts both up and completed down attachments. See [the architecture contract](vswitch.md#deferred-port-activation) and [TAPFD requests](tapfd.md#deferred-attachment-requests).

## Troubleshooting

| Symptom | Cause/action |
|---|---|
| `transit device not found` | Check TRANSIT_DEV against the intended caller namespace's `ip link`; a running switch may already own it in switch-netns. |
| `transit device eth1 must be DOWN before use` | Confirm it is the dedicated unused device, set it DOWN and retry. |
| `failed to pin maps: ...bpffs not mounted` | Mount bpffs at /sys/fs/bpf and configure persistent mounting as appropriate. |
| `switch already exists` | Inspect the existing switch/config first. Stop it normally when replacement is intended; do not delete pins under active forwarding as a routine restart procedure. |
| ABI incompatible after upgrade | Drain/stop consumers and use normal or forced cleanup. For damaged state, force-clean only removes pins; explicitly inspect/remove orphaned devices/TC and return transit before recreating. |
| `port not provisioned` or a Reserved slot cannot attach | Inspect `ports_available`/`ports_reserved` or the selected slot, wait/retry, or explicitly repair the Reserved slot. `PortDevicesReady=True` alone does not prove allocatable capacity. |
| open-port reports `port not attached` | Attach first, then request the queue. |

### GENEVE packet capture

Use the actual switch namespace, transit device and configured locator ports; the filter below is an example, not a universal port range. Capture only authorized traffic and protect captures because payloads and topology can be sensitive.

Capture on the switch namespace's transit device:

```bash
ip netns exec sw0_vswitch tcpdump -ni eth1 -vv -XX 'udp port 6081 or udp portrange 50000-54095'
connector-ctl vswitch show config sw0
connector-ctl vswitch show slots sw0
```

Inspect UDP destination, the 24-bit VNI, OptLen, base C, option class/type/length/data and the start of the inner payload. TLV locator data must be the zero-based slot ID in big-endian 32-bit form.

## Gateway interoperability acceptance and recovery

Use an isolated test switch/namespace and an operator-managed gateway. Connector
provides the host switch and TAP handoff, not an external gateway product or a
policy engine. Gateway implementation, routing/NAT, DNS, policy and audit belong
to its operator. The [GENEVE wire contract](vswitch.md#geneve-tunnels),
[MTU contract](vswitch.md#mtu-validation) and [TAP ownership](tapfd.md)
remain authoritative.

### Prepared platform validation

Product E2E is separate from these source/build targets. Use a prebuilt platform tree containing the matching connector cases and common runner, then prepare a new workspace and run the network suite:

```bash
PLATFORM=/path/to/prebuilt-platform
WORKDIR=/path/to/new-network-workspace
python3 "$PLATFORM/test/e2e/e2e" prepare --release-dir "$PLATFORM" --workdir "$WORKDIR"
sudo python3 "$WORKDIR/test/e2e/e2e" run --workdir "$WORKDIR" --suite network
```

CI uses this same platform runner. It executes the selected cases with prebuilt products, without compiling Go code or invoking a component-owned runner. Run only in an isolated test environment with the prerequisites required by every selected case; missing selected prerequisites are failures, not successful skips.

The network cases check for root when they start. The common runner does not elevate privileges, so retain `sudo` (or use a root shell) when selecting an individual case with `--include network.tap.sh` as well.

### Two-ended acceptance

1. Agree on IP-over-GENEVE versus Ether-over-GENEVE, `port`/`vni`/`tlv` locator,
   UDP destination, VNI and any opaque policy options. Linux GENEVE bridge peers
   need the Ethernet mode. Record the actual attach result: CLI port is one-based,
   wire slot is zero-based; retain any configured generation. Gateway return
   packets must use the configured gateway source IP and valid VNI/locator;
   do not echo outbound opaque options. TLV return carries only the prescribed
   locator. A generic GENEVE endpoint is not proof of this compatibility.
2. Verify underlay routes/neighbors and bidirectional UDP reachability. Derive
   MTU from the actual encapsulation and options, then inspect transit and actual
   port/guest MTUs. Startup `--mtu` does not propagate to newly provisioned ports
   in the current two-phase path. Verify the gateway's return route to the host;
   outbound packet capture alone is not success.
3. Before cleanup in [Manual first switch](#manual-first-switch), use its allocated `port` and the VMM that received the TAP FD,
   and run a known request/response between the guest and a controlled gateway-side
   endpoint. Compare nonce and payload in both directions. Test small and
   near-effective-MTU payloads, TCP and UDP, and guest DNS if required. Capture
   both ends using [GENEVE packet capture](#geneve-packet-capture) and compare `connector-ctl vswitch stats sw1 --port="$port"` deltas with
   gateway observations. Counters are not application success or policy proof.
4. In this private fixture, test an allowed destination and a gateway-denied
   destination/tenant; inspect gateway decisions against the assigned identity.
   Verify no direct sandbox-to-sandbox forwarding, invalid return locator/VNI
   rejection and management-only destinations separately. Do not apply test policy
   or forged traffic to production networks. Stop on cross-identity delivery.
5. Close the test VMM/FD owner, detach only its recorded port, and stop only the
   test switch. Confirm the dedicated transit device returns to the expected
   namespace; the gateway operator removes only this fixture's routes/policy.

For a concrete TCP request/response probe, the gateway operator can expose this
temporary Python 3 endpoint on an approved test IP. Run only the curl command
inside the attached guest (with curl installed); it must return the exact proof
line. Record both captures and per-port stats before and after. This checks the
return path; repeat with your gateway's UDP/DNS fixture and allowed/denied policy
cases rather than interpreting one HTTP success as complete policy acceptance.

```bash
# Gateway-side test endpoint, in the operator-selected test network
TEST_ROOT=$(mktemp -d)
printf 'kuasar-return-path-proof\n' > "$TEST_ROOT/probe"
python3 -m http.server 18080 --bind "$TEST_IP" --directory "$TEST_ROOT" &
TEST_PID=$!
```

```bash
# Run inside the attached test guest, with the same reachable TEST_IP:
curl --fail --max-time 5 "http://$TEST_IP:18080/probe"
```

```bash
# Back at the gateway-side endpoint, after verification:
kill "$TEST_PID"
wait "$TEST_PID" 2>/dev/null || true
rm -rf -- "$TEST_ROOT"
```

### Recovery by failure domain

| Failure | Safe recovery and acceptance |
|---|---|
| `serve` exits; namespace/devices/TC/pins intact | Inspect status/config and restart the same service/config. In-kernel forwarding may survive. Check health/TAPFD service and existing bidirectional traffic; do not detach all ports as a daemon restart ritual. |
| Namespace, TAP/transit device or pinned state damaged | Stop admission and coordinate orchestrator/sandboxer to drain or stop affected consumers. Inventory ownership, ports/generations and committed checkpoints. Repair/recreate through management operations only after owners release resources. Reattach via the owner; old FDs/port numbers are not automatically valid. Validate new traffic and cleanup orphaned resources explicitly. |
| ABI upgrade (including old stats PERCPU_ARRAY) | Drain consumers, preserve required snapshots, stop the old switch, recreate with matching userspace/BPF ABI, then let owners allocate new bindings. Never replace live maps/TC in place to satisfy a new reader. Force cleanup is damaged-state handling and may leave devices/TC; inspect them before recreation. |

Neither restarting serve nor rebuilding a switch restores lost guest memory.
For a paused sandbox, orchestrator/sandboxer own eligible restore, network rebinding
and resource admission; Connector does not reassign platform identity. Re-run the
allow/deny and return-path checks after recovery before reopening admission.

## See also

- [Network invariants](vswitch.md)
- [TAPFD protocol](tapfd.md)
- [Build and validation](../CONTRIBUTING.md#build-and-validation)
