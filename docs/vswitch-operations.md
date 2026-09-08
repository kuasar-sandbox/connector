[English](vswitch-operations.md) | [简体中文](vswitch-operations_zh.md)

# vSwitch operations

Use this guide to build, configure, deploy, inspect and maintain a connector vSwitch. [vswitch.md](vswitch.md) owns forwarding, BPF ABI, identity, isolation, concurrency and resource-lifecycle invariants. [tapfd.md](tapfd.md) remains the independently implementable provider/consumer handoff protocol; using that protocol does not require this vSwitch.

<a id="3-部署"></a>

<a id="3-deployment"></a>
## 1. Deployment and prerequisites

<a id="31-系统要求"></a>

<a id="31-system-requirements"></a>
### 1.1 System requirements

- Documented kernel baseline: Linux **5.10+**, with the needed TC/BPF features and BTF available at `/sys/kernel/btf/vmlinux`. Verify the actual kernel configuration and privileged tests; a version number alone is insufficient.
- bpffs mounted at `/sys/fs/bpf`, for example `mount -t bpf bpf /sys/fs/bpf`.
- Root execution for the privileged BPF/network/namespace paths, with capability requirements discussed in [required privileges](vswitch.md#73-required-privileges).
- **Go 1.24+** for building; regenerating BPF bytecode additionally needs **Clang/LLVM 12+**.

<a id="32-构建"></a>

<a id="32-build"></a>
### 1.2 Build

```bash
make build                      # bin/<arch>/connector-ctl, with a native-arch bin/ symlink
make build TARGET_ARCH=aarch64  # Pure-Go cross-build; amd64/arm64 aliases are also accepted
make release VERSION=vX.Y.Z     # Package and validate build/release-bundle
make generate                   # Regenerate changed BPF source; clang 12+ (prebuilt .o files are tracked)
make test                       # Unit tests
sudo make test-integration      # Integration: root and a BPF-capable kernel
sudo make test-e2e              # test/e2e/run_all.sh
sudo make bench                 # Benchmarks: root and iperf3
make lint                       # go vet
make fmt                        # Go formatting and clang-format
make vmlinux                    # Regenerate bpf/vmlinux.h; requires bpftool
```

<a id="33-systemd-集成"></a>

<a id="33-systemd-integration"></a>
### 1.3 systemd integration

The [dist directory](../dist/) supplies three templates:

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

<a id="34-首次启动"></a>

<a id="34-first-startup"></a>
### 1.4 First startup

1. Install the binary at the template's `/usr/sbin/connector-ctl` path and the selected templates at the locations above. Identify the dedicated transit device with `ip -br link`, then edit `/etc/connector/switch.conf`, including TRANSIT_DEV and TRANSIT_DEV_ADDR.
2. Put that unused transit device DOWN with `ip link set "$TRANSIT_DEV" down`; startup moves it into switch-netns. Confirm the physical underlay supports the configured encapsulation MTU.
3. Run `sudo systemctl daemon-reload`, then `sudo systemctl start connector-vswitch` for the supplied **connector-vswitch.service** filename.
4. Check that `systemctl status connector-vswitch` is active, `connector-ctl vswitch status sw0 --ready` returns zero, and `ip netns list` shows the configured namespaces. READY=1 can precede complete port provisioning ([§6.5](vswitch.md#65-two-phase-startup)).
5. Enable boot startup with `sudo systemctl enable connector-vswitch`.


<a id="2-命令行接口"></a>

<a id="2-command-line-interface"></a>
## 2. Command-line and configuration reference

Most query and one-shot commands emit JSON; `serve` stays resident and reports health/progress. Run privileged network/BPF operations as root with the required kernel capabilities ([§7.3](vswitch.md#73-required-privileges)).

<a id="21-子命令总览"></a>

### 2.1 Subcommands

| Command | Purpose |
|---|---|
| `start [switch_name]` | StartReserved followed by synchronous ProvisionPorts, then exit. |
| `serve [switch_name]` | Resident systemd service: StartReserved, optional TAPFD listen, READY=1, background ProvisionPorts and health/watchdog loop. |
| `stop <name>` | Release ports and switch resources, unpin maps, delete owned devices and move transit into the stop caller's namespace. |
| `attach <name>` | Allocate a slot by CAS Free→IP; optionally move a veth peer into the sandbox namespace. |
| `detach <name> --port=N` | CAS Allocated→Free; Reserved is not a temporary detach state. |
| `reserve <name> --port=N` | Mark a slot Reserved to prevent subsequent attachment, for upgrade/drain. |
| `provision <name>` | Create devices for Reserved slots, in bulk or for one repair. |
| `open-port <name> --port=N` | Open a TAP queue and send its descriptor to `TAPFD_SOCKET`; provider helper in tapfd.md §3. |
| `status <name>` | Conditions-based status; `--ready` expresses readiness as an exit code. |
| `stats <name>` | Management/transit × rx/tx × packets/bytes per port. |
| `show slots\|config <name>` | Dump slots or in-kernel configuration. |
| `dhcp request\|serve` | Embedded DHCP client/server for debugging and test topologies. |

A typical fresh-switch workflow in TAP mode, the default. Use a dedicated transit device that can safely be handed over; the named namespaces must exist:

```bash
# Prepare namespaces and a dedicated, unused transit device
ip netns add sw_ns
ip netns add mgmt_ns
ip link set eth1 down

# Create the switch; the underlay must support the resulting MTU
connector-ctl vswitch start sw1 --netns=sw_ns --ports=128 \
    --mac-addr=02:00:00:00:00:01 --floating-ip-base=100.100.96.0 \
    --mgmt-extract=mgmt_ns:eth0:169.254.169.254/32 \
    --transit-dev=eth1 --transit-dev-addr=10.0.0.1/24:10.0.0.2 \
    --transit-dev-mtu=auto
# Configure the service-owned VIP explicitly.
ip netns exec mgmt_ns ip addr replace 169.254.169.254/32 dev eth0

# Allocate a port; a TAPFD-capable VMM receiver must be waiting on /tmp/recv.sock
connector-ctl vswitch attach sw1 --inner-ip=169.254.1.1 \
    --transit-gateway-ip=10.0.0.2 --transit-geneve-vni=100
TAPFD_SOCKET=/tmp/recv.sock connector-ctl vswitch open-port sw1 --port=1

# Release the port and stop from the namespace that should receive transit
connector-ctl vswitch detach sw1 --port=1
connector-ctl vswitch stop sw1
```

### 2.2 `connector-ctl vswitch start` / `serve`

`start` finishes initialization synchronously and exits; `serve` implements resident systemd `Type=notify` operation ([§6.5](vswitch.md#65-two-phase-startup)). `switch_name` can be omitted when provided by `--config` ([§2.14](#214-configuration-file---config)).

| Flag | Required | Meaning |
|---|---|---|
| `--netns` | Yes | Existing internal switch namespace. |
| `--mac-addr` | Yes | Switch MAC base used by MAC derivation ([§6.1](vswitch.md#61-mac-derivation)); the first four bytes are retained. |
| `--ports` | Yes | Number of ports, 1–4096. |
| `--floating-ip-base` | Yes | Floating-IP base; increment by zero-based slot ID. |
| `--port-netns` | For veth provisioning | Initial location of veth peers. TAP does not need it. Reserved-only startup may omit it, but it must be supplied at start if later veth provisioning is planned. |
| `--mode` | No | Automatic provision mode: `tap` (default) or `veth`. With `--reserved`, it validates the intended startup mode but does not persist a mode override for a future provision invocation. |
| `--mgmt-extract` | No | Repeatable `<netns>:<dev>:<cidr1>,<cidr2>,...`, within the per-slot extraction limit ([§1.3](vswitch.md#13-boundaries)). CIDRs do not configure interface addresses. Empty namespace (`:<dev>:<cidrs>`) leaves the management peer in the caller/host namespace. |
| `--mgmt-service` | No | Repeatable `<VIP>:<vport>:<targetIP>:<targetPort>`. VIP must match extraction; target IP/port must be globally unique. Applies to TCP and UDP ([§4.3](vswitch.md#43-packet-paths)). A loopback target needs `route_localnet=1` on the management device. |
| `--transit-dev` | No | Uplink moved from the start caller's namespace into the switch. It must be **DOWN** to avoid taking over an active interface. Stop moves it into the stop caller's namespace. |
| `--transit-dev-addr` | No | `<ip>/<prefix>:<nexthop>` or `auto` for DHCP ([§6.9](vswitch.md#69-dhcp-gateway-inference)). |
| `--transit-dev-mtu` | No | `auto` or an explicit MTU; default leaves it unchanged and validates ([§6.8](vswitch.md#68-mtu-validation)). |
| `--geneve-locator` | No | `port` (default), `vni` or `tlv`; encodes zero-based slot ID ([§6.2](vswitch.md#62-geneve-tunnels)). |
| `--geneve-port-base` | No | GENEVE UDP destination base for `port` locator; default 50000. |
| `--geneve-tlv-locator` | For `tlv` | Exact wire `CLASS:TYPE`, for example `0102:81` ([§6.2](vswitch.md#62-geneve-tunnels)). |
| `--geneve-encap-eth` | No | Ether-over-GENEVE; default is IP-over-GENEVE. |
| `--mtu` | No | Requested startup MTU used for management devices and transit-budget checks. Current two-phase provision does not propagate it to new TAP/veth ports; inspect actual port MTU ([§6.8](vswitch.md#68-mtu-validation)). |
| `--port-mac-addr` | No | `fixed` (default), `per-port`, or an explicit MAC ([§6.1](vswitch.md#61-mac-derivation)). |
| `--reserved` | No | StartReserved only. The saved switch configuration supplies port-netns, and provision has no independent override; provide `--port-netns` now if later using veth. |
| `--config` | No | Load JSON configuration ([§2.14](#214-configuration-file---config)). |

`serve` shares the switch flags but has no `--reserved`. Additional flags:

| Flag | Meaning |
|---|---|
| `--watch-interval` | Health-check interval, default 30s. |
| `--tapfd-listen` | Persistent switch/TAPFD Unix socket. Accepts `TAPFD/1 PREPARE`, `OPEN`, `RELEASE`; OPEN returns `TAPFD/1 OK`, metadata and SCM_RIGHTS. See tapfd.md §4. |

Example `start` output (illustrative configured values, not the result of the preceding 128-port command):

```json
{
  "switch": "sw1",
  "switch_netns": "netns_switch",
  "switch_maps": {
    "slots":           "/sys/fs/bpf/sw1/slots",
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

### 2.3 `connector-ctl vswitch stop`

Stop uses ReleasePorts then StopReleased: remove owned ports, management/dummy devices and TC references, unpin BPF maps, and move transit into the **stop caller's namespace**. To return it to the original host namespace, invoke stop there; the implementation does not restore a separately remembered origin namespace.

| Flag | Meaning |
|---|---|
| `--force` | Release in-use ports before stopping, using two cleanup passes. |
| `--force-clean` | Recovery for a damaged switch: unpin BPF resources without device cleanup. Orphaned netdevs/TC resources may need explicit cleanup; this does not itself prove forwarding has stopped. |

### 2.4 `connector-ctl vswitch attach`

Allocate a port by CAS Free→IP; veth mode can also move the peer into a sandbox namespace. A port that is not yet provisioned cannot be used; callers of asynchronous startup should handle the not-provisioned/no-available-port state and retry according to readiness ([§6.5](vswitch.md#65-two-phase-startup)).

| Flag | Meaning |
|---|---|
| `--inner-ip=IP` | Required sandbox internal IPv4 address. |
| `--port=N` | Select a one-based slot; omitted/zero means automatic allocation. |
| `--to-netns=NS` | Move the peer into this namespace, veth only. |
| `--transit-gateway-ip=IP` | GENEVE outer destination IPv4 address. |
| `--transit-geneve-vni=N` | Configured VNI, subject to the locator's range. |
| `--transit-geneve-opt=CLASS:TYPE:DATA` | Repeatable outbound opaque option. Hex data length must be a multiple of four bytes; `CLASS:TYPE:` represents empty data ([§6.2](vswitch.md#62-geneve-tunnels)). |
| `--transit-mac-addr=MAC` | Inner Ethernet destination for Ether-over-GENEVE; default broadcast. |
| `--skip-device` | Skip veth namespace movement and retain slot control updates. Rejected for TAP attachment. |
| `--open-port` | TAP only: after allocation, send the queue through `TAPFD_SOCKET`. Transfer failure triggers a detach/rollback attempt; verify state before retry if cleanup also fails. |

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

In attach/show JSON, `geneve_opts_len` is the **total wire option length**, including an automatic TLV locator, and zero is omitted. The raw slot field of the same name stores only opaque-option bytes ([§5.3](vswitch.md#53-data-plane-abi)).

Combined `attach --open-port` output, selected fields:

```json
{
  "port": 4, "port_dev": "sw1-t4",
  "port_mac": "02:00:00:00:80:01",
  "inner_ip": "169.254.4.1",
  "tap_sent_to": "/tmp/recv.sock"
}
```

### 2.5 `connector-ctl vswitch detach`

For a new switch, detach holds the per-switch control flock, directly CASes Allocated→Free, then clears the options fast-path hint. Reserved is reserved for explicit reserve/provision/stop state, not a detach intermediate. Detach leaves the fixed-size options map value and other transit fields for the next Attach to overwrite; free slots are ignored by the data plane. Old switches without `geneve_opts` retain their CAS-only path.

TAP detach performs no device move. For veth, `--from-netns` moves the peer back into port-netns; without it, detach verifies that the peer is already there. Device/namespace failure can prevent completion; inspect the error and slot state.

| Flag | Meaning |
|---|---|
| `--port=N` | Required one-based port. |
| `--from-netns=NS` | Current sandbox namespace containing the veth peer. |
| `--skip-device` | Skip device movement/checks, for either veth or TAP. |

### 2.6 `connector-ctl vswitch reserve`

Mark a port Reserved to prevent new attachment, for upgrade/drain or before changing its device kind with provision ([§6.6](vswitch.md#66-port-modes-veth-and-tap)).

| Flag | Required | Meaning |
|---|---|---|
| `--port=N` | Yes | One-based port. |
| `--force` | No | Allow Allocated→Reserved; default permits only Free→Reserved. |

### 2.7 `connector-ctl vswitch provision`

Create devices for Reserved slots and expose them to Attach. Free/Allocated slots are skipped; failed Reserved slots can be repaired individually.

| Flag | Meaning |
|---|---|
| `--port=N` | Repair only this slot; mutually exclusive with `--count`. |
| `--count=N` | Limit devices created in this invocation; zero means all. Mutually exclusive with `--port`. |
| `--mode=tap\|veth` | Device kind, default TAP. For a Reserved slot changing kind, create the new device, commit the new ifindex, then remove the old device. |

### 2.8 `connector-ctl vswitch open-port`

The dynamic-provider helper from [tapfd.md](tapfd.md) §3 enters switch-netns and opens the persistent TAP with `open(/dev/net/tun)` and `TUNSETIFF(IFF_TAP|IFF_NO_PI|IFF_VNET_HDR)`. It sends the queue descriptor and metadata with SCM_RIGHTS to `TAPFD_SOCKET`, either `fd=N` or a path ([§3.3](tapfd.md#33-advertising-the-socket-tapfd_socket) of tapfd.md). A truthy `TAPFD_WANT_NETNS` appends the switch namespace descriptor after the TAP descriptor and sets `netns_fd=1` ([§3.4](tapfd.md#34-requesting-a-netns-descriptor-tapfd_want_netns)).

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

### 2.9 `connector-ctl vswitch status`

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

### 2.10 `connector-ctl vswitch stats`

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

### 2.11 `connector-ctl vswitch show`

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

### 2.12 `connector-ctl vswitch dhcp`

The embedded DHCP client/server supports debugging transit `auto` addressing and E2E topologies.

- `dhcp request --dev=<iface> [--timeout=5s] [--retries=3]`: make a DHCP request on the interface and print the result.
- `dhcp serve --dev=<iface> --server-ip=<ip> --pool=<a.b.c.d-a.b.c.e> [--gateway=<ip>] [--dns=<ip,...>] [--lease-time=1h]`: run a simple DHCP server; gateway defaults to server-ip.

### 2.13 `connector-ctl tapfd get`

This **subcommand of the same connector-ctl binary** is independent of switch state. It opens a TAP and sends its IFF_VNET_HDR queue descriptor through TAPFD_SOCKET with SCM_RIGHTS. Use it when a consumer only needs a TAP descriptor, without the vswitch data plane, such as simple/test topologies.

```text
connector-ctl tapfd get <tap>            # Open an existing TAP and hand off its queue
connector-ctl tapfd get --new [<tap>]    # Create if absent; kernel chooses an omitted name
```

| Flag | Meaning |
|---|---|
| `--new` | Create the named TAP if missing; default requires an existing device. |
| `--host-cidr=IP/N` | Assign the host-side IP/CIDR and bring the TAP up for point-to-point connectivity tests. |
| `--mac=...` | Guest MAC in handoff metadata. |
| `--ip=...` | Guest inner IP in metadata, with or without a CIDR prefix. |

A TAP created by `--new` is **not persistent**: the handed-off descriptor keeps it alive, and it disappears when all references close. This differs from persistent vswitch TAP ports ([§6.6](vswitch.md#66-port-modes-veth-and-tap)).

<a id="214-配置文件--config"></a>

### 2.14 Configuration file (`--config`)

`start` / `serve` accept JSON with these field/flag mappings:

| JSON field | CLI counterpart |
|---|---|
| `switch_name` | Positional switch_name. |
| `switch_netns` | `--netns`. |
| `port_netns` | `--port-netns`. |
| `num_ports` | `--ports`. |
| `mac_addr` | `--mac-addr`. |
| `floating_ip_base` | `--floating-ip-base`. |
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


<a id="82-故障排除"></a>

<a id="82-troubleshooting"></a>
## 3. Troubleshooting

| Symptom | Cause/action |
|---|---|
| `transit device not found` | Check TRANSIT_DEV against the intended caller namespace's `ip link`; a running switch may already own it in switch-netns. |
| `transit device eth1 must be DOWN before use` | Confirm it is the dedicated unused device, set it DOWN and retry. |
| `failed to pin maps: ...bpffs not mounted` | Mount bpffs at /sys/fs/bpf and configure persistent mounting as appropriate. |
| `switch already exists` | Inspect the existing switch/config first. Stop it normally when replacement is intended; do not delete pins under active forwarding as a routine restart procedure. |
| ABI incompatible after upgrade | Drain/stop consumers and use normal or forced cleanup. For damaged state, force-clean only removes pins; explicitly inspect/remove orphaned devices/TC and return transit before recreating. |
| `port not provisioned` or a Reserved slot cannot attach | Inspect `ports_available`/`ports_reserved` or the selected slot, wait/retry, or explicitly repair the Reserved slot. `PortDevicesReady=True` alone does not prove allocatable capacity. |
| open-port reports `port not attached` | Attach first, then request the queue. |
