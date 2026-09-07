[English](vswitch.md) | [简体中文](vswitch_zh.md)

<a id="vswitch--ebpf-虚拟交换机"></a>

# vswitch — eBPF virtual switch

An eBPF/TC virtual switch providing isolated management and external-network paths for up to **4096 configured sandbox ports** on one host. The CLI is `connector-ctl vswitch`; the same binary also provides `connector-ctl tapfd get` for TAP descriptor handoff. The compiled port capacity is not a guarantee that every host/workload sustains 4096 active MicroVMs.

The forwarding path runs in kernel TC ingress programs. One-shot configuration commands can exit while TC references, pinned maps and network devices retain the data plane. `serve` remains a control/health/TAPFD-provider process; it does not relay forwarded packets. Slot selection uses ingress ifindex, floating IP or the configured GENEVE locator, rather than trusting a sandbox-supplied source IP/MAC as port identity. The local program has no direct port-to-port branch, answers ARP itself and rewrites Ethernet source addresses. These properties can be audited in the source; external gateway and management-service policy remain separate boundaries.

In TAP mode, `SCM_RIGHTS` passes the queue descriptor to a VMM such as Cloud Hypervisor or Firecracker. The independent provider/consumer contract is in [tapfd.md](tapfd.md).

<a id="1-概述"></a>

## 1. Overview

<a id="11-业务问题"></a>

### 1.1 Problem

The target is networking for thousands of MicroVMs on one host: in-kernel forwarding without a userspace packet relay, local sandbox isolation, roughly 4K port capacity, and separation of control-process failure from forwarding. A bridge plus netfilter, OVS/OVN, or per-VM veth orchestration can implement other valid designs, but their isolation, broadcast, routing and lifecycle policies must be configured appropriately. This project chooses a smaller dedicated forwarding model; it does not establish a universal per-port rule count or measured performance disadvantage for those alternatives.

Forwarding decisions are concentrated in [bpf/switch_kern.c](../bpf/switch_kern.c), with control operations updating BPF configuration and devices. The eBPF/TC design provides:

- Forwarding in the kernel without a userspace packet relay. This does not guarantee zero memory copies or context switches across the complete guest/VMM/network path.
- TC references retaining programs and bpffs pins retaining maps after a control process exits, as long as the underlying resources remain intact.
- One dedicated forwarding implementation to review, rather than a policy assembled across bridge forwarding tables and multiple firewall chains.
- Per-CPU counters and bpftool inspection.

<a id="12-设计原则"></a>

### 1.2 Design principles

1. **Local isolation:** no direct port-to-port forwarding branch; ARP replies and output MAC addresses are controlled by the switch.
2. **Stateless forwarding:** no connection table; decisions use slot configuration and IP/UDP/GENEVE locator arithmetic, with optional static management-service translation.
3. **Independent process lifecycle:** `start`, `attach` and `detach` return while the in-kernel data plane continues.
4. **Concurrent ownership:** mmap and atomic CAS establish slot ownership. New switches with `geneve_opts` also serialize compound Attach/Detach/Reserve updates with a per-switch flock; legacy switches without that map retain the CAS-only path.
5. **Observability:** per-port, per-direction, management/transit packet and byte counters; status uses Kubernetes-style Conditions.
6. **systemd integration:** `Type=notify`, watchdog keepalives and reopening pinned resources after restart.

<a id="13-边界"></a>

### 1.3 Boundaries

- One transit uplink device. Upstream networking owns ECMP or link bonding.
- No data-plane rate limiting/QoS; deployments can use VMM, TC qdisc or appropriate cgroup-BPF mechanisms.
- No connection tracking, stateful NAT table or L7 filtering. Management IP/port rewriting is static and stateless.
- `--mgmt-extract` / `--mgmt-service` are fixed at start; changing them requires switch recreation.
- Extraction CIDRs classify traffic only. Deployment owns management-interface addresses, local routes, service listeners and relevant sysctls.
- `MAX_PORTS=4096` is compiled into BPF and tied to the 12-bit slot-locator layout (§6.2).
- Control is local to a host; there is no cross-host state synchronization.

<a id="14-部署形态"></a>

### 1.4 Deployment shape

```mermaid
flowchart TD
  VM["MicroVMs: TAP or veth ports"] --> TC["Switch netns: shared TC ingress"]
  TC --> MG["Management peer: metadata/service netns or host"]
  TC --> TR["Transit device"]
  TR --> GW["External GENEVE gateway"]
  MG --> TC
  GW --> TR
  TC --> VM
```

This fits a single-host MicroVM platform using Firecracker, Cloud Hypervisor or QEMU/KVM where each VM needs controlled egress and configured port capacity stays within 4096. It is not a distributed SDN control plane, a fine-grained L4+ multi-tenant policy manager or a connection-tracking/L7 security gateway.

<a id="2-命令行接口"></a>

## 2. Command-line interface

Most query and one-shot commands emit JSON; `serve` stays resident and reports health/progress. Run privileged network/BPF operations as root with the required kernel capabilities (§7.3).

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

`start` finishes initialization synchronously and exits; `serve` implements resident systemd `Type=notify` operation (§6.5). `switch_name` can be omitted when provided by `--config` (§2.14).

| Flag | Required | Meaning |
|---|---|---|
| `--netns` | Yes | Existing internal switch namespace. |
| `--mac-addr` | Yes | Switch MAC base used by MAC derivation (§6.1); the first four bytes are retained. |
| `--ports` | Yes | Number of ports, 1–4096. |
| `--floating-ip-base` | Yes | Floating-IP base; increment by zero-based slot ID. |
| `--port-netns` | For veth provisioning | Initial location of veth peers. TAP does not need it. Reserved-only startup may omit it, but it must be supplied at start if later veth provisioning is planned. |
| `--mode` | No | Automatic provision mode: `tap` (default) or `veth`. With `--reserved`, it validates the intended startup mode but does not persist a mode override for a future provision invocation. |
| `--mgmt-extract` | No | Repeatable `<netns>:<dev>:<cidr1>,<cidr2>,...`, within the per-slot extraction limit (§1.3). CIDRs do not configure interface addresses. Empty namespace (`:<dev>:<cidrs>`) leaves the management peer in the caller/host namespace. |
| `--mgmt-service` | No | Repeatable `<VIP>:<vport>:<targetIP>:<targetPort>`. VIP must match extraction; target IP/port must be globally unique. Applies to TCP and UDP (§4.3). A loopback target needs `route_localnet=1` on the management device. |
| `--transit-dev` | No | Uplink moved from the start caller's namespace into the switch. It must be **DOWN** to avoid taking over an active interface. Stop moves it into the stop caller's namespace. |
| `--transit-dev-addr` | No | `<ip>/<prefix>:<nexthop>` or `auto` for DHCP (§6.9). |
| `--transit-dev-mtu` | No | `auto` or an explicit MTU; default leaves it unchanged and validates (§6.8). |
| `--geneve-locator` | No | `port` (default), `vni` or `tlv`; encodes zero-based slot ID (§6.2). |
| `--geneve-port-base` | No | GENEVE UDP destination base for `port` locator; default 50000. |
| `--geneve-tlv-locator` | For `tlv` | Exact wire `CLASS:TYPE`, for example `0102:81` (§6.2). |
| `--geneve-encap-eth` | No | Ether-over-GENEVE; default is IP-over-GENEVE. |
| `--mtu` | No | Requested startup MTU used for management devices and transit-budget checks. Current two-phase provision does not propagate it to new TAP/veth ports; inspect actual port MTU (§6.8). |
| `--port-mac-addr` | No | `fixed` (default), `per-port`, or an explicit MAC (§6.1). |
| `--reserved` | No | StartReserved only. The saved switch configuration supplies port-netns, and provision has no independent override; provide `--port-netns` now if later using veth. |
| `--config` | No | Load JSON configuration (§2.14). |

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

Allocate a port by CAS Free→IP; veth mode can also move the peer into a sandbox namespace. A port that is not yet provisioned cannot be used; callers of asynchronous startup should handle the not-provisioned/no-available-port state and retry according to readiness (§6.5).

| Flag | Meaning |
|---|---|
| `--inner-ip=IP` | Required sandbox internal IPv4 address. |
| `--port=N` | Select a one-based slot; omitted/zero means automatic allocation. |
| `--to-netns=NS` | Move the peer into this namespace, veth only. |
| `--transit-gateway-ip=IP` | GENEVE outer destination IPv4 address. |
| `--transit-geneve-vni=N` | Configured VNI, subject to the locator's range. |
| `--transit-geneve-opt=CLASS:TYPE:DATA` | Repeatable outbound opaque option. Hex data length must be a multiple of four bytes; `CLASS:TYPE:` represents empty data (§6.2). |
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

In attach/show JSON, `geneve_opts_len` is the **total wire option length**, including an automatic TLV locator, and zero is omitted. The raw slot field of the same name stores only opaque-option bytes (§5.3).

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

Mark a port Reserved to prevent new attachment, for upgrade/drain or before changing its device kind with provision (§6.6).

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

The dynamic-provider helper from [tapfd.md](tapfd.md) §3 enters switch-netns and opens the persistent TAP with `open(/dev/net/tun)` and `TUNSETIFF(IFF_TAP|IFF_NO_PI|IFF_VNET_HDR)`. It sends the queue descriptor and metadata with SCM_RIGHTS to `TAPFD_SOCKET`, either `fd=N` or a path (§3.3 of tapfd.md). A truthy `TAPFD_WANT_NETNS` appends the switch namespace descriptor after the TAP descriptor and sets `netns_fd=1` (§3.4).

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

Conditions fragment before provisioning completes:

```json
"conditions": [
  { "type": "Ready",        "status": "False", "reason": "PortsReserved" },
  { "type": "PortReserved", "status": "True",
    "message": "all 4096 ports still in Reserved state (ProvisionPorts pending)" }
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

A TAP created by `--new` is **not persistent**: the handed-off descriptor keeps it alive, and it disappears when all references close. This differs from persistent vswitch TAP ports (§6.6).

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

<a id="3-部署"></a>

## 3. Deployment

<a id="31-系统要求"></a>

### 3.1 System requirements

- Documented kernel baseline: Linux **5.10+**, with the needed TC/BPF features and BTF available at `/sys/kernel/btf/vmlinux`. Verify the actual kernel configuration and privileged tests; a version number alone is insufficient.
- bpffs mounted at `/sys/fs/bpf`, for example `mount -t bpf bpf /sys/fs/bpf`.
- Root execution for the privileged BPF/network/namespace paths, with capability requirements discussed in §7.3.
- **Go 1.24+** for building; regenerating BPF bytecode additionally needs **Clang/LLVM 12+**.

<a id="32-构建"></a>

### 3.2 Build

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

### 3.3 systemd integration

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

### 3.4 First startup

1. Install the binary at the template's `/usr/sbin/connector-ctl` path and the selected templates at the locations above. Identify the dedicated transit device with `ip -br link`, then edit `/etc/connector/switch.conf`, including TRANSIT_DEV and TRANSIT_DEV_ADDR.
2. Put that unused transit device DOWN with `ip link set "$TRANSIT_DEV" down`; startup moves it into switch-netns. Confirm the physical underlay supports the configured encapsulation MTU.
3. Run `sudo systemctl daemon-reload`, then `sudo systemctl start connector-vswitch` for the supplied **connector-vswitch.service** filename.
4. Check that `systemctl status connector-vswitch` is active, `connector-ctl vswitch status sw0 --ready` returns zero, and `ip netns list` shows the configured namespaces. READY=1 can precede complete port provisioning (§6.5).
5. Enable boot startup with `sudo systemctl enable connector-vswitch`.

<a id="4-网络架构"></a>

## 4. Network architecture

<a id="41-拓扑与设备命名"></a>

### 4.1 Topology and device names

```mermaid
flowchart TD
  P["Sandbox netns: sw1-pX"] <--> N
  V["VMM: TAP queue via SCM_RIGHTS"] <--> T
  subgraph SW["Switch netns"]
    N["sw1-nX: veth peer"] --> TC["Shared port TC ingress, block 100"]
    T["sw1-tX: persistent TAP"] --> TC
    A["sw1-dummy: block anchor"] -.-> TC
    TC --> M["sw1-m0: management veth"]
    TC --> U["Transit device"]
  end
  M <--> MG["Management peer: eth0; service 169.254.169.254"]
  U <--> G["GENEVE gateway"]
```

Device names follow `<switch>-{p,n,m,t}<id>`: `sw1-p7` is the sandbox veth peer, `sw1-n7` its switch peer, `sw1-m0` the switch-side management device, and `sw1-t7` a persistent TAP. The addressless `<sw>-dummy` anchors the BPF filter on shared TC block 100, keeping it referenced even before any port device attaches; StartReserved creates it and Stop removes it. Port ingress devices share `ingress_block=100`; `skb->ingress_ifindex` identifies the slot. Management/transit ingress use their corresponding programs.

<a id="42-netns-布局"></a>

### 4.2 Namespace layout

| Namespace | Purpose | Devices |
|---|---|---|
| `netns_switch` | Internal switch networking. | `<sw>-nX`, `<sw>-mX`, `<sw>-tX` in TAP mode, `<sw>-dummy`, transit. |
| `netns_ports` | Initial veth peer location. | `<sw>-pX`, later moved into a sandbox namespace by attach. |
| `netns_mgmt` | Management service networking. | Management peer, such as eth0. Optional: an empty namespace leaves it in the caller/host namespace. |
| Sandbox namespace | A sandbox's veth peer. | `<sw>-pX`, moved from port-netns. TAP mode instead hands a queue descriptor to the VMM. |

<a id="43-数据包流向"></a>

### 4.3 Packet paths

CIDRs from `--mgmt-extract` populate each slot's destination classifiers; they do not assign addresses to the management peer. Connector creates the pair, sets MAC/MTU, brings it up, attaches TC, records extraction matches and installs floating-IP return routes. Deployment supplies interface addresses, local routes, service listeners and sysctls, ensuring the selected destination is local or otherwise reachable in the management namespace. The service template uses MGMT_ADDRS for explicit address assignment (§3.3).

**Sandbox → management service**, for example 169.254.169.254:

| Stage | Packet/action |
|---|---|
| Sandbox and port ingress | `src=169.254.1.1, dst=169.254.169.254`; veth path `sw-pX` → `sw-nX` (TAP enters its corresponding port ingress). |
| TC management match | Match `mgmt_cidrs[]`; SNAT source to floating_ip; increment mgmt_tx. |
| Management veth and service | `sw-mX` → management eth0; the service sees the floating source, such as `100.100.96.X`. |

**Management service → sandbox:**

| Stage | Packet/action |
|---|---|
| Management return | `src=169.254.169.254, dst=floating_ip`; eth0 → `sw-mX`. |
| TC management ingress | Derive `slot_id=dst-floating_ip_base`; DNAT destination to inner_ip; set destination MAC to the selected port MAC; increment mgmt_rx. |
| Port delivery | Switch port → sandbox veth peer or TAP queue. |

**Return routes:** replies addressed to floating IP must reach management-side TC for DNAT. Start installs routes scoped to the fixed maximum floating span of 4096 addresses, using the containing /20 and metric `100+index`, rather than replacing the namespace's default route:

```text
ip route add <floating_ip_base>/20 dev <mgmt-dev> metric <100+index>
```

If the floating base is not /20-aligned, the maximum span crosses two /20s and both routes are installed. Addresses captured by those routes but outside the configured floating range reach the management device and are dropped when no slot matches. An empty management namespace means these routes are in the caller/host namespace; they still do not replace its default route.

**Optional management-service translation:** without `--mgmt-service`, extraction changes inner↔floating addressing while retaining the requested service destination IP/port. Deployment must make the VIP reachable and listen appropriately. `--mgmt-service=<VIP>:<vport>:<targetIP>:<targetPort>` adds deterministic stateless TCP/UDP translation:

| Direction | Rewrites and result |
|---|---|
| Outbound | After management classification, SNAT inner→floating source. A forward-map hit DNATs `VIP:vport` to `targetIP:targetPort`. The backend sees the floating source. |
| Inbound | Floating destination identifies the slot and is DNATed to inner_ip. A reverse-map hit SNATs `targetIP:targetPort` to `VIP:vport`, so the sandbox sees the expected service endpoint. |

The static start-time maps are `mgmt_svc_fwd` (`{VIP,vport,proto}` → `{targetIP,targetPort}`) and `mgmt_svc_rev` (the reverse key/value). These are hash lookups without connection tracking. A service-table miss and non-TCP/UDP traffic follow the original management path. VIP must match an extraction route, target IP/port pairs must be globally unique for reverse lookup, and the service mapping is IPv4-only. Deployment owns backend reachability. A loopback target requires route_localnet on the management device; otherwise the kernel can reject it as martian traffic.

**Sandbox → external network:** a non-management destination, such as 8.8.8.8, enters port TC. TC encapsulates it in GENEVE and increments transit_tx. The outer IPv4 source is transit_ip, destination is gateway_ip, and the UDP source is derived from the inner five-tuple. The configured locator encodes the zero-based slot; opaque options travel only in this outbound direction. Ether-over-GENEVE sets inner source to the selected port MAC and inner destination to transit MAC; IP-over-GENEVE has no inner Ethernet header. The transit device sends the packet to the gateway.

**External network → sandbox:** the gateway sends a packet satisfying the configured strict locator contract. Transit TC recovers the slot, verifies allocation, ifindex, outer gateway-source IP and VNI, removes encapsulation, rewrites the destination MAC for the port and increments transit_rx before delivery.

Two invariants govern slot selection and delivery:

- Slot identity comes from ingress ifindex, floating destination arithmetic or the configured locator, not from a sandbox-claimed source IP/MAC.
- Return delivery uses the selected fixed/derived port MAC, matching the device/VMM receive configuration.

<a id="5-数据面"></a>

## 5. Data plane

<a id="51-ebpf-程序挂载点"></a>

### 5.1 eBPF attachment points

| Device | Attachment | Program | Function |
|---|---|---|---|
| `<sw>-nX` / TAP port | TC ingress, shared block 100. | `tc_ingress_nx` | ARP replies; management extraction/SNAT and optional service DNAT; GENEVE encapsulation; mgmt_tx/transit_tx. |
| `<sw>-mX` | TC ingress. | `tc_ingress_mx` | ARP replies; floating→inner DNAT and optional reverse service SNAT; mgmt_rx and delivery. |
| Transit | TC ingress. | `tc_ingress_transit` | GENEVE decapsulation, source-IP/VNI validation, transit_rx and delivery. |

GENEVE inner traffic can be IPv4 or IPv6; management translation and slot.inner_ip are IPv4.

<a id="52-pinned-mapssysfsbpf"></a>

### 5.2 Pinned maps (`/sys/fs/bpf/<sw>/`)

| Map | Type | Shape | nx | mx | transit | Contents |
|---|---|---|---|---|---|---|
| `slots` | ARRAY + MMAPABLE | 4096 × 108-byte value, 112-byte mmap stride. | R | R | R | Slot configuration; userspace CAS on inner_ip allocates/releases ownership (§6.3). |
| `config` | ARRAY | 1 × 40 bytes. | R | R | R | Switch MAC, port count, floating base, GENEVE locator/encapsulation, transit nexthop and port MAC. |
| `metadata` | ARRAY | 1 × 4096 bytes. | — | — | — | JSON SwitchMetadata for userspace only; additive fields do not alter BPF layout. |
| `stats` | PERCPU_ARRAY | 4096 entries per CPU. | W | W | W | Management/transit receive/transmit packet/byte counters. Attach attempts a reset; a reset error is nonfatal. Detach retains counters. |
| `ifindex_to_slot` | HASH | Ingress-device mapping. | R | — | — | ifindex→slot lookup on outbound port ingress. |
| `geneve_opts` | ARRAY | 4096 × 68 bytes. | R | — | — | Complete serialized opaque options; automatic TLV locator is not stored here. |
| `mgmt_svc_fwd` | HASH | Static service entries. | R | — | — | `{VIP,vport,proto}` → `{targetIP,targetPort}`, TCP and UDP entries per service. |
| `mgmt_svc_rev` | HASH | Static reverse entries. | — | R | — | `{targetIP,targetPort,proto}` → `{VIP,vport}`. |

New switches create/pin the service maps even when no service mapping is configured. Slot lookup on inbound traffic uses arithmetic or the fixed locator layout, without a generic inbound slot-index hash or TLV search. Management-service translation still has its separate hash maps.

<a id="53-数据面-abi"></a>

### 5.3 Data-plane ABI

Go code that directly reads/writes these C structures by byte offset is isolated in `pkg/internal/` (§11). Changing an offset is an ABI change and requires synchronized Go and BPF updates.

```c
struct slot_item {                          // 108 bytes, cache-line layout
    // Cache line 0 (hot path)
    __u32 ifindex;                          // offset  0
    __u32 inner_ip;                         // offset  4 — 0=Free, 0xFFFFFFFF=Reserved, other valid IP=Allocated
    __u32 transit_ifindex;                  // offset  8
    __u32 transit_ip;                       // offset 12
    __u32 transit_gateway_ip;               // offset 16
    __u32 transit_geneve_vni;               // offset 20
    __u8  transit_mac[6];                   // offset 24
    __u8  mode;                             // offset 30 — 0=veth, 1=tap (userspace metadata, not read by BPF)
    __u8  geneve_opts_len;                  // offset 31 — opaque bytes only; 0 skips geneve_opts lookup
    __u32 mgmt_cidr_count;                  // offset 32
    struct mgmt_cidr mgmt_cidrs_0;          // offset 36 (20B) — first inline CIDR (hot path)
    __u8  _pad_cl0[8];                      // offset 56
    // Cache line 1 (cold path)
    struct mgmt_cidr mgmt_cidrs_ext[MAX_MGMT_CIDR_EXT]; // offset 64 (40B)
    __u8  _pad_cl1[4];                      // offset 104
};   // 108 bytes; 8-byte mmap alignment gives 112 bytes/slot, 448 KiB for 4096 slots

struct switch_config {                      // 40 bytes
    __u8  switch_mac[6];
    __u16 _pad;
    __u32 n_ports;
    __u32 floating_ip_base;
    __u32 geneve_port_base;
    __u8  geneve_encap_eth;
    __u8  _pad3[3];
    __u32 transit_nexthop;
    __u8  port_mac[6];                      // all zero: derive; nonzero: fixed
    __u8  _pad4[2];
    __u8  geneve_locator;                   // 0=port,1=vni,2=tlv
    __u8  geneve_tlv_type;                  // exact 8-bit wire type
    __u16 geneve_tlv_class;
};

struct geneve_opts_value {                  // 68 bytes
    __u8  len;                              // opaque wire bytes
    __u8  critical;                         // whether any opaque type has bit 0x80
    __u16 reserved;
    __u8  data[64];                         // option header + opaque data
};

struct slot_stats {                         // per-CPU
    __u64 mgmt_rx_packets, mgmt_rx_bytes;
    __u64 mgmt_tx_packets, mgmt_tx_bytes;
    __u64 transit_rx_packets, transit_rx_bytes;
    __u64 transit_tx_packets, transit_tx_bytes;
};
```

`slot_item.geneve_opts_len` is an opaque-option lookup hint; it excludes the eight-byte automatic TLV locator. Attach/show JSON reports total wire length instead (§2.4). The slot's mmap stride is 112 bytes, not its C value size of 108.

Program paths check packet bounds and slot validity before use: Ethernet and relevant IP/header bounds, decapsulation extent, allocated inner_ip (neither Free nor Reserved), nonzero ifindex and `slot_id<n_ports`. **The outer transit IPv4 decoder** requires `ihl==5`; this must not be generalized to every management/inner-IP parsing path. Transit return also checks configured gateway source IP and VNI.

A new switch always creates and pins geneve_opts. Opening a legacy pinned switch treats that map as optional **only on ENOENT**; other load errors mean damage. Zero bytes in the old config's trailing padding decode as the legacy `port` locator. Thus old switches remain usable for Open/status/show, empty-option Attach, Detach and Stop. Nonempty opaque options or vni/tlv locator require stop and recreation with the new implementation. No map is added to an active old switch and no attached TC program is replaced in place.

<a id="6-关键机制"></a>

## 6. Key mechanisms

<a id="61-mac-派生"></a>

### 6.1 MAC derivation

ARP and derived device MACs share a namespace based on switch_mac, with format `SS:SS:SS:SS:BB:LL`:

- Bytes 0–3 retain `switch_mac[0..3]`.
- Byte 4 is `((switch_mac[4] ^ 0x80) & 0x80) | (id >> 8)`.
- Byte 5 is `id & 0xFF`.

Port IDs are zero-based slot IDs, `0x000..0xFFF`; management IDs are `0x7FF0+mgmt_idx`. The high bit of derived byte 4 is the inverse of switch_mac byte 4's high bit, preventing collision with the switch MAC. The lower four bits encode the high four slot bits, supporting 4096 ports. The formula imposes no additional byte-4 collision constraint, but the input still must be a valid six-byte MAC usable for the deployment's network devices. Go and BPF compute the same formula and must change together.

`--port-mac-addr` selects the port MAC:

| Mode | MAC | Use |
|---|---|---|
| `fixed` (default) | Derive with slot_id=1 and use that MAC for every port. | Snapshot relocation into a different free slot without reconfiguring the guest MAC. |
| `per-port` | Derive from each actual slot ID. | Tests or gateway-side MAC distinction. |
| Explicit MAC | Same user-supplied address on all ports. | Specific compatibility requirements. |

<a id="62-geneve-隧道"></a>

### 6.2 GENEVE tunnels

Connector runs on the sandbox host; an external GENEVE gateway provides access to external networks. Their contract covers framing, slot location and return validation. Locators encode **zero-based slot_id=0..4095**, not the CLI's one-based `port=slot_id+1`. Opaque option semantics belong to the caller and gateway: Connector does not define tenant/sandbox/policy schemas or interpret their data.

Encapsulation modes; return decoding recognizes geneve proto_type:

| Mode | proto_type | Inner packet | Purpose |
|---|---|---|---|
| **IP-over-GENEVE** (default) | ETH_P_IP / ETH_P_IPV6 | Bare IP. | Saves an inner 14-byte Ethernet header; suitable for switch-to-switch integration. |
| **Ether-over-GENEVE** | ETH_P_TEB (0x6558) | Full Ethernet frame. | Linux GENEVE devices and gateway bridges. |

Locator wire contract:

| Locator | Outbound UDP destination | Outbound VNI | Automatic locator | Configured VNI range | Strict return |
|---|---|---|---|---|---|
| `port` (default) | geneve_port_base + slot_id | Full transit_geneve_vni. | None. | 0..0xffffff | OptLen=0, C=0; recover slot from UDP destination. |
| `vni` | 6081 | `(slot_id << 12) \| transit_geneve_vni`. | High 12 VNI bits. | 0..0x0fff | UDP destination 6081, OptLen=0, C=0; recover high 12 bits and verify low 12 bits. |
| `tlv` | 6081 | Full transit_geneve_vni. | First eight-byte option. | 0..0xffffff | UDP destination 6081; options consist of exactly the one eight-byte locator. |

The VNI locator has a fixed 12/12 split:

| VNI bits | Width | Meaning |
|---|---|---|
| 23..12 | 12 | slot_id |
| 11..0 | 12 | transit_geneve_vni |

`--geneve-tlv-locator=CLASS:TYPE` is an exact wire class/type. For `0102:81`, type is raw byte 0x81, including its critical bit; Connector does not silently set or clear 0x80. The generated option is Class=configured class, Type=configured type, Length=1, Data=be32(slot_id), eight bytes total, always first. New protocols may choose a critical type, but the two peers must agree.

Attach accepts repeated opaque options:

```bash
connector-ctl vswitch attach sw0 --inner-ip=169.254.1.1 \
    --transit-gateway-ip=10.0.0.2 --transit-geneve-vni=42 \
    --transit-geneve-opt=0102:02:0000002a \
    --transit-geneve-opt=0102:83:1122334455667788
```

Class, type and data are hex; type is the exact eight-bit wire value. Data length must be a multiple of four bytes, including zero (`0102:02:`). Input order, data byte order and duplicates are preserved. In TLV mode, an opaque option cannot share the locator's class and low seven type bits, even with a different critical bit. The GENEVE base C bit is one if the locator or any opaque option has `type & 0x80 != 0`, otherwise zero.

Total wire options are limited to **64 bytes**, including every four-byte option header, opaque data and the TLV locator's eight bytes. Port/vni modes permit 64 bytes of opaque options; TLV permits 56. Opaque options are outbound Connector→gateway only, currently set on Attach rather than updated online, and are not delivered back to the sandbox.

Return decoding is deliberately strict. Port/vni reject options or C=1. TLV requires exactly one first/only locator with matching class/type, length=1, in-range big-endian slot ID, zero reserved bits and a base C bit matching the locator type's critical bit. The gateway must **not echo outbound opaque options** on return. After recovering the slot, all modes check allocation, ifindex, gateway source IP and configured VNI.

The inner five-tuple Jenkins hash selects an outer UDP source in **49152–65535** for underlay ECMP/RSS. An omitted locator means port. With no opaque options, default port-mode framing retains the legacy wire encoding for equivalent inputs.

For outer L2 delivery, bpf_redirect_neigh uses the kernel neighbor subsystem; the BPF program maintains no ARP cache. In Ether-over-GENEVE, the inner destination is transit-mac-addr or broadcast, and the inner source is the selected port MAC, matching the device/VMM configuration for gateway bridge learning.

Capture on the switch namespace's transit device:

```bash
ip netns exec sw0_vswitch tcpdump -ni eth1 -vv -XX 'udp port 6081 or udp portrange 50000-54095'
connector-ctl vswitch show config sw0
connector-ctl vswitch show slots sw0
```

Inspect UDP destination, the 24-bit VNI, OptLen, base C, option class/type/length/data and the start of the inner payload. TLV locator data must be the zero-based slot ID in big-endian 32-bit form.

<a id="63-slot-分配与状态机"></a>

### 6.3 Slot allocation and state machine

Separate BPF Lookup and Update syscalls permit a TOCTOU race: two processes can observe a free slot and overwrite each other. The slots array uses BPF_F_MMAPABLE; userspace maps it and uses atomic.CompareAndSwapUint32 on inner_ip for atomic ownership. The atomic claim itself needs no lock, while new-switch compound operations also use flock (§6.4).

| inner_ip | State | Meaning |
|---|---|---|
| 0x00000000 | Free | Available after provisioning. |
| 0xFFFFFFFF | Reserved | Explicit StartReserved/reserve/provision state. |
| Valid real inner IPv4 | Allocated | Attached port. |

```mermaid
stateDiagram-v2
  [*] --> Reserved: StartReserved
  Reserved --> Free: ProvisionPorts
  Free --> Allocated: Attach CAS
  Allocated --> Free: Detach CAS
  Free --> Reserved: reserve
  Allocated --> Reserved: reserve --force
```

| Operation | Transition | CAS |
|---|---|---|
| Attach | Free→Allocated. | CAS(inner_ip, 0, innerIP). |
| Detach | Allocated→Free. | CAS(inner_ip, currentIP, 0); on new switches clear the hint under control flock, retaining map bytes for the next Attach. No Reserved intermediate. |
| Reserve | Free→Reserved; force can replace Allocated. | CAS to 0xFFFFFFFF. |
| Provision complete | Reserved→Free. | CAS(inner_ip, 0xFFFFFFFF, 0). |

Failed operations attempt to undo their own claim or device movement, without overwriting a different owner. A CAS claim is not an atomic publication of every data-plane field, and rollback/device operations can themselves fail. Callers must use operation results and inspect/reconcile state after an error (§7.4).

<a id="64-控制操作互斥"></a>

### 6.4 Control-operation serialization

CAS protects one slot's ownership. Multi-resource operations and new-switch updates spanning mmap slots plus geneve_opts use `flock(LOCK_EX)` on `/sys/fs/bpf/<sw>/`:

| Operation | flock | CAS |
|---|---|---|
| Start / StartReserved | Yes. | Mark slots Reserved. |
| Stop / stop --force | Yes. | The stop cleanup phase is not a single slot CAS; forced release is a separate step. |
| ProvisionPorts | Yes. | Reserved→Free per completed slot. |
| New-switch Attach / Detach / Reserve | Yes, covering claim, map/MTU/device work and hint publication/retraction. | Yes. |
| Legacy Attach / Detach / Reserve without geneve_opts | No. | Existing CAS-only path. |

After acquiring flock and before CAS, new-switch Attach/Detach/Reserve compare the opened slots map's kernel ID with the map currently pinned at that name. If the switch was stopped/recreated while the operation waited, the old context fails and must be reopened; it does not mutate an unpinned obsolete map.

<a id="65-两阶段启动"></a>

### 6.5 Two-phase startup

Startup is split to support Type=notify and early control-plane availability.

**Phase 1, StartReserved:** validate configuration; load BPF objects and pin maps; write config/metadata, with transit auto-address DHCP in this phase; mmap slots and CAS them to Reserved; create the dummy block anchor; create management veth/TC and return routes, and populate service maps; move/configure/bring up transit, including MTU/IP. Programs are retained by TC references. This phase includes network/RTNL work and has no universal 100 ms duration. Status becomes available while slots remain Reserved.

**Phase 2, ProvisionPorts:** for each Reserved slot, create its veth pair or persistent TAP, attach shared port ingress, write device/management/transit fields and CAS Reserved→Free. Free/Allocated slots are skipped; a failed slot stays repairable with `provision --port=X`.

`serve` orders its work as follows:

1. StartReserved, or reopen the compatible existing switch.
2. Start the optional TAPFD listener; listener startup failure prevents normal readiness.
3. Send `sd_notify(READY=1)` and report initial status.
4. Provision ports asynchronously.
5. Run health checks and watchdog keepalives; handle listener/provision failure and termination signals. SIGTERM/SIGINT exits the process without tearing down the switch data plane.

Dependent services can start after READY=1, before every port is provisioned. They must handle temporary unavailability and retry; readiness of the systemd process is not proof that all ports are Free.

<a id="66-端口模式veth-与-tap"></a>

### 6.6 Port modes: veth and TAP

Each slot records its kind in slot_item.mode. This is userspace metadata; BPF does not read it. Both kinds enter the same port TC program and select their slot by ifindex. Their control and descriptor lifecycles differ:

| | **veth** (mode=0) | **TAP** (mode=1, CLI default) |
|---|---|---|
| Switch device | `<sw>-nX`. | Persistent `<sw>-tX`, using TUNSETPERSIST. |
| Sandbox side | `<sw>-pX`, moved to sandbox-netns by attach. | No moved netdev; the VMM receives a queue descriptor through SCM_RIGHTS. |
| port-netns | Required for veth provisioning. | Not needed; TAP stays in switch-netns. |
| Attach | Slot claim/control updates plus optional peer movement. | Slot claim/control updates; reject missing provisioned ifindex. |
| Detach | Release claim and return/check peer, unless skipped. | Release claim without moving the TAP. |
| Descriptor access | Not applicable. | open-port or attach --open-port (§2.8). |

For a Reserved slot, `provision --mode=<new>` creates the new-kind device before committing its ifindex, then removes the old-kind device. Names differ, allowing temporary coexistence.

Attach/detach do not create or delete port devices. Provision creates them; normal/forced Stop removes owned devices. Force-clean only unpins maps and can leave devices/filter references. `--skip-device` controls permitted movement/checks; it does not turn attachment into a device-provisioning operation.

<a id="67-tap-fd-交接"></a>

### 6.7 TAP descriptor handoff

[tapfd.md](tapfd.md) independently defines the vendor-neutral SCM_RIGHTS, NUL-terminated key=value metadata and TAPFD_SOCKET contract. This section records Connector's provider choices.

**Metadata:** in addition to mandatory `fd=`, send `mac` (selected port MAC, to mirror into the VMM's virtio-net receive configuration), `ip` (real sandbox inner IP), and diagnostic `port` (one-based; a consumer may ignore it). Slot dispatch uses ifindex, not the supplied MAC:

```text
port=1 mac=02:00:00:00:80:01 ip=169.254.1.1 fd=1\0
```

If requested through TAPFD_WANT_NETNS, append the switch namespace descriptor after the TAP queue and set netns_fd=1, allowing a capable consumer to setns and operate on the device (§3.4 of tapfd.md).

**Provider helper:** resolve TAPFD_SOCKET as fd=N or a path, enter switch-netns, open /dev/net/tun and attach with IFF_TAP|IFF_NO_PI|IFF_VNET_HDR. The vnet header is a property of this queue attachment; do not infer it solely from persistent-device creation flags. After sending, close local descriptors and exit. Persistence keeps the TAP device alive, but queues still follow descriptor lifetimes. A later consumer can request a fresh handoff subject to the provider contract.

`attach --open-port` combines allocation and transfer. If transfer fails, the CLI attempts Detach with SkipDevice to undo the claim while retaining the provisioned TAP. Cleanup errors are not a guarantee of a clean slot; callers should inspect/reconcile status before retry. Stop/close the previous VM/queue consumer before reusing its slot.

**Preflight:** before socket/TAP access, require TAP mode, provisioned ifindex and an attached real inner IP. Missing switch yields exit code 3.

**Consumers:** third parties can implement tapfd.md §2. The repository supplies [pkg/tapfd](../pkg/tapfd/) with RecvFd, RecvFds and RecvFdsWithNetns, and [examples/tapfd_receiver](../examples/tapfd_receiver/). A generic Unix byte-stream listener alone does not implement descriptor reception.

<a id="68-mtu-校验"></a>

### 6.8 MTU validation

The implementation uses the following encapsulation budget:

`transit_mtu >= port_mtu + base_overhead + wire_options_len`

| Mode | Base overhead used by the check |
|---|---|
| IP-over-GENEVE | ETH(14) + IPv4(20) + UDP(8) + GENEVE(8) = **50 bytes**. |
| Ether-over-GENEVE | The above plus inner Ethernet(14) = **64 bytes**. |

These are the implementation's configured MTU budgets. TLV always adds at least eight option bytes, even with no opaque options. **Current two-phase provisioning does not carry the requested `--mtu` into new TAP/veth port devices**: the BPF SwitchConfig has no MTU field and provision creates ports with kernel defaults. The requested value is used for management-device setup and initial transit-budget checks. Inspect actual port MTUs rather than assuming the flag configured them.

`--transit-dev-mtu` has three paths:

- Omitted: leave transit MTU unchanged and validate fixed-locator overhead.
- `auto`: set `port_mtu + base_overhead + 64`, reserving the full permitted options budget so later valid Attach options do not require changing the active uplink.
- Numeric: set that MTU and validate fixed overhead.

An explicit requested MTU enables fixed-budget validation before resource creation. Without it, startup uses discovered devices or the default while Reserved ports do not yet exist. Because the requested value may differ from the later provisioned port MTU, initial validation alone is insufficient. Validate the actual port/transit pair before use; if deployment changes a port MTU explicitly, keep its peer/guest receive configuration consistent. The physical underlay still must carry the chosen frames; setting an interface MTU does not enlarge the upstream network.

When Attach's total wire options are nonzero, including the generated TLV locator, it reads the selected port and transit MTUs again before moving veth or handing off TAP. Failure keeps the options hint zero and attempts to release the CAS claim. The error reports every component, for example:

```text
transit device eth1 MTU 1570 is too small for port sw0-n1:
  port MTU 1500 + base GENEVE overhead 64 + options overhead 12 = required MTU 1576
```

<a id="69-dhcp-网关推算"></a>

### 6.9 DHCP gateway inference

For transit auto-addressing, StartReserved runs DHCP after bringing transit up. Router Option 3 is used when present. Otherwise the implementation infers the subnet's first usable address, for example 192.168.1.100/24 → 192.168.1.1, and logs that fallback. This supports DHCP servers that omit a router, but the heuristic does not prove a router actually exists there; configure an explicit gateway when the network differs.

<a id="7-安全与隔离"></a>

## 7. Security and isolation

<a id="71-威胁模型"></a>

### 7.1 Threat model

Connector is a defense-in-depth layer outside the MicroVM; the VMM remains the primary guest isolation boundary. Sandbox code may be malicious. Host control-plane callers, management services and the external gateway must be governed by deployment policy.

| ID | Threat | Mechanism and scope |
|---|---|---|
| T1 | Sandbox forges source IP/MAC as port identity. | Slot selection derives from ifindex, floating destination or configured locator; output MACs are controlled. This is not an external-network anti-spoofing policy for every inner packet field. |
| T2 | Direct local sandbox-to-sandbox forwarding. | No port-to-port TC branch; local outbound paths are management or transit. Gateway/management-mediated access needs its own policy. |
| T3 | Unexpected GENEVE return source. | Verify configured outer gateway IP, locator and VNI. IP/VNI matching is not cryptographic peer authentication; the underlay/gateway remains trusted. |
| T4 | ARP broadcast crosses local ports. | Switch handles port ARP requests and returns replies locally instead of bridging requests to another sandbox port. |
| T5 | Control-process crash stops forwarding. | TC references, pinned maps and intact network resources outlive the process; serve can reopen them (§8.1). |
| T6 | Concurrent attach claims one slot twice. | mmap CAS gives one owner; compound new-switch updates also hold flock. |

<a id="72-隔离不变量"></a>

### 7.2 Isolation invariants

1. **No direct port-to-port path:** the dedicated local forwarding program has no branch bridging one sandbox ingress to another sandbox ingress.
2. **Switch-owned ARP replies:** port ARP requests are consumed and answered back to that port, not broadcast to other ports.
3. **Controlled source MACs:** forwarded Ethernet headers use switch or selected port MACs rather than trusting the sandbox's source MAC as slot identity.
4. **Restricted transit return:** recover the slot using the configured locator and reject invalid allocation/ifindex, gateway-source IP or VNI.
5. **Management address translation:** outbound source becomes floating IP and inbound destination becomes inner IP. This describes packet-header NAT, not concealment of IP values an application might put in payloads.

These are local data-plane properties. They do not authorize arbitrary traffic through the management backend or gateway, and they do not replace those systems' access controls.

<a id="73-所需权限"></a>

### 7.3 Required privileges

The supported privileged test/deployment baseline is root with the required capabilities. Exact reduced-capability execution depends on kernel, BPF policy, namespace ownership and pin-file permissions; this table describes relevant operations rather than a proven minimal capability set:

| Operation | Privilege considerations | Why |
|---|---|---|
| start / serve | CAP_SYS_ADMIN for namespace entry/setup and older BPF paths; CAP_NET_ADMIN for network/TC work. Modern BPF loading has its own CAP_BPF-related checks. | Load BPF, pin maps, enter namespaces, create/configure links and TC. |
| attach / detach / provision / open-port | Namespace-entry and network-device privileges, plus map/pin access as used by the path. | mmap/CAS, move/configure links, open TAP queues. |
| stop | CAP_NET_ADMIN plus namespace-entry privileges, normally CAP_SYS_ADMIN, and map/pin access. | Remove TC/devices and return transit through setns. CAP_BPF alone does not authorize setns. |
| status / stats / show | Appropriate pinned-map and kernel-BPF access; namespace/device inspection may impose additional checks. | Open/read maps and inspect state. |

Linux 5.8+ separates some BPF privileges into CAP_BPF, but this does not replace every CAP_SYS_ADMIN check. TC/device administration still needs the relevant network privileges.

<a id="74-已知限制"></a>

### 7.4 Known limitations

| ID | Limitation | Handling |
|---|---|---|
| L1 | CAS owns inner_ip before all retained transit fields/options are updated. The complete attachment is not one atomic data-plane transaction; no bounded 1 µs window or unconditional packet-drop guarantee is established. | Stop/close the prior consumer before slot reuse; wait for successful attachment before exposing the new consumer. Treat errors as requiring state inspection, and allow protocol retry for transient loss. |
| L2 | External destruction of a sandbox namespace before detach can leave an allocated slot after its device disappears. | Confirm the old consumer is gone and reconcile ownership/device state; deliberate detach --skip-device or forced stop can recover depending on the remaining state. Capacity remains bounded by MAX_PORTS. |
| L3 | Physical transit failure. | Upstream redundancy can help only where configured; Connector itself has one transit device. Startup requires DOWN to avoid taking over an active interface. |
| L4 | MAX_PORTS=4096. | Increasing capacity requires synchronized BPF/Go bounds and the fixed 12-bit locator ABI, not merely editing one constant. |
| L5 | Broad extraction CIDRs admit unintended management traffic; the slot stores only three CIDRs total. | Prefer narrow routes such as /32 and inspect the actual programmed slots. |
| L6 | Unreachable management-service target, especially loopback. | Validate VIP/extraction and target uniqueness; deployment still supplies routing/listeners and route_localnet for loopback. |
| L7 | Legacy switch lacks geneve_opts. | Existing no-option port-mode operations remain supported; stop/recreate before vni/tlv or opaque options. No online map/program migration. |
| L8 | Requested --mtu is not propagated into newly provisioned TAP/veth ports. | Check actual device MTUs and the full underlay budget (§6.8); initial startup validation and CLI help from older versions are not proof of the port value. |

<a id="8-可靠性"></a>

## 8. Reliability

<a id="81-资源生命周期与崩溃恢复"></a>

### 8.1 Resource lifecycle and crash recovery

| Resource | Lifetime mechanism | After control-process exit |
|---|---|---|
| BPF program | TC filter references. | Retained while those references exist. |
| BPF maps | bpffs pins under `/sys/fs/bpf/<sw>/`. | Retained while pinned/referenced. |
| veth / TAP / dummy / transit | Kernel devices/namespaces; persistent TAP where configured. | Retained while the owning resources remain intact. |
| flock | Released when the process closes/exits. | Does not permanently block the next control operation. |

After a serve crash, systemd Restart=on-failure launches a process that reopens compatible pinned state, skips already Free/Allocated ports during provisioning and resumes control/provider service. Existing forwarding can continue during this **process-only** restart. Deleted namespaces/devices, damaged maps, host reboot or incompatible ABI are different failures and are not covered by that guarantee.

<a id="82-故障排除"></a>

### 8.2 Troubleshooting

| Symptom | Cause/action |
|---|---|
| `transit device not found` | Check TRANSIT_DEV against the intended caller namespace's `ip link`; a running switch may already own it in switch-netns. |
| `transit device eth1 must be DOWN before use` | Confirm it is the dedicated unused device, set it DOWN and retry. |
| `failed to pin maps: ...bpffs not mounted` | Mount bpffs at /sys/fs/bpf and configure persistent mounting as appropriate. |
| `switch already exists` | Inspect the existing switch/config first. Stop it normally when replacement is intended; do not delete pins under active forwarding as a routine restart procedure. |
| ABI incompatible after upgrade | Drain/stop consumers and use normal or forced cleanup. For damaged state, force-clean only removes pins; explicitly inspect/remove orphaned devices/TC and return transit before recreating. |
| `port not provisioned` | Wait for provisioning/PortDevicesReady, or repair the Reserved slot explicitly. |
| open-port reports `port not attached` | Attach first, then request the queue. |

<a id="9-性能特征"></a>

## 9. Performance characteristics

The previous document reported the following WSL2/Linux 5.15 figures. It did not attach a pinned source revision, complete benchmark invocation and raw results. They are retained as **unverified historical observations**, not results rerun for this translation or current performance/capacity guarantees. CPU, NIC, kernel, offloads, topology, packet sizes and load materially change results.

<a id="91-数据面2-端口拓扑"></a>

### 9.1 Data plane (two-port topology)

| Metric | Reported bare-veth baseline | Reported GENEVE path | Reported difference |
|---|---|---|---|
| Single-flow TCP throughput | ~110 Gbps | ~55 Gbps | ~50% lower. |
| UDP 64-byte packet rate | ~1100 Kpps | ~250 Kpps | ~77% lower. |
| End-to-end RTT | — | ~0.09 ms | — |
| tc_ingress_nx invocation | — | ~110 ns | — |
| tc_ingress_transit invocation | — | ~110 ns | — |

Per-packet work and GRO/GSO can make small-packet and bulk-TCP results differ. The historical table alone does not isolate the cost of BPF, veth and encapsulation or prove which stage dominates. Repeat the benchmark with recorded offload/CPU/topology settings before drawing that conclusion.

<a id="92-控制面128-端口"></a>

### 9.2 Control plane (128 ports unless stated)

| Phase | Historical value | Interpretation/limit |
|---|---|---|
| Complete Start | ~8.7 s | The old report attributed 97% to TC attachment; no raw profiling evidence accompanies it here. Link/TC operations involve RTNL. |
| StartReserved | ~100 ms | Includes BPF/map and network-device/TC/transit setup; it is not a no-RTNL phase. |
| Stop, 128 ports | ~18 s | Old report: ~70 ms/pair without BPF to ~145 ms/pair with filter removal. Configuration and kernel matter. |
| Stop, 256 ports | ~35 s | Historical observation, not proof of universal linear scaling. |

Historical asynchronous-start timeline, retained without a timing guarantee:

| Reported time | Event |
|---|---|
| 0 ms | serve starts. |
| 100 ms | READY=1; dependent services may start. |
| 200 ms | First port reportedly becomes Free. |
| 8700 ms | All 128 ports reportedly Free. |

Use the actual ordering in §6.5 and Conditions rather than fixed delays to determine readiness.

<a id="10-测试"></a>

## 10. Tests

<a id="101-分层"></a>

### 10.1 Layers

| Layer | Files | Privilege | Coverage |
|---|---|---|---|
| Unit | `*_test.go`. | Ordinary user. | Pure logic with injected BPF/netlink dependencies. |
| Integration | `*_integration_test.go`. | Root/BPF-capable kernel. | Real BPF loads/netlink with integration build tags and privileged execution. |
| End-to-end | [test/e2e](../test/e2e/) `*_test.sh`. | Root. | Real topology/packets; setup/test/teardown/all script modes where provided. |
| Benchmarks | [perf_bench.sh](../examples/perf_bench.sh), [start_perf_bench.sh](../examples/start_perf_bench.sh). | Root and iperf3. | Throughput/PPS/RTT at varying port counts and control-plane startup timing. |

<a id="102-ebpf-三层验证"></a>

### 10.2 Three levels of BPF validation

1. **Layout:** integration tests under pkg/internal/bpf verify Go/C offsets, sizes and alignment.
2. **BPF_PROG_TEST_RUN:** construct packets, execute the program and assert actions/output bytes. Where ingress_ifindex cannot be supplied conveniently, tests map ifindex=0 to the test slot for tc_ingress_nx.
3. **Real topology:** test/e2e scripts create networks and use actual ping/iperf traffic.

<a id="103-e2e-套件"></a>

### 10.3 E2E suites

| Script | Coverage |
|---|---|
| mgmt_isolation_test.sh | Management connectivity and local sandbox isolation. |
| geneve_eth_test.sh | Legacy port locator with Ether-over-GENEVE through a Linux gateway bridge. |
| geneve_ip_test.sh | IP-over-GENEVE between switches; run_all covers port/vni/tlv locators, bidirectional connectivity and transit counters. |
| provision_test.sh | Two-phase startup, Reserved-slot repair and show. |
| tap_test.sh | TAP mode, open-port, attach --open-port and mode changes. |

[examples/manage_switch.sh](../examples/manage_switch.sh) manages JSON-configured switches with setup/teardown/status/exec, supporting manual operations and topology construction.

<a id="11-内部组织"></a>

## 11. Internal organization

| Path | Role |
|---|---|
| `cmd/connector-ctl/` | Cobra CLI, JSON output/dependency injection and the tapfd provider subcommand. |
| `pkg/tapfd/` | Public protocol reference: PortMetadata, OpenTap, SendFd, RecvFd, RecvFds, RecvFdsWithNetns, ConnectUnix and UnixConnFromFd. |
| `pkg/vswitch/` | Public lifecycle API: context/Open, lifecycle/Start/StartReserved, provision, stop, Attach/Detach/Reserve, Status/Stats, Config/FileConfig, metadata, flock and exported helpers. |
| `pkg/netlink/` | Public veth/TAP/TC and batched netlink operations. |
| `pkg/netns/` | Public namespace enter/move/exec. |
| `pkg/dhcp/` | Public embedded DHCP client/server. |
| `pkg/daemon/` | Public systemd sd_notify support. |
| `pkg/internal/bpf/` | Internal BPF ABI: generated cilium/ebpf bindings, types and loader. |
| `pkg/internal/bpfmap/` | Internal ABI-coupled mmap, CAS, counters and MAC derivation. |
| `bpf/` | C sources: switch_kern.c, common.h and vmlinux.h. |
| `test/e2e/` | Component suites and run_all.sh. |
| `examples/` | Operations/benchmark scripts and tapfd_receiver source example. |
| `dist/` | systemd service/configuration templates. |

Byte-offset BPF structure access belongs in pkg/internal; a field-offset change is an ABI change. Go's internal rule permits imports only from within the parent pkg tree, not from cmd or arbitrary external modules. The other pkg packages expose the intended public API. CLI code uses helpers re-exported by pkg/vswitch/exports.go and follows the same API path as external embedders.

Dependency direction is acyclic:

```mermaid
flowchart TD
  C["cmd/connector-ctl"] --> V["pkg/vswitch"]
  C --> T["pkg/tapfd"]
  C --> U["pkg/netlink, netns, dhcp, daemon"]
  V --> U
  V --> M["pkg/internal/bpfmap"]
  M --> B["pkg/internal/bpf"]
```

pkg/tapfd is self-contained apart from the standard library and golang.org/x/sys.

## 12. See also

- [tapfd.md](tapfd.md): full provider/consumer descriptor-handoff contract.
- [sandboxer/docs/sandbox.md](https://github.com/kuasar-sandbox/sandboxer/blob/main/docs/sandbox.md): sandbox-ctl consumption through TAPFD helpers.
- [RFC 8926](https://www.rfc-editor.org/rfc/rfc8926): GENEVE framing.
- [Linux commit fc9702273e2e](https://github.com/torvalds/linux/commit/fc9702273e2edb90400a34b3be76f7b08fa3344b): mmap support for BPF_MAP_TYPE_ARRAY.
- [sd_notify](https://www.freedesktop.org/software/systemd/man/sd_notify.html): systemd Type=notify integration.
- [cilium/ebpf](https://github.com/cilium/ebpf) and [vishvananda/netlink](https://github.com/vishvananda/netlink): Go libraries used by the implementation.
