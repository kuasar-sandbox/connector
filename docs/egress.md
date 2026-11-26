[English](egress.md) | [简体中文](egress_zh.md)

# Geneve Egress operations

Egress is a file-configured IPv4 Geneve forwarding gateway with ordered ACLs, TCP/UDP DNAT, longest-prefix Pool selection and native NAT44-ED. Valid traffic creates forwarding state automatically. Native protocol inactivity timers release NAT mappings, followed by safe reclamation of idle contexts. Egress has no sandbox registration, token, lease, renew or release protocol and exposes no management API.

Local and remote deployments use the same Area/Pool configuration and wire contract. The gateway does not provide DNS/domain policy, an application proxy, IPv6 forwarding or automatic Pool failover. [Proposal #117](https://github.com/kuasar-sandbox/connector/issues/117) is the design baseline.

## Deployment and ownership

Build the matching native runtime and pure-Go control binary using [build and acceptance](../egress/README.md). Keep its executable, libraries and plugins together. VPP owns each configured gateway/SNAT address; Linux must not hold the same address on that interface. Unrelated Linux IPv4 addresses are permitted. AF_PACKET checksum and segmentation offloads are disabled and verified through the kernel API.

For a local gateway, use [link.json](../dist/egress/link.json), [switch.json](../dist/egress/switch.json), [gateway.json](../dist/egress/gateway.json) and [area7.json](../dist/egress/area7.json). Replace example addresses and resources before deployment; use `aarch64-linux-gnu` library paths on ARM64.

1. Run `connector-ctl egress link prepare --config link.json`. The stable owner namespace holds the switch endpoint while vSwitch is stopped; the gateway endpoint stays in the Egress namespace. Namespace and device ownership are recorded.
2. Have the external-network owner place the uplink in the gateway namespace, configure its MTU and bring it up. Provide real external reachability for SNAT resources. The host default route is not an implicit Pool exit.
3. Prepare switch and port namespaces using existing [vSwitch operations](vswitch-operations.md), then run `connector-ctl egress validate --config gateway.json`.
4. Run `ip netns exec egress-local connector-ctl egress serve --config gateway.json`. Alternatively install [connector-egress@.service](../dist/connector-egress@.service), place the main configuration at `/etc/connector-egress/egress-local.json` and its referenced Area files beside it, then start `connector-egress@egress-local.service`.
5. Run `connector-ctl egress link start --config link.json --switch-config switch.json --mode veth`. The default is `tap`, as in existing vSwitch. The wrapper starts vSwitch from the recorded stable owner namespace.
6. Attach sandboxes through existing vSwitch interfaces and verify real request/reply traffic through the required Pools. No Egress registration call is involved.

Repeated prepare verifies and reuses the owned pair. It rejects foreign names, changed namespace identities and damaged installed pairs. Each local vSwitch uses a dedicated pair; multiple pairs may share an Egress instance. Separate underlay FIBs support overlapping outer addresses. Existing vSwitch `transit_dev_mtu:auto` may lower its endpoint below the provisioned gateway MTU; this does not change pair ownership.

Remote deployments use externally owned transit devices rather than the local pair manager. Configure `peer` as the vSwitch outer source and `next_hop` as an on-link router for routed peers; it defaults to `peer`. Configure existing vSwitch transit addressing and the Geneve gateway normally. The receive interface, local VTEP, peer and Area select a configured forwarding domain. Geneve and generation MACs are not cryptographic authentication; underlay ownership must prevent sender impersonation.

## Files and reload

The main configuration is strict JSON. `areas` may contain inline Area objects; `area_files` lists files containing one Area object each, resolved relative to the main file. Both sources form one validated set. Unknown fields, duplicate JSON members, duplicate Areas, invalid references, and trailing values are rejected.

Complete all file edits, then trigger reload:

```bash
systemctl reload connector-egress@egress-local.service
# For a directly supervised process:
kill -HUP "$(cat /var/lib/connector-egress/egress-local/pid)"
```

Each reload reads the main file and all referenced Area files, validates and stages the complete candidate, then publishes all Areas and attachment profiles under one worker barrier. A parse, reference or preparation error retains the previous configuration. No independently writable online policy store exists. Use atomic file replacement and send SIGHUP after the complete file set is ready.

Reload supports Area addition/removal, ACL/DNAT/routes/Pools, attachment profiles and peer routes, context budget, idle grace and native protocol timeouts. Removing an Area also requires removing references to it. Runtime executable/library paths, CPU/heap allocation, physical interfaces/Exit topology and NAT preallocation currently require restart: such changes are rejected before publication, with the running configuration retained. An ambiguous native publication acknowledgement stops the gateway rather than reporting an unproven rollback.

Ordinary route, DNAT and SNAT selection changes affect new mappings. Existing mappings retain their original public tuple, destination translation and exit. Lower Pool quotas limit new mappings without evicting existing mappings. ACL revocation, removed Pools/Areas and unavailable original paths invalidate only affected mappings. Incompatible attachment wire/gateway changes retire affected contexts; immutable returns never borrow another generation's marker.

A process restart reads the files again and does not restore NAT state. Subsequent valid traffic automatically creates new forwarding state. No controller re-registration is required.

## Configuration and resources

| Object | Meaning |
|---|---|
| Interface | Linux device name, VPP-owned IPv4 `address` prefix and physical L3 `mtu`. |
| Exit | Physical interface, on-link `next_hop` and reachable SNAT `addresses`. Multiple Exits may share an interface. Return lookup uses the shared physical FIB; each Exit has its own routing FIB. |
| Attachment | Transit interface, peer, Area, locator, encapsulation, existing generation width and inner gateway. `inner_mtu` defaults to 1500; optional `mtu` caps the outer path. |
| Area | Logical `vni`, ordered `acl`, ordered TCP/UDP `dnat`, longest-prefix `routes` and Pools. |
| Pool | Area-local unsigned 32-bit ID, Exit and a subset of its addresses. `max_connections` limits live NAT mappings per forwarding context/Pool; zero removes the business quota, not physical resource limits. |
| Match | Canonical IPv4 destination prefix and `any`, `icmp`, `tcp` or `udp`; ports require TCP/UDP. `any` also covers other ordinary IPv4 protocols. |

ACL first-match/default-deny applies to the original destination before DNAT. A DNAT match selects its Pool directly; otherwise routing uses longest-prefix selection. A missing route, exhausted selected Pool or unavailable exit fails without choosing another Pool. Portless IPv4 protocols require distinct public addresses for overlapping remote/protocol tuples because they have no translated port to disambiguate returns.

| Resource setting | Default and meaning |
|---|---|
| `max_contexts` | 65536 concurrent forwarding contexts, including those awaiting safe reclamation. Configurable above this value; not a 4096 or 10000 gateway hard limit. |
| `max_connections` | 65536 native mappings **per worker** by default; configurable according to available resources. Independent of Pool quotas. Capacity acceptance selects 262144 per worker. |
| `heap_size` | `4G` native main heap reservation, configurable using an integer followed by `M` or `G`. Actual resident memory depends on load. |
| `stats_size` | `1G` native statistics heap reservation, configurable using `M` or `G`. This is needed for per-context native interface counters even with the statistics listener disabled. |
| `context_idle_seconds` | 1 second after the context has no live mapping; pending graph/handoff/reassembly references must also be safely drained. |
| `timeouts.udp` | 300 seconds of connection inactivity. |
| `timeouts.tcp_transitory` | 240 seconds. |
| `timeouts.tcp_established` | 7440 seconds. |
| `timeouts.icmp` | 60 seconds. |

`main_core` and `workers` select distinct available CPUs; omitting workers uses the native single-thread mode. Areas, attachments, Exits, Pools, addresses and rules use dynamically sized storage, with no additional fixed object-count ceiling. Pool IDs are sparse keys, not array indexes; removed state is reclaimed. The native statistics segment has no listener; its budget must include per-context interface counters. Size addresses, NAT slots, context budget, memory and CPUs together; an unlimited Pool quota is not unlimited gateway capacity.

The acceptance target is 12288 simultaneous active contexts and 196608 bidirectional NAT mappings across multiple switch sources, with two native workers. Consult the candidate's acceptance manifest and measured memory rather than inferring a throughput or latency guarantee.

## Wire identity and MTU

| Locator | Existing vSwitch contract |
|---|---|
| `port` | The received destination UDP port is an opaque locator and is preserved on return. Egress accepts the full nonzero UDP destination-port field, independently of the sender’s `port_base` or slot allocation. Area VNI is 24 bits. |
| `vni` | UDP 6081; VNI is `(slot << 12) | area`, with a 12-bit logical Area. |
| `tlv` | UDP 6081; configured class/type identify the first locator option, with a 24-bit Area. Unknown critical options fail; noncritical metadata is accepted without reflection. |

Egress imposes no slot range. It preserves locator values within their wire fields, including the complete 32-bit TLV value; context storage is keyed by source and locator rather than sized by the numeric slot. `port_base` remains an accepted compatibility hint and does not restrict ingress. Ether encapsulation with 1–20 generation bits encodes the existing generation in source MAC `02:fe:<32-bit big-endian generation>`; zero is valid. Egress learns the return marker and inner source from traffic, and keeps them immutable in that context. vSwitch checks tagged destination MACs against its existing generation, restores the Guest MAC, and preserves untagged legacy compatibility. No vSwitch Go configuration, Attach parameter or generation scheme changes.

IP encapsulation and legacy Ether add no new wire identity. Their existing inability to distinguish arbitrary late traffic after identity reuse remains; no Egress lease protocol is added to disguise that limitation.

Return encapsulation respects the smaller of the configured outer budget and inner MTU plus overhead. Inner and outer IPv4 fragments are reassembled natively. Returns may fragment within the tunnel budget; DF errors and related ICMP quotes retain the original context. Coordinate real path and vSwitch MTUs; the outer tunnel does not implement active PMTU discovery.

## Diagnostics and recovery

The private runtime directory contains `pid`, `startup.conf`, `owner.lock` and an atomically replaced `status.json`. The status file reports configuration generation, reload error, context and NAT counts, Area/Pool counters, native packet errors, native PID and interface/carrier state. It is output only and is never restored as configuration. No HTTP, Unix CLI, binary API, statistics listener or named shared-memory API transport is exposed. The supervisor uses an unnamed parent/child descriptor pair.

`egress link check --config link.json` reports pair ownership/placement and existing vSwitch conditions. Runtime checks cover the gateway process, configuration, deployment-owned wiring and interface state. Controlled end-to-end tests verify bidirectional Geneve forwarding and Pool return. External network/target probes, probe-target configuration and external-reachability startup gates are outside this deployment capability.

Losing or replacing one physical interface disables that interface pending controlled repair; unrelated paths continue. A same-name replacement is not adopted automatically. For local repair, stop affected traffic, drain allocated vSwitch ports through normal Detach, stop Egress before replacing its endpoint, run `egress link repair --config link.json --switch-config switch.json --mode veth`, restart Egress and verify traffic. A shared gateway restart loses its NAT state. The repair wrapper refuses active ports and does not force-delete sandboxes.

Normal `link stop` returns the switch endpoint to its stable owner and keeps the pair. Explicit uninstall follows Detach and stopping both sides, then `egress link uninstall --config link.json`. Only owned resources are removed; borrowed namespaces and Pool interfaces are retained. A namespace still containing processes or other devices is retained for a retry. No sandbox-specific notification is sent to Egress during these operations.

When upgrading from the earlier implementation, remove `vppctl` from the main JSON and stop using `egress request`, session grants and `policy.json`. Move the intended policies into the main file or referenced Area files before restart.

## Component delivery and node-infra

The same-version Connector release includes `bin/connector-egress.bundle`, the control binary, `deploy/connector-egress@.service`, and `deploy/egress` examples. The platform extracts the native runtime at `/opt/node-infra/lib/connector-egress`; configure its architecture-specific library and plugin paths accordingly.

For a managed local gateway, mount the main/Area files and `link.json` at `/etc/connector-egress`, and use the platform's `node-infra/examples/local-egress` example. The existing node preparation owns the shared link; `owner_netns: ""` refers to its retained primary network namespace, whose inode is checked on every operation. vSwitch still starts and stops through its unchanged node service. Egress has a separate forwarding process unit and SIGHUP reload, with no sandbox lifecycle coupling. Ordinary service stops retain the pair; final owner cleanup removes it only after the gateway and switch stop. Borrowed gateway namespaces and Pool interfaces remain with their external owner.
