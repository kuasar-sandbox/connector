[English](egress.md) | [简体中文](egress_zh.md)

# Geneve Egress operations

Egress is a file-configured IPv4 Geneve forwarding gateway with ordered ACLs, TCP/UDP DNAT, longest-prefix Pool selection and native NAT44-ED. Valid traffic creates forwarding state automatically. Native protocol inactivity timers release NAT mappings, followed by safe reclamation of idle contexts. Egress has no sandbox registration, token, lease, renew or release protocol and exposes no management API.

Local and remote deployments use the same Area/Pool configuration and wire contract. The gateway does not provide DNS/domain policy, an application proxy, IPv6 forwarding or automatic Pool failover. [Proposal #117](https://github.com/kuasar-sandbox/connector/issues/117) is the design baseline.

## Deployment and ownership

### Choose the deployment owner

| Deployment | Start here | Owner of switch/transit lifecycle |
|---|---|---|
| Platform node with local Egress | [node-infra deployment](https://github.com/kuasar-sandbox/kuasar-sandbox/blob/main/docs/node-infra.md) and its `examples/local-egress` files | node-infra preparation and normal vSwitch service; Egress has its own unit. |
| Independently deployed vSwitch with local Egress | The standalone sequence below | `connector-ctl egress link` owns the dedicated pair and wraps switch start/stop. |
| Remote Egress shared by nodes | The remote deployment section below | Deployment owner supplies the routed underlay; no local-pair wrapper. |

Use a release that actually includes native Egress: matching `bin/connector-ctl`, `bin/connector-vpp`, `bin/vpp-runtime.json` and Egress deployment templates. For node-infra, select an aggregate whose image includes these binaries and `connector-egress.service`; adding a new configuration to an older image does not add that service. Follow [platform installation](https://github.com/kuasar-sandbox/kuasar-sandbox/blob/main/docs/installation.md) to select and verify the assets. The quickstart profile is not the custom local-Egress deployment profile. [Source build and acceptance](../egress/README.md) is for producing or changing the component.

Install both executables from the same component version. The default `connector-vpp` lookup is beside the actual `connector-ctl` executable, after resolving its symlink; neither the working directory nor `PATH` determines the dataplane path. Keep the complete `bin/` directory. The optional `vpp` field provides an absolute override. The static dataplane needs no separate VPP package, shared-library directory or externally loaded plugin set.

VPP owns each configured gateway/SNAT address; Linux must not hold the same address on that interface. Unrelated Linux IPv4 addresses are permitted. The external-network owner provides the uplink, MTU, UP state, reachable next hop and return routing for the selected SNAT addresses. The host default route is not an implicit Pool exit. The dataplane normalizes AF_PACKET checksum and TCP segmentation metadata without changing borrowed devices or external peers.

### Standalone local gateway

Use [link.json](../dist/egress/link.json), [switch.json](../dist/egress/switch.json), [gateway.yaml](../dist/egress/gateway.yaml) and [area7.yaml](../dist/egress/area7.yaml) as one configuration set. Example addresses are documentation ranges; replace them with the addresses and devices owned by your deployment. This procedure assumes a fresh deployment with unused `egress-owner`, `egress-local`, `switch`, `ports` and `sw0` names. Run privileged commands as root.

1. Extract the component archive into `/opt/connector`. Copy the examples to `/etc/connector-egress`, naming the gateway file `egress-local.yaml` for the service template. Keep its relative `area_files` next to it. Install [connector-egress@.service](../dist/connector-egress@.service) under `/etc/systemd/system/`.
2. Edit the whole set before starting. Validate policy and prepare the owned pair:

   ```bash
   /opt/connector/bin/connector-ctl egress validate --config /etc/connector-egress/egress-local.yaml
   /opt/connector/bin/connector-ctl egress link prepare --config /etc/connector-egress/link.json
   ip netns add switch
   ip netns add ports
   ```

   `validate` prints `{"valid":true}` for a valid file set; it does not check physical reachability. `prepare` creates or verifies the owner/gateway namespaces and records pair ownership. The switch and port namespaces are separate prerequisites.
3. Have the external-network owner place `egress-uplink` in `egress-local`, set its configured MTU and bring it UP. Provide an on-link Pool next hop and return routing for every selected SNAT address. Do not assign VPP-owned addresses to Linux. This is site-specific network provisioning, not a requirement to run a Docker gateway or add a second host NAT layer.
4. Start the gateway and the TAP switch, then inspect their state:

   ```bash
   systemctl daemon-reload
   systemctl start connector-egress@egress-local.service
   /opt/connector/bin/connector-ctl egress link start \
     --config /etc/connector-egress/link.json \
     --switch-config /etc/connector-egress/switch.json --mode tap
   /opt/connector/bin/connector-ctl egress link check --config /etc/connector-egress/link.json
   cat /var/lib/connector-egress/egress-local/status.json
   ```

   `tap` is also the default and is the MicroVM path. Choose `veth` only for a consumer that deliberately uses namespace ports. If directly supervising Egress instead of systemd, run `ip netns exec egress-local /opt/connector/bin/connector-ctl egress serve --config /etc/connector-egress/egress-local.yaml` in its own foreground service or terminal before starting the switch.
5. Attach through the owning runtime or [vSwitch/TAPFD workflow](vswitch-operations.md). Set the attachment's transit gateway and logical VNI to match the gateway configuration, then verify real request/reply traffic through each intended Pool. No Egress registration is involved.

The bundled example has the following matching fields:

| Side | Value | Meaning |
|---|---|---|
| vSwitch `transit_dev_addr` | `198.18.0.2/24:198.18.0.1` | Switch underlay address and next hop. |
| Gateway interface / attachment | `198.18.0.1/24`, `peer: 198.18.0.2`, `locator: port` | Gateway ingress and admitted switch source. |
| Each sandbox attachment | `transit_gateway_ip: 198.18.0.1`, `transit_geneve_vni: 7` | Select this gateway and Area `vni: 7`; these are not the Guest's default-router address or subnet. |
| vSwitch | `generation_bits: 4`, `geneve_encap_eth: true` | Enable the existing generation MAC fencing on Ether Geneve. The caller advances attachment generation on identity reuse. |

There is no switch-wide default Area/VNI or separate `TransitMACFencing` setting. CLI consumers pass `--transit-gateway-ip` and `--transit-geneve-vni` to `vswitch attach`; TAPFD consumers use the corresponding underscore fields. Orchestrator supplies these through the Create/Build network specification or an inherited template; see [request configuration](https://github.com/kuasar-sandbox/orchestrator/blob/main/docs/sandbox-lifecycle.md#request-configuration) and the [Build client workflow](https://github.com/kuasar-sandbox/orchestrator/blob/main/docs/node-build.md#client-workflow). Merely defining Area 7 at the gateway does not select it for a sandbox. Do not add `generation_bits` or encapsulation fields to an Egress attachment.

Repeated prepare verifies and reuses the owned pair. It rejects foreign names, changed namespace identities and damaged installed pairs. Each local vSwitch uses a dedicated pair; multiple pairs may share an Egress instance. Distinct gateway IPs use distinct ingress addresses. The same peer, locator and inner IP may access each gateway independently. Existing vSwitch `transit_dev_mtu:auto` may lower its endpoint below the provisioned gateway MTU; this does not change pair ownership.

### Remote gateway

Use externally owned transit devices instead of `egress link prepare/start`. Route each switch's outer source to the configured Egress ingress address, admit that source with an attachment, and set the sandbox gateway/VNI as above. Configure each Pool's exit separately from the return path to switches.

`peer` accepts an IPv4 address, CIDR, inclusive IP range, or a list of these, for example `["198.18.0.2", "203.0.113.0/24"]`; omission or an empty list adds no source filter. The actual peer always comes from the outer source IP. An omitted `next_hop` uses the actual peer as a directly reachable next hop; routed peers require an on-link router. Packet VNI selects a configured Area without per-attachment Area registration. Overlapping source ranges for the same ingress/gateway must agree on decoding, MTU and return routing or the complete candidate is rejected. The same gateway/source range cannot select different return devices; disjoint peer ranges may reuse a gateway address across devices. Remote transit and Pool exits may share an interface when their Geneve gateway and SNAT addresses are distinct; the local dedicated veth remains separate. Geneve access fields and the opaque return MAC are not cryptographic authentication; underlay ownership must prevent sender impersonation.

## Files and reload

The main and Area files use YAML, including its JSON subset. `areas` may contain inline Area objects; `area_files` lists files containing one Area object each, resolved relative to the main file. Both sources form one validated set. Unknown fields, duplicate members, duplicate Areas, invalid references, and trailing values are rejected.

Complete all file edits, then trigger reload:

```bash
systemctl reload connector-egress@egress-local.service
# For a directly supervised process:
kill -HUP "$(cat /var/lib/connector-egress/egress-local/pid)"
```

Each reload reads the main file and all referenced Area files, validates and stages the complete candidate, then publishes all Areas and attachment profiles under one worker barrier. A parse, reference or preparation error retains the previous configuration. No independently writable online policy store exists. Use atomic file replacement and send SIGHUP after the complete file set is ready.

Reload supports Areas, ACL/DNAT/routes/Pools, source admission, peer return routing and inactivity timeouts. Pool `interface`, `next_hop` and `addresses` may change on already admitted devices: existing mappings retain their original exit resources until reclamation while new mappings use the new definition. A new ingress address that overlaps a retained SNAT mapping rejects the entire reload; retry after those mappings expire. Update the Area-file list when removing an Area. Executable paths, CPU/preallocated memory, physical device takeover and namespace changes require maintenance restart; these changes are rejected before publication with the running configuration retained. An ambiguous native publication acknowledgement stops the gateway rather than reporting an unproven rollback.

Ordinary route, DNAT and SNAT selection changes affect new mappings. Existing mappings retain their original public tuple, destination translation and exit. Lower Pool quotas limit new mappings without evicting existing mappings. ACL revocation, removed Pools/Areas and unavailable original paths invalidate only affected mappings. Incompatible attachment wire/gateway changes retire affected contexts; an existing mapping's saved opaque return MAC is never replaced by one from later traffic.

A process restart reads the files again and does not restore NAT state. Subsequent valid traffic automatically creates new forwarding state. No controller re-registration is required.

## Configuration and resources

| Object | Meaning |
|---|---|
| Interface | Linux device name, VPP-owned IPv4 `address` prefix and physical L3 `mtu`. |
| Attachment | `name`, `interface`, optional `peer` source list and return `next_hop`, `locator` and TLV decoding fields. The default locator is `port`; `inner_mtu` defaults to 1500 and `mtu` to the interface MTU. Ether/IP encapsulation is determined from the packet; an Ether source MAC is retained as opaque return information. |
| Area | Logical `vni`, ordered `acl`, ordered TCP/UDP `dnat`, longest-prefix `routes` and Pools. |
| Pool | Area-local unique `name`, with its own `interface`, on-link `next_hop` and SNAT `addresses`; routes and DNAT refer to its name. `max_connections` limits live NAT mappings for each outer access in that Pool. Zero or omission removes that business quota. |
| Match | Destination IP/CIDR/range sets, protocol values and port sets as described below; ports require TCP/UDP. `any` also covers other ordinary IPv4 protocols. |

ACL first-match/default-allow applies to the original destination before DNAT. A DNAT match selects its Pool directly; otherwise routing uses longest-prefix selection. A single Pool with omitted `routes` is the default exit. Explicit `routes: []` disables ordinary routing but permits DNAT. Multiple Pools require explicit routes; an Area with no Pools has no exit. `routes: null` is invalid. A missing route, exhausted selected Pool or unavailable exit fails without choosing another Pool. Portless IPv4 protocols require distinct public addresses for overlapping remote/protocol tuples because they have no translated port to disambiguate returns.

Address fields `addresses` (Pool), `destination` (rule) and `peer` accept one value or a list: `192.0.2.10`, `192.0.2.0/28`, or `192.0.2.10-192.0.2.30`. Intervals include both endpoints. Pool ranges contain every supplied unicast address, including CIDR endpoints; they do not silently subtract subnet network/broadcast addresses. The operator must own and route every selected address. Duplicates and overlapping sets are normalized. Explicit route CIDR lengths retain their LPM precedence; duplicate identical routes are removed, conflicting identical prefixes are rejected.

`ports` accepts `443`, `"8000-8100"`, or `[80, 443, "8000-8100"]`; endpoints must be 1..65535. `protocol` accepts one of `any`, `icmp`, `tcp`, `udp`, or a list. Omitted destination matches any address. Omitted protocol means `any`, except a port constraint or DNAT implies TCP/UDP. Omitted ports matches any port; port constraints require TCP/UDP. Empty match lists and null values are rejected; omit the field to express any value. ACLs may contain only `action`. Omitted or empty ACL allows unmatched traffic; add a final `action: deny` for an allowlist. No `cidrs`, `protocols`, `port_first` or `port_last` aliases are accepted.

```yaml
acl:
  - destination: [203.0.113.0/24, 198.51.100.10-198.51.100.20]
    protocol: [tcp, udp]
    ports: [443, "8000-8100"]
    action: allow
  - action: deny
```

| Resource setting | Default and meaning |
|---|---|
| `heap_size` | `4G` native main heap reservation, configurable using an integer followed by `M` or `G`. Actual resident memory depends on load. |
| `stats_size` | `1G` native statistics heap reservation, configurable using `M` or `G`. This is needed for per-context native interface counters even with the statistics listener disabled. |
| `context_idle_seconds` | 1 second after the context has no live mapping; pending graph/handoff/reassembly references must also be safely drained. |
| `timeouts.udp` | 300 seconds of connection inactivity. |
| `timeouts.tcp_transitory` | 240 seconds. |
| `timeouts.tcp_established` | 7440 seconds. |
| `timeouts.icmp` | 60 seconds. |

The main configuration has no `max_contexts` or `max_connections`, and the dataplane has no hidden equivalent independent admission ceiling. Initial memory allocation does not cap admission. `main_core` and `workers` select distinct available CPUs; omitting workers uses native single-thread mode. Areas, attachments, Pools, addresses and rules use dynamic storage. The native statistics segment has no listener but still needs memory for forwarding state counters. Available memory, CPU, addresses and ports remain finite; an unlimited Pool quota does not make gateway resources unlimited.

Size each gateway from measured concurrent accesses, mappings, packet rate and resident memory. The developer [acceptance matrix](../egress/README.md#native-acceptance) tests 12288 active contexts and 196608 bidirectional mappings with two workers; those are validation workloads, not deployment defaults or throughput/latency guarantees.

## Wire identity and MTU

| Locator | Existing vSwitch contract |
|---|---|
| `port` | The received destination UDP port is an opaque locator and is preserved on return. Egress accepts the full nonzero UDP destination-port field, independently of the sender’s `port_base` or slot allocation. Area VNI is 24 bits. |
| `vni` | UDP 6081; VNI is `(slot << 12) | area`, with a 12-bit logical Area. |
| `tlv` | UDP 6081; configured class/type identify the first locator option, with a 24-bit Area. Unknown critical options fail; noncritical metadata is accepted without reflection. |

Egress imposes no slot range. It preserves locator values within their wire fields, including the complete 32-bit TLV value; context storage is keyed by source and locator rather than sized by the numeric slot. Egress does not configure `port_base`.

Access identity is the outer source IP + Geneve destination port or SlotID + VNI/logical Area + outer destination IP (gatewayIP). Inner IPs participate in routing and connection lookup; multiple inner IPs share this access’s Pool quota. The inner MAC is return information, not an additional access identity or Pool quota.

With Ether encapsulation, Egress preserves the received inner source MAC as opaque return information and uses it unchanged as the inner destination MAC in that mapping’s replies. Later traffic cannot replace an existing mapping’s saved return MAC. Egress does not decode fencing prefixes, generation values or generation widths. [vSwitch](vswitch.md) owns the fencing checks, Guest MAC restoration and existing legacy compatibility.

There is no inner `gateway` field. ICMP errors use the ingress data-plane address as their source; this neither changes the Guest default gateway nor constrains its inner IP.

IP encapsulation and legacy Ether add no new wire identity. Their existing inability to distinguish arbitrary late traffic after identity reuse remains; no Egress lease protocol is added to disguise that limitation.

Return encapsulation respects the smaller of the configured outer budget and inner MTU plus overhead. Inner and outer IPv4 fragments are reassembled natively. Returns may fragment within the tunnel budget; DF errors and related ICMP quotes retain the original context. Coordinate real path and vSwitch MTUs; the outer tunnel does not implement active PMTU discovery.

## Diagnostics and recovery

The private runtime directory contains `pid`, `startup.conf`, `owner.lock` and an atomically replaced `status.json`. The status file reports configuration generation, reload error, outer accesses (`accesses`), internal return versions (`contexts`), NAT counts, named Area/Pool counters, native packet errors, native PID and interface/carrier state. It is output only and is never restored as configuration. No HTTP, Unix CLI, binary API, statistics listener or named shared-memory API transport is exposed. The supervisor uses an unnamed parent/child descriptor pair.

For the standalone unit, inspect both the unit and the current output file:

```bash
systemctl status connector-egress@egress-local.service
journalctl -u connector-egress@egress-local.service -n 100 --no-pager
cat /var/lib/connector-egress/egress-local/status.json
```

After reload, confirm `configuration_generation` advanced and `reload_error` is empty, then test affected traffic. A successful `systemctl reload` means the signal was delivered, not that the candidate was accepted. For node-infra, use `connector-egress.service`, `systemctl reload connector-egress`, and `/run/connector-egress/local/status.json` inside the node container. The file-reading CLI described next is available in current source; the published `v0.2.0-preview.20261127` control binary uses these file commands.

### Read a saved snapshot with the CLI

Current source adds `egress status`; use a build/release containing this change. It is a read-only convenience over the existing file, not a management API or health probe:

```bash
connector-ctl egress status --config /etc/connector-egress/egress-local.yaml
# Inspect the retained running configuration's snapshot even if edited files are invalid:
connector-ctl egress status --runtime-dir /var/lib/connector-egress/egress-local
```

Provide exactly one nonempty selector. `--config` loads the whole candidate file set to locate `runtime_dir`; `--runtime-dir` reads that directory directly. JSON output wraps the unchanged native object in `snapshot` and adds its absolute `path`, UTC file modification time `updated_at`, and `age_seconds`. The timestamp is the file's metadata, not an independently verified collection time. Retained or copied files can outlive a gateway; the command neither contacts nor signals a process and does not claim it is running. Missing, unreadable or malformed snapshots return an error. Use the unit and real traffic checks above to assess operation.

### Wiring and repair

`egress link check --config link.json` reports pair ownership/placement and existing vSwitch conditions. Runtime checks cover the gateway process, configuration, deployment-owned wiring and interface state. Controlled end-to-end tests verify bidirectional Geneve forwarding and Pool return. External network/target probes, probe-target configuration and external-reachability startup gates are outside this deployment capability.

Losing or replacing one physical interface disables that interface pending controlled repair; unrelated paths continue. A same-name replacement is not adopted automatically. For local repair, stop affected traffic, drain allocated vSwitch ports through normal Detach, stop Egress before replacing its endpoint, run `egress link repair --config link.json --switch-config switch.json --mode tap` (or the original `veth` mode), restart Egress and verify traffic. A shared gateway restart loses its NAT state. The repair wrapper refuses active ports and does not force-delete sandboxes.

Normal `link stop` returns the switch endpoint to its stable owner and keeps the pair. Explicit uninstall follows Detach and stopping both sides, then `egress link uninstall --config link.json`. Only owned resources are removed; borrowed namespaces and Pool interfaces are retained. A namespace still containing processes or other devices is retained for a retry. No sandbox-specific notification is sent to Egress during these operations.

Use the file model and bundled examples above. The main file has no `exits`; Pools have no numeric `id`; attachments have no `area`, `port_base`, `encapsulation`, `generation_bits` or inner `gateway`. Strict validation rejects these fields.

## Component delivery and node-infra

The same-version Connector release places `connector-ctl`, `connector-vpp`, and `vpp-runtime.json` directly under `bin/`. The dataplane includes VPP, its six built-in plugins and libc in one fully static executable. The archive also includes native license materials, `deploy/connector-egress@.service`, and `deploy/egress` examples. Keep the complete directory when installing or copying the component. In node-infra these files are under `/opt/node-infra/bin`; the gateway uses `/opt/node-infra/bin/connector-vpp`.

For a managed local gateway, mount the main/Area files and `link.json` at `/etc/connector-egress`, and use the platform's `node-infra/examples/local-egress` example. The existing node preparation owns the shared link; `owner_netns: ""` refers to its retained primary network namespace, whose inode is checked on every operation. vSwitch still starts and stops through its unchanged node service. Do not also run standalone `egress link start/stop` against that managed switch. Egress has a separate forwarding process unit and SIGHUP reload, with no sandbox lifecycle coupling. Ordinary service stops retain the pair; final owner cleanup removes it only after the gateway and switch stop. Borrowed gateway namespaces and Pool interfaces remain with their external owner.
