[English](README.md) | [简体中文](README_zh.md)

# connector

`connector` is the **high-density eBPF networking component** for MicroVMs in [Kuasar Sandbox](https://github.com/kuasar-sandbox/kuasar-sandbox).

It allocates and releases sandbox network resources quickly, forwards established traffic in the Linux kernel, keeps sandbox-to-sandbox forwarding absent by default, assigns a platform-controlled network identity to each sandbox, and provides the foundation for enforcing sandbox-level policy at an external network gateway.

The repository can be used as part of the full Kuasar Sandbox platform or integrated independently with another MicroVM runtime through its TAP file-descriptor handoff contract.

## Network model

The base vSwitch provides:

- per-sandbox isolated network channels;
- kernel-resident forwarding through eBPF/TC after control-plane configuration;
- platform validation and rewriting of sandbox network identity rather than trusting guest-supplied source identity;
- controlled access to node management services;
- external-network integration through GENEVE;
- fast attach, detach, reserve, provision, and port-open operations;
- statistics and lifecycle inspection through `connector-ctl`;
- TAP and network-namespace file-descriptor handoff to the VMM/runtime.

The top-level purpose is not a particular Slot, VNI, UDP-port, or TLV encoding. Those mechanisms let a deployment assign each sandbox an independent tunnel-plane identity and carry trusted sandbox metadata to an external policy gateway. The gateway can then apply sandbox-level public-network, private-network, DNS, proxy, audit, and traffic-governance rules without embedding application policy in the base switch.

A node-local lightweight Egress policy plane is tracked as a [proposed extension](https://github.com/kuasar-sandbox/connector/issues/9). It is not presented as an already delivered feature of the base vSwitch.

## Main interfaces

| Path | Purpose |
| --- | --- |
| `cmd/connector-ctl` | Start/serve/stop a vSwitch; attach/detach, reserve/provision, open a port, inspect status/statistics, and provide DHCP support |
| `pkg/vswitch` | Programmatic vSwitch lifecycle and port management |
| `pkg/tapfd` | Public provider/consumer SDK for passing TAP and network-namespace file descriptors over Unix sockets |
| `pkg/netlink`, `pkg/netns`, `pkg/dhcp`, `pkg/daemon` | Linux network, namespace, DHCP, and service helpers |
| `bpf/` | eBPF C sources; pre-generated runtime objects are in `pkg/internal/bpf/` |
| `dist/` | systemd units and configuration templates |

The normative TAP handoff protocol is documented in [`docs/tapfd.md`](docs/tapfd.md).

## Build and test

```bash
make build                      # bin/<arch>/connector-ctl; pure Go control plane
make build TARGET_ARCH=aarch64  # cross-compile; amd64/arm64 aliases are accepted
make generate                   # regenerate BPF objects after changing bpf/*.c; requires Clang/LLVM
make test                       # unit tests
sudo make test-e2e              # privileged networking owner suite
```

Runtime requirements:

- Linux 5.10 or newer with BTF and TC BPF support;
- root or the equivalent required capabilities;
- network namespaces, TAP, veth, routing, and TC support;
- Go 1.24 or newer for source builds;
- Clang 12 or newer only when regenerating BPF objects.

The repository includes pre-generated BPF objects, so an ordinary build does not require Clang. A skipped privileged test must not be interpreted as completed network validation. Privileged E2E must run in an isolated candidate environment and clean up every TAP device, namespace, route, rule, BPF map, and pin path owned by the run.

## Minimal local example

The following illustrates a fresh switch. Run as root with a dedicated, unused `eth1` that can safely be moved into `sw_ns`; the underlay must support the resulting transit MTU. A TAPFD-capable VMM receiver must already be listening on `/tmp/recv.sock` before `open-port`. Production values depend on the deployment network:

```bash
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

connector-ctl vswitch attach sw1 \
    --inner-ip=169.254.1.1 \
    --transit-gateway-ip=10.0.0.2 \
    --transit-geneve-vni=100

TAPFD_SOCKET=/tmp/recv.sock \
    connector-ctl vswitch open-port sw1 --port=1

connector-ctl vswitch detach sw1 --port=1
connector-ctl vswitch stop sw1
```

These addresses are documentation values, not a production topology. Run `stop` from the namespace that should receive the returned transit device. Inspect actual port and transit MTUs: the current two-phase provision path does not propagate `--mtu` to newly created TAP/veth ports. The complete command reference and deployment procedures are in [vSwitch operations](docs/vswitch-operations.md); forwarding and lifecycle constraints are defined in [vSwitch design](docs/vswitch.md).

The legacy [manage_switch.sh](examples/manage_switch.sh) helper illustrates veth
namespace orchestration. Its current start call omits `--mode=veth` even though
the CLI defaults to TAP: adapt that call to `start --mode=veth --config "$tmpfile"`
before using `setup`. The helper also derives ports from sandbox index + 1 and
therefore assumes fresh sequential allocation; reuse requires consuming the
actual port returned by `attach`. Its `help` output describes the configuration
shape, and `example` prints JSON without setting up networking.

## Integration with sandboxer

`sandboxer` imports only `github.com/kuasar-sandbox/connector/pkg/tapfd`. `connector-ctl` opens and configures TAP queues, then passes their file descriptors and, where required, a network-namespace descriptor over a Unix socket using `SCM_RIGHTS`. This keeps the runtime integration narrow and avoids linking the eBPF implementation into the MicroVM lifecycle engine.

## Release model

`connector` publishes independent component versions named `vX.Y.Z`. The x86_64 component archive contains `connector-ctl`, deployment files, and the operational helpers selected by the component release contract. Design documents and E2E sources are collected from the selected component tag into the project platform archive.

The project repository publishes aggregate versions named `release-vX.Y.Z`, selecting an exact `connector` tag together with the other release units and validating the combined platform. Component and aggregate version numbers are independent.

See the [project release documentation](https://github.com/kuasar-sandbox/kuasar-sandbox/blob/main/docs/release.md) and the [latest Stable aggregate release](https://github.com/kuasar-sandbox/kuasar-sandbox/releases/latest).

## Documentation

- [vSwitch operations](docs/vswitch-operations.md) — complete CLI/configuration, deployment and troubleshooting.

Detailed design and reference documents have complete English and Chinese editions:

- [vSwitch — English](docs/vswitch.md) / [Chinese](docs/vswitch_zh.md) — architecture, data paths, management and external networking, security properties, reliability, performance, and tests;
- [TAPFD — English](docs/tapfd.md) / [Chinese](docs/tapfd_zh.md) — normative TAP file-descriptor handoff protocol for providers and consumers.

The English README contains the complete public component entry path. Detailed locator encodings and packet-field layouts remain in the specialized design document rather than the public overview.

## Project boundaries

- node and cluster orchestration belongs to [`orchestrator`](https://github.com/kuasar-sandbox/orchestrator);
- MicroVM lifecycle and the TAP consumer belong to [`sandboxer`](https://github.com/kuasar-sandbox/sandboxer);
- image/snapshot data infrastructure belongs to [`accelerator`](https://github.com/kuasar-sandbox/accelerator);
- guest runtime and kernel artifacts belong to [`guest-runtime`](https://github.com/kuasar-sandbox/guest-runtime);
- system design, shared BMS, demos, and aggregate releases belong to [`kuasar-sandbox/kuasar-sandbox`](https://github.com/kuasar-sandbox/kuasar-sandbox).

## Contributing and security

Read the repository-specific [contribution guide](CONTRIBUTING.md) and the [organization contribution guide](https://github.com/kuasar-sandbox/.github/blob/main/CONTRIBUTING.md). Network protocol, TAP handoff, or cross-repository contract changes require linked companion pull requests and exact-source project validation.

Do not publish credentials, real internal topology, packet captures containing sensitive payloads, or unpatched vulnerabilities. Use the [Kuasar Sandbox Security Policy](https://github.com/kuasar-sandbox/kuasar-sandbox/security/policy) and GitHub private vulnerability reporting.

## License

Original project content is licensed under the [Apache License 2.0](LICENSE). The eBPF programs and generated objects retain the GPL-2.0-only boundary documented in [`LICENSE_SCOPE.md`](LICENSE_SCOPE.md). Preserve Linux, toolchain, vendored-code, and generated-artifact attribution and licensing.
