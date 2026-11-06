[English](README.md) | [简体中文](README_zh.md)

# connector

For the first cross-component sandbox or Demo, follow the project
[Quick Start](https://github.com/kuasar-sandbox/kuasar-sandbox/blob/main/docs/quickstart.md)
with the matching aggregate release and
[workbench](https://github.com/kuasar-sandbox/kuasar-sandbox/blob/main/workbench/README.md).
This component can still be built/deployed independently; workbench is not a
production runtime dependency. Published architectures are specific to the
selected release; source support does not imply all historical assets exist.

`connector` is the **high-density eBPF networking component** for MicroVMs in [Kuasar Sandbox](https://github.com/kuasar-sandbox/kuasar-sandbox).

It allocates and releases sandbox network resources quickly, forwards established traffic in the Linux kernel, keeps sandbox-to-sandbox forwarding absent by default, assigns a platform-controlled network identity to each sandbox, and provides the foundation for enforcing sandbox-level policy at an external network gateway.

The repository can be used as part of the full Kuasar Sandbox platform or integrated independently with another MicroVM runtime through its TAP file-descriptor handoff contract.

## Choose a task

| Task | Guide |
|---|---|
| Deploy, allocate a port, observe traffic or recover a switch | [vSwitch operations](docs/vswitch-operations.md) |
| Integrate a gateway or review isolation, identity and ABI | [Network architecture and contracts](docs/vswitch.md) |
| Implement a TAP provider or consumer | [TAPFD protocol](docs/tapfd.md) |
| Build, test or change this component | [Contributing](CONTRIBUTING.md) |

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

Current attachment traffic reads and reset/error semantics are documented in [vSwitch stats](docs/vswitch-operations.md#connector-ctl-vswitch-stats). The Go Stats API reads multiple ports without per-port CLI processes.

## Integration with sandboxer

`sandboxer` imports only `github.com/kuasar-sandbox/connector/pkg/tapfd`. `connector-ctl` opens and configures TAP queues, then passes their file descriptors and, where required, a network-namespace descriptor over a Unix socket using `SCM_RIGHTS`. This keeps the runtime integration narrow and avoids linking the eBPF implementation into the MicroVM lifecycle engine.

## Distribution

Component releases use `vX.Y.Z`; the platform selects exact component tags in independent `release-vX.Y.Z` releases. Component archives supply the native `connector-ctl`, deployment templates and selected helpers. The aggregate archive supplies selected guides and prepared E2E inputs. Available architectures depend on the selected release assets. See [installation](https://github.com/kuasar-sandbox/kuasar-sandbox/blob/main/docs/installation.md) and [component packaging](CONTRIBUTING.md#component-packaging-and-releases).

## Project boundaries

- node and cluster orchestration belongs to [`orchestrator`](https://github.com/kuasar-sandbox/orchestrator);
- MicroVM lifecycle and the TAP consumer belong to [`sandboxer`](https://github.com/kuasar-sandbox/sandboxer);
- image/snapshot data infrastructure belongs to [`accelerator`](https://github.com/kuasar-sandbox/accelerator);
- guest runtime and kernel artifacts belong to [`guest-runtime`](https://github.com/kuasar-sandbox/guest-runtime);
- system design, shared integration tests, demos, and aggregate releases belong to [`kuasar-sandbox/kuasar-sandbox`](https://github.com/kuasar-sandbox/kuasar-sandbox).

## Contributing and security

Read the repository-specific [contribution guide](CONTRIBUTING.md) and the [organization contribution guide](https://github.com/kuasar-sandbox/.github/blob/main/CONTRIBUTING.md). Network protocol, TAP handoff, or cross-repository contract changes require linked companion pull requests and exact-source project validation.

Do not publish credentials, real internal topology, packet captures containing sensitive payloads, or unpatched vulnerabilities. Use the [Kuasar Sandbox Security Policy](https://github.com/kuasar-sandbox/kuasar-sandbox/security/policy) and GitHub private vulnerability reporting.

## License

Original project content is licensed under the [Apache License 2.0](LICENSE). The eBPF programs and generated objects retain the GPL-2.0-only boundary documented in [`LICENSE_SCOPE.md`](LICENSE_SCOPE.md). Preserve Linux, toolchain, vendored-code, and generated-artifact attribution and licensing.
