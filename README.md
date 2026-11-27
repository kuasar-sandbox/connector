[English](README.md) | [简体中文](README_zh.md)

# connector

For a first sandbox, follow the project's [Quick Start](https://github.com/kuasar-sandbox/kuasar-sandbox/blob/main/docs/quickstart.md): pull the node-infra image with `docker pull`, start it with `docker run`, and execute a command in a Guest. For a persistent node or cluster, continue with the platform deployment guides and explicit site configuration. Use the quickstart profile with its dedicated data volume; use a site-configured instance for custom workloads.

Use this repository's guides when deploying this component independently or integrating it with another runtime. Use the binaries, configuration examples and guides from the same selected release and architecture. [Workbench](https://github.com/kuasar-sandbox/kuasar-sandbox/blob/main/workbench/README.md) is for source development, demonstrations and integration validation.

`connector` is the **high-density eBPF networking component** for MicroVMs in [Kuasar Sandbox](https://github.com/kuasar-sandbox/kuasar-sandbox).

It allocates and releases sandbox network resources quickly, forwards established traffic in the Linux kernel, keeps sandbox-to-sandbox forwarding absent by default, assigns a platform-controlled network identity to each sandbox, and provides the foundation for enforcing sandbox-level policy at an external network gateway.

The repository can be used as part of the full Kuasar Sandbox platform or integrated independently with another MicroVM runtime through its TAP file-descriptor handoff contract.

## Choose a task

| Task | Guide |
|---|---|
| Provide sandbox IPv4 egress through a local or remote gateway | [Egress operations](docs/egress.md) |
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

A sandbox's tunnel identity lets the gateway select its network policy independently of the guest's self-reported address. The vSwitch supplies forwarding and identity; deployment owners choose the gateway and its policy. Starting a vSwitch alone does not provide Internet access.

The [Geneve Egress gateway](docs/egress.md) supplies IPv4 routing, ordered ACLs, DNAT and native NAT with the same Area/Pool configuration for local and remote deployment. Valid traffic creates state automatically. Use a managed local gateway with node-infra, a dedicated local pair for an independent switch, or a remote gateway reached through an owned underlay. DNS/domain policy and application proxies require services outside this gateway.

Install the matching `connector-ctl` and fully static `connector-vpp` from one component release, keeping them together in `bin/`. A separate VPP installation, plugin directory or sandbox-registration service is unnecessary. Source builds and native acceptance belong to [Egress build and acceptance](egress/README.md).

## Main interfaces

| Path | Purpose |
| --- | --- |
| `cmd/connector-ctl` | Start/serve/stop a vSwitch; attach/detach, reserve/provision, open a port, inspect status/statistics, and provide DHCP support |
| `pkg/egress` | File configuration/reload, gateway process supervision and owned local-link lifecycle |
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

Component releases use `vX.Y.Z`; the platform selects exact component tags in independent `release-vX.Y.Z` releases. Component archives supply `bin/connector-ctl`, the matching fully static `bin/connector-vpp` with `bin/vpp-runtime.json`, deployment templates and selected helpers. The aggregate archive supplies selected guides and prepared E2E inputs. Available architectures depend on the selected release assets. See [installation](https://github.com/kuasar-sandbox/kuasar-sandbox/blob/main/docs/installation.md) and [component packaging](CONTRIBUTING.md#component-packaging-and-releases).

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
