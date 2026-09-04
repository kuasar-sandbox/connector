# Kuasar Sandbox Connector

[简体中文](README.md) · [Kuasar Sandbox project](https://github.com/kuasar-sandbox/kuasar-sandbox)

`connector` is the high-density eBPF networking component for Kuasar Sandbox and other MicroVM platforms. It provides fast sandbox network allocation and release, kernel data-plane forwarding, default sandbox-to-sandbox isolation, trusted sandbox network identity, and the foundation for applying per-sandbox policy through an external network gateway.

The component focuses on a small, fast, auditable virtual-switch boundary. Higher-level DNS, proxy, Internet/private-network access, policy, and audit logic can remain in dedicated gateway services rather than becoming hard-coded business behavior in the base switch.

`connector` can be deployed as part of the complete Kuasar Sandbox platform or integrated independently. The project repository owns system-level architecture, cross-component BMS/E2E, demos, and aggregate release selection.

## Design goals

A high-density sandbox network needs to solve three problems together:

1. allocate and reclaim networking quickly as sandboxes are created and destroyed;
2. forward traffic efficiently when a node hosts many MicroVMs;
3. preserve a trustworthy per-sandbox identity so network policy is not based on addresses supplied by an untrusted guest.

The connector data path therefore aims to provide:

- no default direct forwarding path between sandbox ports;
- platform-controlled attachment and identity;
- forwarding decisions that do not trust a guest-provided source address as the security identity;
- controlled management-service paths;
- external-network integration through a tunnel or gateway boundary;
- kernel-resident forwarding after configuration, without requiring a userspace process on every packet;
- deterministic cleanup of TAP devices, namespaces, routes, maps, and pinned eBPF objects owned by a sandbox or test run.

## Sandbox-level network policy

### Central policy gateway integration

For deployments with a central network-security platform, connector can establish an independently identifiable external path for each sandbox and carry trusted sandbox identity to the policy gateway.

The gateway can then apply:

- Internet egress policy;
- tenant-private-network access;
- DNS and proxy selection;
- destination and protocol controls;
- connection accounting, audit, and traffic governance.

The virtual switch is responsible for fast identity, transport, isolation, and forwarding. The gateway is responsible for interpreting tenant and application policy.

Encoding details used to carry identity—such as port, VNI, or tunnel-option layouts—belong in the dedicated design documentation. They are integration contracts, not the top-level definition of the component.

### Node-local egress policy plane

A lightweight node-local egress policy service is tracked as a separate design proposal. It is intended for deployments that do not use a central policy gateway, while keeping policy, DNS, connection state, and audit logic outside the base vSwitch.

Unless a particular release and feature-status document says otherwise, do not treat the node-local egress proposal as a delivered connector capability.

## Main capabilities

- eBPF/TC-based virtual switching for MicroVM TAP interfaces;
- rapid attach/detach and explicit ownership of network resources;
- sandbox isolation by data-path structure;
- management-service access through controlled translation paths;
- external network/tunnel integration;
- trusted sandbox identity exported to an external policy point;
- support for platform-managed floating or forwarded service addresses where configured;
- interface-file-descriptor handoff to the runtime boundary;
- verification and cleanup tooling for namespaces, devices, maps, routes, and pins.

The exact map layout, tunnel metadata, address model, CLI flags, and attach/detach protocol are documented in `docs/vswitch.md` and other repository design documents.

## Component boundaries

| Component | Connector interaction |
| --- | --- |
| [`sandboxer`](https://github.com/kuasar-sandbox/sandboxer) | Receives the prepared TAP/interface contract and attaches it to the MicroVM lifecycle |
| [`orchestrator`](https://github.com/kuasar-sandbox/orchestrator) | Allocates sandbox network intent, coordinates lifecycle, routes services, and integrates tenant/platform policy |
| [`accelerator`](https://github.com/kuasar-sandbox/accelerator) | No direct network data-path dependency; both remain separate components composed by the platform |
| [`guest-runtime`](https://github.com/kuasar-sandbox/guest-runtime) | Supplies the guest network stack and runtime environment; guest addresses are not treated as the trusted platform identity |
| [`kuasar-sandbox`](https://github.com/kuasar-sandbox/kuasar-sandbox) | Selects exact versions and validates the integrated network/runtime path |

## Build and test

This repository contains Go userspace code and eBPF programs. A typical public build environment needs:

- Go as declared by `go.mod`;
- Clang/LLVM and the repository-supported BPF toolchain;
- Linux UAPI/kernel headers and BTF information compatible with the build path;
- generated-code tools declared by the repository;
- root or the required capabilities for privileged integration tests.

For a standalone checkout, keep Go workspace overrides disabled unless you intentionally use the six-repository sibling workspace:

```bash
GOWORK=off go test ./...
GOWORK=off go build ./...
```

Use the repository `Makefile`, current Chinese README, and `docs/` tree as the authoritative source for BPF generation, binary names, kernel requirements, and privileged E2E commands.

### Test levels

- Go unit/static checks and non-privileged parsers should run without production credentials.
- BPF compile/verifier checks require the documented compiler and kernel metadata.
- Network E2E may require root or `CAP_NET_ADMIN`, network namespaces, TAP devices, routes, and eBPF program loading.
- Cross-component tests run through project BMS using an exact source set.

External fork code must not automatically execute as root on a shared host network or on a runner holding release/control credentials. Privileged tests require an isolated candidate runner or explicit trusted approval.

### Cleanup

Every privileged test must own uniquely named resources and remove them on success, failure, and cancellation. Validation should check for residual:

- network namespaces;
- TAP/veth devices;
- routes and policy rules;
- qdiscs and TC filters;
- pinned BPF maps/programs;
- test processes and sockets.

Do not use global cleanup that can delete resources belonging to another test or deployment.

## Documentation

- [Project English overview](https://github.com/kuasar-sandbox/kuasar-sandbox/blob/main/README_EN.md)
- [English Quick Start](https://github.com/kuasar-sandbox/kuasar-sandbox/blob/main/docs/quickstart_en.md)
- [Project architecture](https://github.com/kuasar-sandbox/kuasar-sandbox/blob/main/docs/kuasar-sandbox.md)
- [English release overview](https://github.com/kuasar-sandbox/kuasar-sandbox/blob/main/docs/releases_en.md)
- [Virtual-switch design](docs/vswitch.md)

Detailed design documents may remain Chinese during the initial source-publication phase. Build prerequisites, public integration contracts, security boundaries, delivered/proposed status, and cleanup behavior must retain an accurate English entry point.

## Releases

The component publishes independent connector versions. Aggregate Kuasar Sandbox releases select one exact connector version together with exact accelerator, sandboxer, orchestrator, Runtime, and VMLinux versions.

- [Component releases](https://github.com/kuasar-sandbox/connector/releases)
- [Aggregate releases](https://github.com/kuasar-sandbox/kuasar-sandbox/releases)

Use the aggregate release selection rather than combining similarly numbered component archives by assumption.

## Contributing

Read the project [English contribution guide](https://github.com/kuasar-sandbox/kuasar-sandbox/blob/main/CONTRIBUTING_EN.md). Keep data-path and protocol changes focused, document compatibility, preserve isolation invariants, and include owned-resource cleanup. Exported runtime or orchestrator integration changes may require linked companion pull requests and exact-source-set BMS validation.

## Security

Do not report vulnerabilities in public issues. Use the project [English Security Policy](https://github.com/kuasar-sandbox/kuasar-sandbox/blob/main/SECURITY_EN.md) and GitHub private vulnerability reporting.

Security-sensitive reports can include sandbox identity spoofing, cross-sandbox forwarding, policy-gateway bypass, unsafe management translation, verifier/data-path inconsistencies, host-network impact, or privileged-CI compromise. Remove internal topology, credentials, packet payloads, customer identifiers, and unredacted production captures from public material.

## License

Project-owned userspace code is licensed under the [Apache License 2.0](LICENSE). eBPF programs, Linux UAPI material, generated BPF skeletons/objects, libbpf/bpftool inputs, and other third-party files retain their applicable copyright and license obligations. Consult the repository's license-scope and release-notice documentation before redistribution.