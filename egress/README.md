[English](README.md) | [简体中文](README_zh.md)

# Native Egress build and acceptance

Operator configuration, ownership, file reload and recovery are defined in [Egress operations](../docs/egress.md). This directory contains the Connector plugins and source acceptance executors. The upstream VPP build and patches follow the repository's `native-deps` workflow. `connector-ctl` remains a pure-Go binary.

## Build inputs and outputs

[`../native-deps/deps/vpp-source.json`](../native-deps/deps/vpp-source.json) pins the FD.io VPP 26.10 source archive and its SHA256. Source acquisition verifies the archive, extracts it into `native-deps/build/src/vpp`, and creates the `vpp-patches-base` Git baseline. The numbered patches in [`../native-deps/deps/vpp-patches`](../native-deps/deps/vpp-patches) are applied with `git am`. They adapt native NAT44-ED allocation, accounting, flow retirement, path MTU and short TCP-quoted ICMP translation, and provide safe native reassembly retirement hooks. Native VPP continues to own NAT hashes, ports, TCP state, timers, checksums and packet fragmentation. The three Connector plugins own Area policy, traffic-created Geneve forwarding contexts and packet normalization.

Build each architecture natively. `TARGET_ARCH` selects `x86_64` or `aarch64` (also accepting `amd64` and `arm64`); the native build checks it against the build host. The CPU baseline is `x86-64-v2` on x86_64 and `armv8-a+crc` on aarch64. Source and downloads are retained separately from the architecture-specific object directory, `native-deps/build/<arch>/vpp`. `KUASAR_BUILD_JOBS` controls build parallelism. The compiler, C library and native dependencies belong to the selected build environment.

The acceptance environment is Linux with Ubuntu 24.04 userspace, GCC 13 and CMake/Ninja. Prepare its build dependencies:

```bash
sudo apt-get update
sudo apt-get install --no-install-recommends \
  build-essential ninja-build cmake git python3 python3-ply pkg-config \
  libunwind-dev libmbedtls-dev libpcap-dev libssl-dev libnl-3-dev \
  libnl-route-3-dev libelf-dev liblz4-dev libzstd-dev libbpf-dev libyaml-dev \
  iproute2 ethtool
KUASAR_BUILD_JOBS=8 make build
```

Use the supported Go toolchain from [CONTRIBUTING](../CONTRIBUTING.md). The default `make build` builds both components directly into the same `bin/<arch>` directory:

| Path | Contents |
|---|---|
| `connector-ctl` | Go control program |
| `vpp` | Native forwarding executable |
| `lib/<triplet>/` | Matching core libraries and the six enabled plugins under `vpp_plugins/` |
| `vpp-runtime.json` | Source inputs, architecture, CPU baseline, file hashes and required system libraries |

For control-only Go development or cross-compilation, use `make connector-ctl`; `make -C native-deps vpp` builds only the native runtime. Native license materials are retained in `native-deps/build/<arch>/vpp/licenses` for packaging.

The component release keeps the same runtime layout under `bin/`, alongside the normal `deploy/` and `share/licenses/connector` directories. Extract the component archive once, for example into `/opt/connector`, and retain the entire `bin/` directory. The gateway example then uses `/opt/connector/bin/vpp` and `/opt/connector/bin/lib/<triplet>`. Supply the system libraries listed in `vpp-runtime.json` (glibc and libunwind on the validated Ubuntu build). The control program, VPP and plugins must come from the same component version. Platform CI and node-infra consume these files directly.

### Maintain the upstream patches

The stages match the Cloud Hypervisor and Guest kernel workflows:

```bash
make -C native-deps vpp-fetch
make -C native-deps vpp-patches-apply
# Edit and commit changes in native-deps/build/src/vpp.
make -C native-deps vpp-patches-format
make -C native-deps vpp-build
```

`vpp-patches` is an alias for `vpp-patches-apply`. The ordinary `vpp` target performs source acquisition, patch application and build. Export upstream changes to the numbered patch directory before producing a candidate. Project plugins remain normal sources in `egress/vpp/plugins`; format them using `egress/vpp/.clang-format`. `VPP_TARBALL` and `VPP_TARBALL_SHA256` support a verified source mirror or local archive using the same download conventions as other native dependencies. Runtime validation checks that its recorded native inputs match the selected Connector source.

## Required source checks

```bash
make test-source-checks
```

The source gate includes Egress/control CLI race checks, all real BPF integration tests (including Transit generation fencing), and real local-link ownership and cleanup tests. Required privileged tests fail when their capabilities are absent; skipped tests are not acceptance. The ownership suite verifies foreign same-name refusal, borrowed resources, failed first deployment cleanup and retry after partially completed uninstall.

After changing `bpf/switch_kern.c`, regenerate both tracked x86 and ARM64 objects using the repository generation workflow. The C/Go slot ABI and Attach contract remain unchanged. Format the native plugin sources with the `.clang-format` in `vpp`.

## Native acceptance

Run on a disposable, privileged executor with a BPF-capable kernel, at least two available CPUs (one main thread and one NAT worker; three CPUs exercise two workers), enough memory for the gateway and the 12288-context / 196608-mapping case, Python 3, iproute2 and ethtool. Use each architecture's control binary and native runtime from the same `bin/<arch>` directory. Do not run the suite against production interface names or a production gateway. Every case creates unique namespaces and links and cleans its owned topology.

```bash
sudo make test-egress
```

[`tests/run.sh`](tests/run.sh) executes 16 cases and writes `acceptance.json` only after every case succeeds:

| Executor | Evidence |
|---|---|
| `e2e.py` | Real sandbox sockets → TC/eBPF → Geneve → native VPP/NAT → external sockets. All three locators, IP/Ether, local dedicated pair and remote routed underlay; two worker threads. |
| Local lifecycle checks | Repeat prepare, stable-owner Start/Stop twice, automatic entry and idle cleanup, file reload, restart configuration restoration, isolated interface loss, refusal to repair active sandboxes, drained repair and reattachment, Pool resource preservation and safe uninstall. |
| Policy/exit checks | Independent sandbox and Pool quotas, ACL default allow and explicit deny, LPM, DNAT tuple restoration, TCP/UDP, quota lowering, failed update preservation, selective revocation, and one failed exit while another continues. |
| `wire.py --locator tlv` | Overlapping outer/inner identities on separate attachments, malformed framing and unknown critical options, opaque metadata behavior, out-of-order inner and outer reassembly, fragmented returns, pre-NAT PMTU, eight-byte TCP-quoted ICMP, ordinary IPv4 protocols, immutable generation returns and automatic accounting cleanup. |
| `wire.py --locator port` / `--locator tlv` | Full wire-field locator values, named Pool references and reorder stability, dynamic configuration beyond old object counts, quota isolation and policy shrink. |
| `wire.py --contexts 12288 --flows 16` | Traffic automatically creates 12288 simultaneously active contexts across three unchanged 4096-slot switch locators and 196608 actual bidirectional NAT connections. Checks distinct public tuples, file reload, selective Area revocation and automatic reclamation; records memory and elapsed time. |

The additional legacy case runs Ether with fencing disabled. The real BPF suite separately verifies generation 0, 1, 15 and the 20-bit maximum, rejection of tagged old returns, and acceptance of untagged legacy returns for every locator. The raw wire executor tests gateway capacity and packet correctness; the TC executor covers the vSwitch boundary. These are functional and capacity checks, not a throughput or latency SLA.

For focused iteration, invoke a Python executor with `--ctl`, `--runtime` (the `bin/<arch>` directory) and a fresh `--output` directory. `e2e.py` accepts `--locator`, `--encap`, `--remote`, `--legacy` and `--workers`. `wire.py` accepts `--locator vni|tlv`, `--contexts` and `--flows`. The executors retain commands, assertions, gateway logs, native diagnostics and results. The suite verifies every runtime payload hash; the source-tree entry also verifies the current native source receipt, then binds the control binary hash to that manifest, which also records native source/patch/build-input hashes. Runtime validation rejects inputs changed since the completed build. Keep these records with the reviewed source and CI evidence, outside product packages.

The normal protected integration flow and current-base/current-head merge requirements remain those of [CONTRIBUTING](../CONTRIBUTING.md). Native acceptance evidence supplements that gate and must identify the exact candidate; it does not replace or manufacture the protected status.

The prepared artifact case is `test/e2e/cases/network.egress.sh`; its Python and shell executors live under `test/e2e/lib/egress`. It runs the full native matrix and capacity test on both architectures through the existing protected integration pipeline.
