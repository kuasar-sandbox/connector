[English](README.md) | [简体中文](README_zh.md)

# Native Egress build and acceptance

Operator configuration, ownership, file reload and recovery are defined in [Egress operations](../docs/egress.md). This directory owns the native build and its source acceptance executors. `connector-ctl` remains a pure-Go binary; the native dataplane is built separately.

## Build inputs

[`vpp/source.json`](vpp/source.json) pins FD.io VPP 26.10 to commit `4acb320269bc4f3533e35c80afedac38853b2f60`. [`vpp/patches/native-policy.patch`](vpp/patches/native-policy.patch) adapts native NAT44-ED allocation, accounting, flow retirement, path MTU and short TCP-quoted ICMP translation. It also provides safe native reassembly retirement hooks. The native implementation continues to own NAT hashes, ports, TCP state, timers, checksums and packet fragmentation. The three Connector plugins own Area policy, traffic-created Geneve forwarding contexts and packet normalization.

The patch is applied only to the pinned commit. A build rejects unrelated tracked source changes. Rebuilding reuses its source and object directory and only copies changed plugin inputs. The native runtime targets `x86-64-v2` on x86_64 and `armv8-a+crc` on aarch64, matching the pinned VPP baseline; it does not use the build machine's unrestricted `-march=native` features. Build each architecture natively. The compiler, C library and native build dependencies are part of the selected build environment.

The acceptance environment is Linux with Ubuntu 24.04 userspace, GCC 13 and CMake/Ninja. Prepare its build dependencies:

```bash
sudo apt-get update
sudo apt-get install --no-install-recommends \
  build-essential ninja-build cmake git python3 python3-ply pkg-config \
  libunwind-dev libmbedtls-dev libpcap-dev libssl-dev libnl-3-dev \
  libnl-route-3-dev libelf-dev liblz4-dev libzstd-dev libbpf-dev libyaml-dev \
  iproute2 ethtool
make build
JOBS=8 make egress-runtime
```

Use the repository's supported Go toolchain from [CONTRIBUTING](../CONTRIBUTING.md). `EGRESS_BUILD_DIR` defaults to `build/egress`; `EGRESS_RUNTIME_DIR` defaults to its `runtime` child. Staging requires a new output directory, so choose another `EGRESS_RUNTIME_DIR` for a subsequent candidate. It copies the selected VPP executable, core libraries and six enabled plugins; verifies native ELF architecture; preserves licenses and embedded upstream notices; and records payload hashes and required system libraries in `runtime.json`. It does not copy sources, build caches or test history into the runtime.

`make connector-egress.bundle` creates `bin/<arch>/connector-egress.bundle` from the verified native build. The ordinary component release now includes this runtime, the matching `connector-ctl`, the Egress service template, and the main/Area/link configuration examples. Extract the native bundle into the directory selected by the gateway configuration (for example `/opt/connector-egress`), preserving `bin`, `lib/<triplet>`, and `share/licenses`. Supply the system libraries listed in `runtime.json` (glibc and libunwind on the validated Ubuntu build). Do not mix a control binary with a native runtime from another component version. The platform consumes the same bundle in its native CI and node-infra image.

## Required source checks

```bash
make test-source-checks
```

The source gate includes Egress/control CLI race checks, all real BPF integration tests (including Transit generation fencing), and real local-link ownership and cleanup tests. Required privileged tests fail when their capabilities are absent; skipped tests are not acceptance. The ownership suite verifies foreign same-name refusal, borrowed resources, failed first deployment cleanup and retry after partially completed uninstall.

After changing `bpf/switch_kern.c`, regenerate both tracked x86 and ARM64 objects using the repository generation workflow. The C/Go slot ABI and Attach contract remain unchanged. Format the native plugin sources with the `.clang-format` in `vpp`.

## Native acceptance

Run on a disposable, privileged executor with a BPF-capable kernel, at least two available CPUs (one main thread and one NAT worker; three CPUs exercise two workers), enough memory for the gateway and the 12288-context / 196608-mapping case, Python 3, iproute2 and ethtool. Use each architecture's native control binary and staged runtime. Do not run the suite against production interface names or a production gateway. Every case creates unique namespaces and links and cleans its owned topology.

```bash
sudo make test-egress \
  EGRESS_RUNTIME_DIR="$PWD/build/egress/runtime" \
  EGRESS_TEST_DIR="$PWD/build/egress/acceptance"
```

[`tests/run.sh`](tests/run.sh) executes 16 cases and writes `acceptance.json` only after every case succeeds:

| Executor | Evidence |
|---|---|
| `e2e.py` | Real sandbox sockets → TC/eBPF → Geneve → native VPP/NAT → external sockets. All three locators, IP/Ether, local dedicated pair and remote routed underlay; two worker threads. |
| Local lifecycle checks | Repeat prepare, stable-owner Start/Stop twice, automatic entry and idle cleanup, file reload, restart configuration restoration, isolated interface loss, refusal to repair active sandboxes, drained repair and reattachment, Pool resource preservation and safe uninstall. |
| Policy/exit checks | Independent sandbox and Pool quotas, ACL default deny, LPM, DNAT tuple restoration, TCP/UDP, quota lowering, failed update preservation, selective revocation, and one failed exit while another continues. |
| `wire.py --locator tlv` | Overlapping outer/inner identities on separate attachments, malformed framing and unknown critical options, opaque metadata behavior, out-of-order inner and outer reassembly, fragmented returns, pre-NAT PMTU, eight-byte TCP-quoted ICMP, ordinary IPv4 protocols, immutable generation returns and automatic accounting cleanup. |
| `wire.py --locator port` / `--locator tlv` | Full wire-field locator values, named Pool references and reorder stability, dynamic configuration beyond old object counts, quota isolation and policy shrink. |
| `wire.py --contexts 12288 --flows 16` | Traffic automatically creates 12288 simultaneously active contexts across three unchanged 4096-slot switch locators and 196608 actual bidirectional NAT connections. Checks distinct public tuples, file reload, selective Area revocation and automatic reclamation; records memory and elapsed time. |

The additional legacy case runs Ether with fencing disabled. The real BPF suite separately verifies generation 0, 1, 15 and the 20-bit maximum, rejection of tagged old returns, and acceptance of untagged legacy returns for every locator. The raw wire executor tests gateway capacity and packet correctness; the TC executor covers the vSwitch boundary. These are functional and capacity checks, not a throughput or latency SLA.

For focused iteration, invoke a Python executor with `--ctl`, `--vpp-build` (the staged runtime) and a fresh `--output` directory. `e2e.py` accepts `--locator`, `--encap`, `--remote`, `--legacy` and `--workers`. `wire.py` accepts `--locator vni|tlv`, `--contexts` and `--flows`. The executors retain commands, assertions, gateway logs, native diagnostics and results. The suite verifies every runtime payload hash; the source-tree entry also verifies the current native source receipt, then binds the control binary hash to that manifest, which also records native source/patch/build-input hashes. Staging rejects inputs changed since the completed build. Keep these records with the reviewed source and CI evidence, outside product packages.

The normal protected integration flow and current-base/current-head merge requirements remain those of [CONTRIBUTING](../CONTRIBUTING.md). Native acceptance evidence supplements that gate and must identify the exact candidate; it does not replace or manufacture the protected status.

The prepared artifact case is `test/e2e/cases/network.egress.sh`; its Python and shell executors live under `test/e2e/lib/egress`. It runs the full native matrix and capacity test on both architectures through the existing protected integration pipeline.
