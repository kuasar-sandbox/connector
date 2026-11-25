[English](README.md) | [简体中文](README_zh.md)

# Native Egress build and acceptance

Operator configuration, ownership, session authorization and recovery are defined in [Egress operations](../docs/egress.md). This directory owns the native build and its source acceptance executors. `connector-ctl` remains a pure-Go binary; the native dataplane is built separately.

## Build inputs

[`vpp/source.json`](vpp/source.json) pins FD.io VPP 26.10 to commit `4acb320269bc4f3533e35c80afedac38853b2f60`. [`vpp/patches/native-policy.patch`](vpp/patches/native-policy.patch) adapts native NAT44-ED allocation, accounting, flow retirement, path MTU and short TCP-quoted ICMP translation. It also provides safe native reassembly retirement hooks. The native implementation continues to own NAT hashes, ports, TCP state, timers, checksums and packet fragmentation. The three Connector plugins own Area policy, authorized Geneve attachments and packet normalization.

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

Use the repository's supported Go toolchain from [CONTRIBUTING](../CONTRIBUTING.md). `EGRESS_BUILD_DIR` defaults to `build/egress`; `EGRESS_RUNTIME_DIR` defaults to its `runtime` child. Staging requires a new output directory, so choose another `EGRESS_RUNTIME_DIR` for a subsequent candidate. It copies the selected VPP executables, core libraries and six enabled plugins; verifies native ELF architecture; preserves licenses and embedded upstream notices; and records payload hashes and required system libraries in `runtime.json`. It does not copy sources, build caches or test history into the runtime.

Copy the staged runtime to the directory selected by the gateway configuration, for example `/opt/connector-egress`, and install the separately built `connector-ctl`. Preserve the `bin`, `lib/<triplet>` and `share/licenses` layout. Provide the system libraries listed by `runtime.json`; an Ubuntu 24.04 build requires compatible glibc and libunwind/lzma libraries. A build made with a different userspace must be validated on its intended deployment userspace. The ordinary Connector component packaging still owns the pure-Go control binary; this target supplies the separately selected native gateway runtime without changing the component's existing archive contract.

## Required source checks

```bash
make test-source-checks
```

The source gate includes Egress/control CLI race checks, all real BPF integration tests (including Transit generation fencing), and real local-link ownership and cleanup tests. Required privileged tests fail when their capabilities are absent; skipped tests are not acceptance. The ownership suite verifies foreign same-name refusal, borrowed resources, failed first deployment cleanup and retry after partially completed uninstall.

After changing `bpf/switch_kern.c`, regenerate both tracked x86 and ARM64 objects using the repository generation workflow. The C/Go slot ABI and Attach contract remain unchanged. Format the native plugin sources with the `.clang-format` in `vpp`.

## Native acceptance

Run on a disposable, privileged executor with a BPF-capable kernel, at least three available CPUs, enough memory for the gateway and the 4096-session case, Python 3, iproute2 and ethtool. Use each architecture's native control binary and staged runtime. Do not run the suite against production interface names or a production gateway. Every case creates unique namespaces and links and cleans its owned topology.

```bash
sudo make test-egress \
  EGRESS_RUNTIME_DIR="$PWD/build/egress/runtime" \
  EGRESS_TEST_DIR="$PWD/build/egress/acceptance"
```

[`tests/run.sh`](tests/run.sh) executes 15 cases and writes `acceptance.json` only after every case succeeds:

| Executor | Evidence |
|---|---|
| `e2e.py` | Real sandbox sockets → TC/eBPF → Geneve → native VPP/NAT → external sockets. All three locators, IP/Ether, local dedicated pair and remote routed underlay; two worker threads. |
| Local lifecycle checks | Repeat prepare, stable-owner Start/Stop twice, unauthorized data, token/lease expiry, restart policy restoration, interface loss, refusal to repair active sandboxes, drained repair and reattachment, Pool resource preservation and safe uninstall. |
| Policy/exit checks | Independent sandbox and Pool quotas, ACL default deny, LPM, DNAT tuple restoration, TCP/UDP, quota lowering, failed update preservation, selective revocation, and one failed exit while another continues. |
| `wire.py --locator tlv` | Overlapping outer/inner identities on separate attachments, malformed framing and unknown critical options, opaque metadata behavior, out-of-order inner reassembly, fragmented returns, pre-NAT PMTU, eight-byte TCP-quoted ICMP, generation reuse and accounting cleanup. |
| `wire.py --contexts 4096 --flows 16` | Public API registration, 4096 simultaneously resident attachments and 65536 actual bidirectional NAT connections, distinct public tuples, resident-capacity rejection, live policy replacement, selective Area retirement and balanced reclamation. |

The additional legacy case runs Ether with fencing disabled. The real BPF suite separately verifies generation 0, 1, 15 and the 20-bit maximum, rejection of tagged old returns, and acceptance of untagged legacy returns for every locator. The raw wire executor tests gateway capacity and packet correctness; the TC executor covers the vSwitch boundary. These are functional and capacity checks, not a throughput or latency SLA.

For focused iteration, invoke a Python executor with `--ctl`, `--vpp-build` (the staged runtime) and a fresh `--output` directory. `e2e.py` accepts `--locator`, `--encap`, `--remote`, `--legacy` and `--workers`. `wire.py` accepts `--locator vni|tlv`, `--contexts` and `--flows`. The executors retain commands, assertions, gateway logs, native diagnostics and results. The suite manifest binds the control binary hash to the staged runtime manifest, which also records native source/patch/build-input hashes. Staging rejects inputs changed since the completed build. Keep these records with the reviewed source and CI evidence, outside product packages.

The normal protected integration flow and current-base/current-head merge requirements remain those of [CONTRIBUTING](../CONTRIBUTING.md). Native acceptance evidence supplements that gate and must identify the exact candidate; it does not replace or manufacture the protected status.
