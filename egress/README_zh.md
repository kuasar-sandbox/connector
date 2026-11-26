[English](README.md) | [简体中文](README_zh.md)

# 原生 Egress 构建与验收

配置、资源归属、文件 reload和恢复合同见 [Egress 运维](../docs/egress_zh.md)。本目录负责原生构建与源码验收执行器。`connector-ctl` 保持纯 Go，原生数据面单独构建。

## 构建输入

[`vpp/source.json`](vpp/source.json) 将 FD.io VPP 26.10 固定到 commit `4acb320269bc4f3533e35c80afedac38853b2f60`。[`vpp/patches/native-policy.patch`](vpp/patches/native-policy.patch) 为原生 NAT44-ED 的分配、计数、连接回收、路径 MTU 和短 TCP 引用 ICMP 转换提供适配，并加入原生重组状态的安全回收接口。NAT hash、端口、TCP 状态、计时器、校验和及分片继续由原生实现负责。三个 Connector 插件分别负责 Area 策略、由流量创建的 Geneve 转发上下文和报文规范化。

补丁只应用于固定 commit，构建会拒绝无关的已跟踪源码修改。重复构建复用源码及对象目录，只复制变化的插件输入。x86_64 运行时使用 `x86-64-v2`，aarch64 使用 `armv8-a+crc`，与固定版本 VPP 的基线一致，不使用构建机无限制的 `-march=native` 特性。两种架构分别原生构建；编译器、C 库和原生依赖属于所选构建环境的一部分。

验收环境为 Linux 内核、Ubuntu 24.04 用户态、GCC 13 与 CMake/Ninja。准备构建依赖：

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

Go 工具链遵循 [CONTRIBUTING](../CONTRIBUTING_zh.md)。`EGRESS_BUILD_DIR` 默认是 `build/egress`，`EGRESS_RUNTIME_DIR` 默认是其 `runtime` 子目录。暂存要求使用新输出目录，后续候选版本应选择新的 `EGRESS_RUNTIME_DIR`。暂存流程复制选定 VPP 可执行文件、核心运行库和六个启用插件，验证原生 ELF 架构，保留许可证与上游内嵌声明，并在 `runtime.json` 中记录载荷 hash 及所需系统库；不将源码、构建缓存或测试历史装入运行时。

`make connector-egress.bundle` 从已校验的原生构建生成 `bin/<arch>/connector-egress.bundle`。常规组件发行包包含该运行时、同版本 `connector-ctl`、Egress 服务模板，以及主配置、Area 和接线示例。将 bundle 解压至网关配置指定目录（例如 `/opt/connector-egress`），保留 `bin`、`lib/<triplet>` 和许可证目录；提供 `runtime.json` 列出的系统库。不要混用不同组件版本的控制程序和原生运行时。平台原生 CI 与 node-infra 镜像使用同一 bundle。

## 必需源码检查

```bash
make test-source-checks
```

源码 gate 包含 Egress/控制 CLI race 检查、全部真实 BPF 集成测试（含 Transit generation fencing），以及真实本地接线归属和清理测试。必需特权测试在能力缺失时失败，跳过不能算验收。归属测试覆盖同名外部设备拒绝、借用资源保留、首次部署失败清理，以及部分卸载完成后的重试。

修改 `bpf/switch_kern.c` 后，按仓库生成流程重新生成已跟踪的 x86 和 ARM64 对象。C/Go slot ABI 和 Attach 合同保持不变。原生插件源码使用 `vpp` 内的 `.clang-format` 格式化。

## 原生验收

在可丢弃的特权执行环境运行：内核支持 BPF，至少两个可用 CPU（主线程加一个 NAT worker；三个 CPU 可验证两个 worker），内存足以运行网关和 12288 上下文 / 196608 映射用例，并提供 Python 3、iproute2 和 ethtool。使用相应架构的原生控制程序与暂存运行时。不要针对生产接口名或生产网关运行此套件。每个用例创建唯一 namespace 和设备，并清理其自有拓扑。

```bash
sudo make test-egress \
  EGRESS_RUNTIME_DIR="$PWD/build/egress/runtime" \
  EGRESS_TEST_DIR="$PWD/build/egress/acceptance"
```

[`tests/run.sh`](tests/run.sh) 执行 15 个用例，仅在全部成功后写出 `acceptance.json`：

| 执行器 | 验证证据 |
|---|---|
| `e2e.py` | 真实沙箱 socket → TC/eBPF → Geneve → 原生 VPP/NAT → 外部 socket。覆盖三种 locator、IP/Ether、本地专用 pair 和远端路由 underlay，使用两个 worker。 |
| 本地生命周期检查 | 重复 prepare、稳定 owner 下两轮 Start/Stop、自动进入与空闲清理、文件 reload、重启读取配置、接口故障隔离、拒绝带活动沙箱修复、排空后修复并重新接入、保留 Pool 资源和安全卸载。 |
| 策略/出口检查 | 沙箱与 Pool 独立额度、ACL 默认拒绝、LPM、DNAT 元组恢复、TCP/UDP、降低额度、更新失败保留策略、选择性撤销，以及一个出口失败时另一个继续工作。 |
| `wire.py --locator tlv` | 不同接入上的外层/内层身份重叠、错误 framing 和未知 critical option、opaque 元数据行为、乱序内层和外层重组、分片回程、NAT 前 PMTU、仅引用八个 TCP 字节的 ICMP、普通 IPv4 协议、不可变代次回程和自动计数清理。 |
| `wire.py --contexts 12288 --flows 16` | 流量在三个既有 4096-slot vSwitch 来源上自动创建 12288 个同时活跃上下文和 196608 条真实双向 NAT 连接。验证公网元组唯一性、文件 reload、按 Area 撤销及自动回收，记录内存和耗时。 |

另有 legacy 用例，在关闭 fencing 时运行 Ether。真实 BPF 套件分别对所有 locator 验证 generation 0、1、15、20 位最大值，拒绝带旧标记回包，并接收未标记 legacy 回包。raw wire 执行器验证网关容量和报文正确性，TC 执行器覆盖 vSwitch 边界。这些是功能与容量检查，不构成吞吐或时延 SLA。

定向迭代可直接调用 Python 执行器，指定 `--ctl`、`--vpp-build`（暂存运行时）和新的 `--output` 目录。`e2e.py` 支持 `--locator`、`--encap`、`--remote`、`--legacy` 和 `--workers`；`wire.py` 支持 `--locator vni|tlv`、`--contexts`、`--flows`。执行器保留命令、断言、网关日志、原生诊断和结果；套件先核验全部运行时文件 hash 与原生源码收据，再将控制程序 hash 与该清单关联，后者还记录原生源码、补丁和构建输入的 hash。暂存拒绝构建完成后发生变化的输入。这些记录应与已审查源码及 CI 证据一起保存，不进入产品包。

正常受保护集成流程及当前 base/head 的合入要求仍遵循 [CONTRIBUTING](../CONTRIBUTING_zh.md)。原生验收是 gate 的补充证据，须明确对应候选版本，不能替代或伪造受保护状态。

制品验收入口为 `test/e2e/cases/network.egress.sh`；执行器位于 `test/e2e/lib/egress`。现有受保护集成流水线在两种架构运行完整原生矩阵和容量测试。
