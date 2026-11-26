[English](README.md) | [简体中文](README_zh.md)

# 原生 Egress 构建与验收

配置、资源归属、文件 reload 和恢复约定见 [Egress 运维](../docs/egress_zh.md)。本目录包含 Connector 插件和源码验收执行器；上游 VPP 构建与补丁采用 `native-deps` 工作流。`connector-ctl` 保持纯 Go 程序。

## 构建输入与输出

[`../native-deps/deps/vpp-source.json`](../native-deps/deps/vpp-source.json) 固定 FD.io VPP 26.10 源码归档及其 SHA256。获取阶段校验归档，解包到 `native-deps/build/src/vpp`，并创建 `vpp-patches-base` Git 基线；随后通过 `git am` 应用 [`../native-deps/deps/vpp-patches`](../native-deps/deps/vpp-patches) 中的编号补丁。补丁适配原生 NAT44-ED 的分配、计数、连接回收、路径 MTU、短 TCP 引用 ICMP 转换，以及原生重组状态的安全回收接口。NAT hash、端口、TCP 状态、计时器、校验和及分片继续由 VPP 负责；三个 Connector 插件分别负责 Area 策略、由流量创建的 Geneve 转发上下文和报文规范化。

两种架构分别原生构建。`TARGET_ARCH` 选择 `x86_64` 或 `aarch64`，也接受 `amd64`、`arm64` 别名；原生构建会核对目标与宿主架构。CPU 基线在 x86_64 上为 `x86-64-v2`，aarch64 上为 `armv8-a+crc`。源码、下载缓存与架构独立的对象目录 `native-deps/build/<arch>/vpp` 分开保留。`KUASAR_BUILD_JOBS` 控制并发度；编译器、C 库和原生依赖属于所选构建环境的一部分。

以下构建依赖示例以 Ubuntu 24.04 和 CMake/Ninja 为基础。编译器沿用上游 VPP 的选择规则：设置 `CC` 时使用指定编译器，否则优先选择 Clang，再回退到 GCC。

```bash
sudo apt-get update
sudo apt-get install --no-install-recommends \
  build-essential clang ninja-build cmake git python3 python3-ply pkg-config \
  libunwind-dev libmbedtls-dev libpcap-dev libssl-dev libnl-3-dev \
  libnl-route-3-dev libelf-dev liblz4-dev libzstd-dev libbpf-dev libyaml-dev \
  iproute2 ethtool
KUASAR_BUILD_JOBS=8 make build
```

Go 工具链遵循 [CONTRIBUTING](../CONTRIBUTING_zh.md)。默认 `make build` 构建两项组件，并直接写入同一个 `bin/<arch>` 目录：

| 路径 | 内容 |
|---|---|
| `connector-ctl` | Go 控制程序 |
| `vpp` | 原生转发程序 |
| `lib/<triplet>/` | 配套核心库，以及 `vpp_plugins/` 中启用的六个插件 |
| `vpp-runtime.json` | 源码输入、架构、CPU 基线、文件摘要和所需系统库 |

仅开发或交叉编译 Go 控制程序时使用 `make connector-ctl`；`make -C native-deps vpp` 单独构建原生运行时。原生许可证材料保留在 `native-deps/build/<arch>/vpp/licenses`，供打包流程使用。

组件发布包在 `bin/` 下保留相同运行目录结构，并携带既有 `deploy/` 和 `share/licenses/connector` 许可证目录。将组件归档一次解压至例如 `/opt/connector`，保留完整的 `bin/` 目录；网关示例使用 `/opt/connector/bin/vpp` 和 `/opt/connector/bin/lib/<triplet>`。运行环境提供该次构建生成的 `vpp-runtime.json` 中 `required_system_libraries` 列出的系统库。控制程序、VPP 与插件须来自同一组件版本。平台 CI 与 node-infra 直接使用这些文件。

### 维护上游补丁

各阶段与 Cloud Hypervisor、Guest kernel 工作流一致：

```bash
make -C native-deps vpp-fetch
make -C native-deps vpp-patches-apply
# 在 native-deps/build/src/vpp 中修改并提交。
make -C native-deps vpp-patches-format
make -C native-deps vpp-build
```

`vpp-patches` 是 `vpp-patches-apply` 的别名。普通 `vpp` 目标依次获取源码、应用补丁并构建。生成候选产物前，先将上游源码改动导出到编号补丁目录。项目插件仍作为 `egress/vpp/plugins` 中的正常源码维护，并使用 `egress/vpp/.clang-format` 格式化。`VPP_TARBALL`、`VPP_TARBALL_SHA256` 按其他原生依赖的下载约定支持已校验的源码镜像或本地归档。运行目录校验会核对记录的原生输入是否匹配选定 Connector 源码。

## 必需源码检查

```bash
make test-source-checks
```

源码 gate 包含 Egress/控制 CLI race 检查、全部真实 BPF 集成测试（含 Transit generation fencing），以及真实本地接线归属和清理测试。必需特权测试在能力缺失时失败，跳过不能算验收。归属测试覆盖同名外部设备拒绝、借用资源保留、首次部署失败清理，以及部分卸载完成后的重试。

修改 `bpf/switch_kern.c` 后，按仓库生成流程重新生成已跟踪的 x86 和 ARM64 对象。C/Go slot ABI 和 Attach 合同保持不变。原生插件源码使用 `vpp` 内的 `.clang-format` 格式化。

## 原生验收

在可丢弃的特权执行环境运行：内核支持 BPF，至少两个可用 CPU（主线程加一个 NAT worker；三个 CPU 可验证两个 worker），内存足以运行网关和 12288 上下文 / 196608 映射用例，并提供 Python 3、iproute2 和 ethtool。使用同一个 `bin/<arch>` 目录中相应架构的控制程序与原生运行时。不要针对生产接口名或生产网关运行此套件。每个用例创建唯一 namespace 和设备，并清理其自有拓扑。

```bash
sudo make test-egress
```

[`tests/run.sh`](tests/run.sh) 执行 16 个用例，仅在全部成功后写出 `acceptance.json`：

| 执行器 | 验证证据 |
|---|---|
| `e2e.py` | 真实沙箱 socket → TC/eBPF → Geneve → 原生 VPP/NAT → 外部 socket。覆盖三种 locator、IP/Ether、本地专用 pair 和远端路由 underlay，使用两个 worker。 |
| 本地生命周期检查 | 重复 prepare、稳定 owner 下两轮 Start/Stop、自动进入与空闲清理、文件 reload、重启读取配置、接口故障隔离、拒绝带活动沙箱修复、排空后修复并重新接入、保留 Pool 资源和安全卸载。 |
| 策略/出口检查 | 沙箱与 Pool 独立额度、ACL 默认允许与显式拒绝、LPM、DNAT 元组恢复、TCP/UDP、降低额度、更新失败保留策略、选择性撤销，以及一个出口失败时另一个继续工作。 |
| `wire.py --locator tlv` | 不同接入上的外层/内层身份重叠、错误 framing 和未知 critical option、opaque 元数据行为、乱序内层和外层重组、分片回程、NAT 前 PMTU、仅引用八个 TCP 字节的 ICMP、普通 IPv4 协议、不可变代次回程和自动计数清理。 |
| `wire.py --locator port` / `--locator tlv` | 完整报文字段 locator、具名 Pool 引用和重排稳定性、超过旧固定对象上限的配置、额度隔离及配置缩减回收。 |
| `wire.py --contexts 12288 --flows 16` | 流量在三个既有 4096-slot vSwitch 来源上自动创建 12288 个同时活跃上下文和 196608 条真实双向 NAT 连接。验证公网元组唯一性、文件 reload、按 Area 撤销及自动回收，记录内存和耗时。 |

另有 legacy 用例，在关闭 fencing 时运行 Ether。真实 BPF 套件分别对所有 locator 验证 generation 0、1、15、20 位最大值，拒绝带旧标记回包，并接收未标记 legacy 回包。raw wire 执行器验证网关容量和报文正确性，TC 执行器覆盖 vSwitch 边界。这些是功能与容量检查，不构成吞吐或时延 SLA。

定向迭代可直接调用 Python 执行器，指定 `--ctl`、`--runtime`（`bin/<arch>` 目录）和新的 `--output` 目录。`e2e.py` 支持 `--locator`、`--encap`、`--remote`、`--legacy` 和 `--workers`；`wire.py` 支持 `--locator vni|tlv`、`--contexts`、`--flows`。执行器保留命令、断言、网关日志、原生诊断和结果；套件先核验全部运行时文件 hash 与原生源码收据，再将控制程序 hash 与该清单关联，后者还记录原生源码、补丁和构建输入的 hash。运行目录校验拒绝构建完成后发生变化的输入。这些记录应与已审查源码及 CI 证据一起保存，不进入产品包。

正常受保护集成流程及当前 base/head 的合入要求仍遵循 [CONTRIBUTING](../CONTRIBUTING_zh.md)。原生验收是 gate 的补充证据，须明确对应候选版本，不能替代或伪造受保护状态。

制品验收入口为 `test/e2e/cases/network.egress.sh`；执行器位于 `test/e2e/lib/egress`。现有受保护集成流水线在两种架构运行完整原生矩阵和容量测试。
