[English](egress.md) | [简体中文](egress_zh.md)

# Geneve Egress 运维

Egress 是通过文件配置的 IPv4 Geneve 转发网关，提供有序 ACL、TCP/UDP DNAT、最长前缀 Pool 选择和原生 NAT44-ED。有效流量自动创建转发状态，原生协议空闲计时器释放 NAT 映射，再安全回收空闲上下文。Egress 没有沙箱登记、token、租约、续租或释放协议，也不暴露任何管理 API。

本地和远端部署使用相同 Area/Pool 配置及线协议。网关不提供 DNS/域名策略、应用代理、IPv6 转发或自动 Pool 故障切换。[提案 #117](https://github.com/kuasar-sandbox/connector/issues/117) 是设计基线。

## 部署和归属

按照[构建与验收](../egress/README_zh.md)构建相互匹配的原生运行时和纯 Go 控制程序。可执行文件、运行库与插件须配套。配置中的网关/SNAT 地址归 VPP 所有，Linux 不得在同一接口重复持有这些地址；无关 Linux IPv4 地址可以保留。AF_PACKET 的校验和及分段 offload 通过内核 API 关闭并核验。

本地部署参考 [link.json](../dist/egress/link.json)、[switch.json](../dist/egress/switch.json)、[gateway.json](../dist/egress/gateway.json) 和 [area7.json](../dist/egress/area7.json)。部署前替换示例地址和资源；ARM64 使用 `aarch64-linux-gnu` 库路径。

1. 运行 `connector-ctl egress link prepare --config link.json`。vSwitch 停止时，其接线端保留在稳定 owner namespace，网关端保留在 Egress namespace，并记录 namespace 与设备归属。
2. 由外部网络所有者将 uplink 放入网关 namespace，配置 MTU 并启用。SNAT 资源必须具有真实外部可达性；主机默认路由不隐式构成 Pool 出口。
3. 按既有 [vSwitch 运维](vswitch-operations_zh.md)准备 switch 和 port namespace，再运行 `connector-ctl egress validate --config gateway.json`。
4. 运行 `ip netns exec egress-local connector-ctl egress serve --config gateway.json`。也可安装 [connector-egress@.service](../dist/connector-egress@.service)，把主配置放在 `/etc/connector-egress/egress-local.json`，关联 Area 文件放在旁边，再启动 `connector-egress@egress-local.service`。
5. 运行 `connector-ctl egress link start --config link.json --switch-config switch.json --mode veth`。默认模式与既有 vSwitch 一样为 `tap`。包装流程从记录的稳定 owner namespace 启动 vSwitch。
6. 通过既有 vSwitch 接口 Attach 沙箱，并验证所需 Pool 的真实请求与回包。无需调用 Egress 登记接口。

重复 prepare 核验并复用自有 pair，拒绝外部同名设备、变化的 namespace 身份和已损坏的已安装 pair。每个本地 vSwitch 使用独立 pair，多个 pair 可以共用 Egress 实例。独立 underlay FIB 支持外层地址重叠。既有 vSwitch `transit_dev_mtu:auto` 可以将其端点 MTU 调低至网关预留 MTU 以下，这不改变 pair 归属。

远端部署使用外部拥有的 transit 设备，不使用本地 pair 管理器。`peer` 是 vSwitch 外层源地址，路由接入的 `next_hop` 是同链路路由器，默认等于 `peer`。沿用 vSwitch 的 transit 地址与 Geneve 网关配置。接收接口、本地 VTEP、peer 和 Area 选择配置的转发域。Geneve 和 generation MAC 不是密码学认证，underlay 资源归属必须防止发送方伪造。

## 文件与 reload

主配置采用严格 JSON。`areas` 可包含内联 Area 对象，`area_files` 列出每个包含一个 Area 对象的文件，其相对路径以主配置所在目录解析。两者组成一个完整校验集合。未知字段、重复 JSON 成员、重复 Area、无效引用、尾随值均被拒绝。

完成所有文件修改后触发 reload：

```bash
systemctl reload connector-egress@egress-local.service
# 直接管理进程时：
kill -HUP "$(cat /var/lib/connector-egress/egress-local/pid)"
```

每次 reload 重新读取主配置和全部关联 Area 文件，完成整份候选配置的校验及暂存，再在同一个 worker barrier 内发布全部 Area 和接入配置。解析、引用或准备失败时保留原配置。不再存在独立可写的在线策略存储。使用原子替换文件，并在整套文件准备完成后发送 SIGHUP。

reload 支持 Area 增删、ACL/DNAT/路由/Pool、接入配置及 peer 路由、上下文预算、空闲回收宽限和原生协议超时。删除 Area 时须同时删除其引用。当前实现中，运行程序/库路径、CPU/堆资源、物理接口/Exit 拓扑和 NAT 预分配容量需要重启；此类变更在发布前被拒绝，保留运行配置。原生发布应答不明确时停止网关，不报告未经证明的回滚。

普通路由、DNAT 和 SNAT 选择变化作用于新映射，既有映射保留原公网元组、目的转换及出口。降低 Pool 额度只限制新映射，不驱逐已有映射。ACL 撤销、Pool/Area 删除和原路径不可用只使相关映射失效。不兼容的接入线协议/网关变更回收相关上下文；回程标记不会借用其他代次的身份。

进程重启重新读取文件，不恢复 NAT 状态。后续有效流量自动建立新状态，无需控制方重新登记。

## 配置与资源

| 对象 | 含义 |
|---|---|
| Interface | Linux 设备名、VPP 拥有的 IPv4 `address` 前缀和物理 L3 `mtu`。 |
| Exit | 物理接口、同链路 `next_hop` 和可达 SNAT `addresses`。多个 Exit 可以共用接口；回包查找使用该物理接口的 FIB，各 Exit 保持独立路由 FIB。 |
| Attachment | transit 接口、peer、Area、locator、封装、既有 generation 位宽和内层网关。`inner_mtu` 默认 1500，可选 `mtu` 限定外层路径。 |
| Area | 逻辑 `vni`、有序 `acl`、有序 TCP/UDP `dnat`、最长前缀 `routes` 和 Pool。 |
| Pool | Area 内唯一 ID 0–63、Exit 及其地址子集。`max_connections` 限制每个转发上下文/Pool 的存活 NAT 映射，零取消业务额度，不取消物理资源限制。 |
| Match | 规范 IPv4 目的前缀和 `any`、`icmp`、`tcp` 或 `udp`；端口仅适用于 TCP/UDP。`any` 也覆盖其他普通 IPv4 协议。 |

ACL 对 DNAT 前的原始目的地址执行 first-match/default-deny。DNAT 命中直接选择其 Pool，否则使用最长前缀路由。无匹配路由、所选 Pool 耗尽或出口不可用时失败，不选择其他 Pool。没有端口的 IPv4 协议在远端地址/协议元组重叠时需要不同公网地址，因为无法用转换端口区分回包。

| 资源配置 | 默认值与含义 |
|---|---|
| `max_contexts` | 65536 个并发转发上下文，包括等待安全回收的对象；可配置更大值，不是 4096 或 10000 的网关硬上限。 |
| `max_connections` | **每个 worker** 默认 65536 条原生映射，最大可配置 1048576；与 Pool 业务额度独立。容量验收使用每 worker 262144。 |
| `heap_size` | 默认 `4G` 原生主堆预留，可使用正整数加 `M` 或 `G` 配置。实际驻留内存随负载变化。 |
| `stats_size` | 默认 `1G` 原生统计堆预留，可用 `M` 或 `G` 配置。即使禁用统计监听接口，每上下文的原生接口计数仍需要这部分内存。 |
| `context_idle_seconds` | 无存活映射后等待 1 秒，还须安全排空在途 graph/handoff/reassembly 引用。 |
| `timeouts.udp` | 连接空闲 300 秒。 |
| `timeouts.tcp_transitory` | 240 秒。 |
| `timeouts.tcp_established` | 7440 秒。 |
| `timeouts.icmp` | 60 秒。 |

`main_core` 和 `workers` 选择互不重复且可用的 CPU；不指定 worker 时使用原生单线程模式。Area、attachment、Exit、Pool、地址与规则使用动态存储，不再设置额外固定数量上限。Pool ID 是稀疏键，不作为数组长度；移除的状态自动回收。原生统计段没有监听接口，但预算必须包含每上下文接口计数。应一起配置地址、NAT 槽位、上下文、内存及 CPU；Pool 不限额不等于网关容量无限。

验收目标为跨多个 vSwitch 来源的 12288 个同时活跃上下文和 196608 条双向 NAT 映射，使用两个原生 worker。应查看具体候选版本的验收清单和内存实测，不据此推导吞吐或时延承诺。

## 线协议身份与 MTU

| Locator | 既有 vSwitch 合同 |
|---|---|
| `port` | 收到的目的 UDP 端口作为不透明 locator 原样用于回程。接受非零 UDP 目的端口字段的完整范围，不依赖发送方的 `port_base` 或 slot 分配。Area VNI 为 24 位。 |
| `vni` | UDP 6081，VNI 为 `(slot << 12) | area`，逻辑 Area 为 12 位。 |
| `tlv` | UDP 6081，配置的 class/type 标识第一个 locator option，Area 为 24 位。未知 critical option 拒绝，非 critical 元数据接收但不反射。 |

Egress 不限制 slot 范围，按报文字段保留 locator，包括完整 32-bit TLV 值。上下文按来源及 locator 建立索引，不按 slot 数值分配数组。`port_base` 作为兼容配置继续接受，但不限制接入范围。Ether 封装且 generation 位宽为 1–20 时，源 MAC `02:fe:<32-bit big-endian generation>` 携带既有 generation，零也是有效值。Egress 从流量学习回程标记及内层源地址，并在该上下文内保持不变。vSwitch 按既有 generation 校验带标记目的 MAC，恢复 Guest MAC，并保留未标记 legacy 兼容。没有 vSwitch Go 配置、Attach 参数或代次方案变化。

IP 封装和 legacy Ether 不增加新身份字段，既有协议无法区分身份复用后的任意迟到流量这一限制仍存在，不增加 Egress 租约协议掩盖它。

回程封装使用配置外层预算与内层 MTU 加封装开销中的较小值。内外层 IPv4 分片由原生重组；回包可以在隧道预算内分片，DF 错误及关联 ICMP 引用保持原上下文。真实路径和 vSwitch MTU 须协调；外层隧道不主动探测 PMTU。

## 诊断与恢复

私有运行目录包含 `pid`、`startup.conf`、`owner.lock` 及原子替换的 `status.json`。状态文件报告配置代次、reload 错误、上下文及 NAT 数量、Area/Pool 计数、原生报文错误、原生 PID 和接口/carrier 状态。它只是输出，不会作为配置恢复。服务不暴露 HTTP、Unix CLI、二进制 API、统计监听或命名共享内存 API 传输。管理进程通过匿名父子进程描述符对控制原生进程。

`egress link check --config link.json` 报告 pair 归属、位置和既有 vSwitch 状态。接口 UP 不是就绪证据，须验证每个所需 Pool 的真实双向流量。

丢失或替换一个物理接口只禁用该接口并等待受控修复，其他路径继续工作；同名新设备不会自动被接纳。本地修复时，停止受影响流量，通过正常 Detach 排空 vSwitch 已分配端口，在更换 Egress 端点前停止 Egress，运行 `egress link repair --config link.json --switch-config switch.json --mode veth`，重新启动 Egress 并验证流量。共享网关重启会丢失其 NAT 状态。修复包装流程拒绝活动端口，不强制删除沙箱。

普通 `link stop` 将 switch 端点归还稳定 owner 并保留 pair。显式卸载应在 Detach 和停止两端后运行 `egress link uninstall --config link.json`。仅删除自有资源，保留借用 namespace 和 Pool 接口。仍有进程或其他设备的 namespace 保留供重试。这些操作不向 Egress 发送沙箱级通知。

从先前实现升级时，删除主 JSON 的 `vppctl` 字段，停止使用 `egress request`、session grant 和 `policy.json`。重启前将需要的策略放入主配置或关联 Area 文件。

## 组件交付与 node-infra

同版本 Connector 发行包包含 `bin/connector-egress.bundle`、控制程序、`deploy/connector-egress@.service` 和 `deploy/egress` 示例。平台将原生运行时解压至 `/opt/node-infra/lib/connector-egress`；配置需选用对应架构的库和插件路径。

本地网关将主配置、Area 文件和 `link.json` 挂载到 `/etc/connector-egress`，参考平台 `node-infra/examples/local-egress`。现有节点准备流程管理共享链路；`owner_netns: ""` 表示节点流程保留的主网络命名空间，每次操作均核对其 inode。vSwitch 继续通过原有节点服务启停。Egress 仅运行转发进程，通过 SIGHUP reload，不接收沙箱生命周期通知。普通服务停止保留 pair；最终 owner 卸载在网关与 vSwitch 停止后清理 pair。借用的网关 namespace 和 Pool 接口由外部所有者保留。
