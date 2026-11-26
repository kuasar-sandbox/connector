[English](egress.md) | [简体中文](egress_zh.md)

# Geneve Egress 运维

Egress 是通过文件配置的 IPv4 Geneve 转发网关，提供有序 ACL、TCP/UDP DNAT、最长前缀 Pool 选择和原生 NAT44-ED。有效流量自动创建转发状态，原生协议空闲计时器释放 NAT 映射，再安全回收空闲上下文。Egress 没有沙箱登记、token、租约、续租或释放协议，也不暴露任何管理 API。

本地和远端部署使用相同 Area/Pool 配置及线协议。网关不提供 DNS/域名策略、应用代理、IPv6 转发或自动 Pool 故障切换。[提案 #117](https://github.com/kuasar-sandbox/connector/issues/117) 是设计基线。

## 部署和归属

按照[构建与验收](../egress/README_zh.md)构建相互匹配的全静态 `connector-vpp` 数据面和纯 Go `connector-ctl`，安装同一组件版本的两个可执行文件。配置中的网关/SNAT 地址归 VPP 所有，Linux 不得在同一接口重复持有这些地址；无关 Linux IPv4 地址可以保留。数据面在转发前处理 AF_PACKET 携带的校验和和 TCP 分段元数据，不要求修改借用设备或外部对端的 offload 设置；本地专用 veth 仍按既有 vSwitch 报文契约准备。

本地部署参考 [link.json](../dist/egress/link.json)、[switch.json](../dist/egress/switch.json)、[gateway.yaml](../dist/egress/gateway.yaml) 和 [area7.yaml](../dist/egress/area7.yaml)。将选定组件归档解压至 `/opt/connector`，保留完整的 `bin/` 目录；服务模板和网关示例采用此前缀。以下命令使用 `/opt/connector/bin/connector-ctl`，也可先将该目录加入 `PATH`。`vpp` 是可选的绝对路径覆盖项；省略时，`connector-ctl` 在自身可执行文件所在目录定位 `connector-vpp`，先解析控制程序的符号链接，查找不受工作目录或 `PATH` 影响。部署前替换示例地址和资源。

1. 运行 `connector-ctl egress link prepare --config link.json`。vSwitch 停止时，其接线端保留在稳定 owner namespace，网关端保留在 Egress namespace，并记录 namespace 与设备归属。
2. 由外部网络所有者将 uplink 放入网关 namespace，配置 MTU 并启用。SNAT 资源必须具有真实外部可达性；主机默认路由不隐式构成 Pool 出口。
3. 按既有 [vSwitch 运维](vswitch-operations_zh.md)准备 switch 和 port namespace，再运行 `connector-ctl egress validate --config gateway.yaml`。
4. 运行 `ip netns exec egress-local connector-ctl egress serve --config gateway.yaml`。也可安装 [connector-egress@.service](../dist/connector-egress@.service)，把主配置放在 `/etc/connector-egress/egress-local.yaml`，关联 Area 文件放在旁边，再启动 `connector-egress@egress-local.service`。
5. 运行 `connector-ctl egress link start --config link.json --switch-config switch.json --mode veth`。默认模式与既有 vSwitch 一样为 `tap`。包装流程从记录的稳定 owner namespace 启动 vSwitch。
6. 通过既有 vSwitch 接口 Attach 沙箱，并验证所需 Pool 的真实请求与回包。无需调用 Egress 登记接口。

重复 prepare 核验并复用自有 pair，拒绝外部同名设备、变化的 namespace 身份和已损坏的已安装 pair。每个本地 vSwitch 使用独立 pair，多个 pair 可以共用 Egress 实例。不同 gatewayIP 使用不同的接收地址；相同 peer、locator 和内层地址可以分别接入这些 gatewayIP，而不串用状态。既有 vSwitch `transit_dev_mtu:auto` 可以将其端点 MTU 调低至网关预留 MTU 以下，这不改变 pair 归属。

远端部署使用外部拥有的 transit 设备。`peer` 为可选的 IPv4 地址/CIDR 列表，例如 `["198.18.0.2", "203.0.113.0/24"]`；省略或空列表不额外限制来源，实际 peer 从外层源 IP 获取。`next_hop` 省略时对实际 peer 按直连回程处理，路由接入应指定同链路路由器。报文 VNI 直接选择已配置 Area，不按 attachment 重复登记 Area。同一入口和外层网关地址的来源范围重叠时，解码、MTU 和回程约定必须一致，否则整批拒绝。同一网关/来源范围不能指向不同回程设备；不同 peer 范围可以跨设备复用网关地址。远端 transit 与 Pool 可以共用接口，但 Geneve 网关地址必须与 SNAT 地址分离；本地专用 veth 保持独立。Geneve 和 generation MAC 不是密码学认证，underlay 资源归属必须防止发送方伪造。

## 文件与 reload

主配置和 Area 文件采用 YAML，同时接受其 JSON 子集。`areas` 可包含内联 Area 对象，`area_files` 列出每个包含一个 Area 对象的文件，其相对路径以主配置所在目录解析。两者组成一个完整校验集合。未知字段、重复成员、重复 Area、无效引用、尾随值均被拒绝。

完成所有文件修改后触发 reload：

```bash
systemctl reload connector-egress@egress-local.service
# 直接管理进程时：
kill -HUP "$(cat /var/lib/connector-egress/egress-local/pid)"
```

每次 reload 重新读取主配置和全部关联 Area 文件，完成整份候选配置的校验及暂存，再在同一个 worker barrier 内发布全部 Area 和接入配置。解析、引用或准备失败时保留原配置。不再存在独立可写的在线策略存储。使用原子替换文件，并在整套文件准备完成后发送 SIGHUP。

reload 支持 Area 增删、ACL/DNAT/路由/Pool、接入来源及 peer 回程、空闲回收和协议超时。在已接入设备范围内，Pool 的 `interface`、`next_hop` 和 `addresses` 也支持 reload；旧连接继续引用原出口资源直到回收，新连接采用新定义。新增入口地址若与旧连接仍在使用的 SNAT 地址重叠，整批 reload 拒绝；待旧映射回收后可重试。删除 Area 时同步更新 Area 文件清单。程序/库路径、CPU/预分配内存、物理设备接管和 namespace 变化需要维护重启；此类变更在发布前被拒绝，保留运行配置。原生发布应答不明确时停止网关，不报告未经证明的回滚。

普通路由、DNAT 和 SNAT 选择变化作用于新映射，既有映射保留原公网元组、目的转换及出口。降低 Pool 额度只限制新映射，不驱逐已有映射。ACL 撤销、Pool/Area 删除和原路径不可用只使相关映射失效。不兼容的接入线协议/网关变更回收相关上下文；回程标记不会借用其他代次的身份。

进程重启重新读取文件，不恢复 NAT 状态。后续有效流量自动建立新状态，无需控制方重新登记。

## 配置与资源

| 对象 | 含义 |
|---|---|
| Interface | Linux 设备名、VPP 拥有的 IPv4 `address` 前缀和物理 L3 `mtu`。 |
| Attachment | `name`、`interface`、可选 `peer` 来源列表、可选回程 `next_hop`、`locator` 及 TLV 解码字段。`locator` 默认 `port`；`inner_mtu` 默认 1500，`mtu` 默认采用接口 MTU。Ether/IP 和 fencing 从报文识别。 |
| Area | 逻辑 `vni`、有序 `acl`、有序 TCP/UDP `dnat`、最长前缀 `routes` 和 Pool。 |
| Pool | Area 内唯一的 `name`，直接定义 `interface`、同链路 `next_hop` 和 SNAT `addresses`；路由与 DNAT 按名称引用。`max_connections` 限制每个外层接入在该 Pool 的存活 NAT 映射，零或省略取消业务额度。 |
| Match | 目的 IP/CIDR/范围、协议和端口集合，写法见下文；端口仅适用于 TCP/UDP。`any` 也覆盖其他普通 IPv4 协议。 |

ACL 对 DNAT 前的原始目的地址执行 first-match/default-allow。DNAT 命中直接选择其 Pool，否则使用最长前缀路由。单 Pool 省略 `routes` 时作为默认出口；显式 `routes: []` 关闭普通路由，但 DNAT 仍可使用 Pool。多 Pool 必须显式配置 routes；没有 Pool 的 Area 没有出口。`routes: null` 无效。无匹配路由、所选 Pool 耗尽或出口不可用时失败，不选择其他 Pool。没有端口的 IPv4 协议在远端地址/协议元组重叠时需要不同公网地址，因为无法用转换端口区分回包。

地址字段统一使用 Pool 的 `addresses`、规则的 `destination` 和接入的 `peer`，都接受单值或列表：`192.0.2.10`、`192.0.2.0/28`、`192.0.2.10-192.0.2.30`。范围包含首尾地址。Pool CIDR 表示完整单播地址集合，不自动扣除子网首尾地址；部署方须拥有并提供所选地址的回程。重复、重叠集合自动规范化。路由显式 CIDR 的前缀长度保留，用于最长前缀匹配；相同 Pool 的重复路由去重，相同前缀指向不同 Pool 则报错。

`ports` 支持 `443`、`"8000-8100"` 或 `[80, 443, "8000-8100"]`，范围闭合且必须在 1..65535 内。`protocol` 接受 `any`、`icmp`、`tcp`、`udp` 的单值或列表。省略 destination 表示任意地址；省略 protocol 默认 any，有 ports 约束或 DNAT 时默认为 TCP/UDP；省略 ports 表示任意端口。端口约束只适用于 TCP/UDP。空匹配列表和 null 报错，表达任意值应省略字段。ACL 可只写 action；省略或空 ACL 均允许未命中流量，白名单需要显式末尾 `action: deny`。不接受 `cidrs`、`protocols`、`port_first`、`port_last` 别名。

```yaml
acl:
  - destination: [203.0.113.0/24, 198.51.100.10-198.51.100.20]
    protocol: [tcp, udp]
    ports: [443, "8000-8100"]
    action: allow
  - action: deny
```

| 资源配置 | 默认值与含义 |
|---|---|
| `heap_size` | 默认 `4G` 原生主堆预留，可使用正整数加 `M` 或 `G` 配置。实际驻留内存随负载变化。 |
| `stats_size` | 默认 `1G` 原生统计堆预留，可用 `M` 或 `G` 配置。即使禁用统计监听接口，每上下文的原生接口计数仍需要这部分内存。 |
| `context_idle_seconds` | 无存活映射后等待 1 秒，还须安全排空在途 graph/handoff/reassembly 引用。 |
| `timeouts.udp` | 连接空闲 300 秒。 |
| `timeouts.tcp_transitory` | 240 秒。 |
| `timeouts.tcp_established` | 7440 秒。 |
| `timeouts.icmp` | 60 秒。 |

主配置不提供 `max_contexts` 或 `max_connections`，内部也不设置等效的独立接入/连接数门槛；初始内存分配不是准入上限。`main_core` 和 `workers` 选择互不重复且可用的 CPU；不指定 worker 时使用原生单线程模式。Area、attachment、Pool、地址和规则按实际资源动态存储。原生统计段没有监听接口，但内存规划仍需包含转发状态计数。实际内存、CPU、地址和端口资源有限；Pool 不限额不等于资源无限。

验收目标为跨多个 vSwitch 来源的 12288 个同时活跃上下文和 196608 条双向 NAT 映射，使用两个原生 worker。应查看具体候选版本的验收清单和内存实测，不据此推导吞吐或时延承诺。

## 线协议身份与 MTU

| Locator | 既有 vSwitch 合同 |
|---|---|
| `port` | 收到的目的 UDP 端口作为不透明 locator 原样用于回程。接受非零 UDP 目的端口字段的完整范围，不依赖发送方的 `port_base` 或 slot 分配。Area VNI 为 24 位。 |
| `vni` | UDP 6081，VNI 为 `(slot << 12) | area`，逻辑 Area 为 12 位。 |
| `tlv` | UDP 6081，配置的 class/type 标识第一个 locator option，Area 为 24 位。未知 critical option 拒绝，非 critical 元数据接收但不反射。 |

Egress 不限制 slot 范围，按报文字段保留 locator，包括完整 32-bit TLV 值。上下文按来源及 locator 建立索引，不按 slot 数值分配数组。Egress 不配置 `port_base`。Ether 封装且 generation 位宽为 1–20 时，源 MAC `02:fe:<32-bit big-endian generation>` 携带既有 generation，零也是有效值。Egress 从报文识别并保留各连接的回程标记，不重复配置 generation 位宽。接入身份为外层源 IP + Geneve 目的端口或 SlotID + VNI/逻辑 Area + 外层目的 IP（gatewayIP）。内层 IP 只参与转发和连接匹配；多个内层 IP 共用这一接入的 Pool 额度。vSwitch 按既有 generation 校验带标记目的 MAC，恢复 Guest MAC，并保留未标记 legacy 兼容。没有 vSwitch Go 配置、Attach 参数或代次方案变化。

attachment 不设置内层 `gateway`。ICMP 差错以接入接口的数据面地址为来源，不修改 Guest 默认网关，也不限制内层源 IP。

IP 封装和 legacy Ether 不增加新身份字段，既有协议无法区分身份复用后的任意迟到流量这一限制仍存在，不增加 Egress 租约协议掩盖它。

回程封装使用配置外层预算与内层 MTU 加封装开销中的较小值。内外层 IPv4 分片由原生重组；回包可以在隧道预算内分片，DF 错误及关联 ICMP 引用保持原上下文。真实路径和 vSwitch MTU 须协调；外层隧道不主动探测 PMTU。

## 诊断与恢复

私有运行目录包含 `pid`、`startup.conf`、`owner.lock` 及原子替换的 `status.json`。状态文件报告配置代次、reload 错误、外层接入数（`accesses`）、内部回程版本数（`contexts`）、NAT 数量及按名称标识的 Area/Pool 计数、原生报文错误、原生 PID 和接口/carrier 状态。它只是输出，不会作为配置恢复。服务不暴露 HTTP、Unix CLI、二进制 API、统计监听或命名共享内存 API 传输。管理进程通过匿名父子进程描述符对控制原生进程。

`egress link check --config link.json` 报告 pair 归属、位置和既有 vSwitch 状态。运行时检查覆盖网关进程、配置、部署拥有的接线和接口状态。Geneve 双向转发及 Pool 回程通过受控端到端测试验收。本部署能力不包含外部网络或目标探测、探测目标配置，也不以外部可达性作为启动门槛。

丢失或替换一个物理接口只禁用该接口并等待受控修复，其他路径继续工作；同名新设备不会自动被接纳。本地修复时，停止受影响流量，通过正常 Detach 排空 vSwitch 已分配端口，在更换 Egress 端点前停止 Egress，运行 `egress link repair --config link.json --switch-config switch.json --mode veth`，重新启动 Egress 并验证流量。共享网关重启会丢失其 NAT 状态。修复包装流程拒绝活动端口，不强制删除沙箱。

普通 `link stop` 将 switch 端点归还稳定 owner 并保留 pair。显式卸载应在 Detach 和停止两端后运行 `egress link uninstall --config link.json`。仅删除自有资源，保留借用 namespace 和 Pool 接口。仍有进程或其他设备的 namespace 保留供重试。这些操作不向 Egress 发送沙箱级通知。

配置只使用上述文件模型和随包示例。主配置不定义 `exits`，Pool 不定义数值 `id`；attachment 不定义 `area`、`port_base`、`encapsulation`、`generation_bits` 或内层 `gateway`，这些字段会被严格校验拒绝。

## 组件交付与 node-infra

同版本 Connector 发行包将 `connector-ctl`、`connector-vpp` 和 `vpp-runtime.json` 直接放在 `bin/` 下。数据面将 VPP、六个内建插件及 libc 静态链接到一个可执行文件。归档同时包含原生许可证材料、`deploy/connector-egress@.service` 和 `deploy/egress` 示例。安装或复制组件时保留完整目录。node-infra 中这些文件位于 `/opt/node-infra/bin`，网关使用 `/opt/node-infra/bin/connector-vpp`。

本地网关将主配置、Area 文件和 `link.json` 挂载到 `/etc/connector-egress`，参考平台 `node-infra/examples/local-egress`。现有节点准备流程管理共享链路；`owner_netns: ""` 表示节点流程保留的主网络命名空间，每次操作均核对其 inode。vSwitch 继续通过原有节点服务启停。Egress 仅运行转发进程，通过 SIGHUP reload，不接收沙箱生命周期通知。普通服务停止保留 pair；最终 owner 卸载在网关与 vSwitch 停止后清理 pair。借用的网关 namespace 和 Pool 接口由外部所有者保留。
