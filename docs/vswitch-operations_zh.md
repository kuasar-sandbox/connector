[English](vswitch-operations.md) | [简体中文](vswitch-operations_zh.md)

# vSwitch 运维

本手册覆盖交换机部署、沙箱端口分配、TAP queue 交付、流量检查与自有资源恢复。[网络契约](vswitch_zh.md)定义身份、转发、ABI 与并发；[TAPFD](tapfd_zh.md)定义可独立实现的 provider/consumer 协议。源码构建与验证策略见[贡献指南](../CONTRIBUTING_zh.md)。

## 部署与前置条件

### 系统要求

- 文档基线为 Linux **5.10+**,需相应 TC/BPF 配置,且 `/sys/kernel/btf/vmlinux`
  可访问。应验证实际内核配置与特权测试,版本号本身不足以保证可用。
- bpffs 挂载在 `/sys/fs/bpf`(`mount -t bpf bpf /sys/fs/bpf`)。
- 特权路径以具有所需能力的 root 运行;能力裁剪条件见 [所需权限](vswitch_zh.md#所需权限)。
- 需要 network namespace、TAP、veth、路由与 TC 支持。运行预构建二进制不需要 Go 或 Clang；源码工具链见[贡献指南](../CONTRIBUTING_zh.md#build-and-validation)。


延迟发布在 AMD64/ARM64 上使用普通 BPF 读取和显式地址依赖,不使用 fetch-atomic 指令或 `-mcpu=v3`,保持原 Linux 5.10 基线。生成指令及内核重写后的指令必须保留 up 到读取地址的依赖,并在 up 后重新读取 InnerIP;通过特权报文与 TAP-FD 测试验证实际行为。

### 获取匹配的二进制

从选定组件或聚合版本安装 `connector-ctl` 与 `dist/` 模板。精确资产验证见[平台安装](https://github.com/kuasar-sandbox/kuasar-sandbox/blob/main/docs/installation_zh.md)；自行生产组件时遵循[源码构建](../CONTRIBUTING_zh.md#build-and-validation)。用户态二进制与其内嵌 BPF 对象应来自同一源码版本。

### systemd 集成

`dist/` 提供三个模板:

| 模板 | 安装位置 | 用途 |
| --- | --- | --- |
| `dist/connector-vswitch.service` | `/etc/systemd/system/` | `Type=notify` 单元 |
| `dist/connector-switch.conf` | `/etc/connector/switch.conf` | EnvironmentFile(shell 变量格式) |
| `dist/NetworkManager-connector.conf` | `/usr/lib/systemd/system/NetworkManager.service.d/` | 可选:让 NetworkManager 在交换机之后启动 |

service unit 的关键结构(完整内容见 `dist/connector-vswitch.service`):

```ini
[Service]
Type=notify
WatchdogSec=60
EnvironmentFile=/etc/connector/switch.conf
ExecStartPre=...   # 1) 创建 SWITCH/PORT/MGMT netns(幂等,跳过空值)
ExecStartPre=...   # 2) switch 不存在时等待 TRANSIT_DEV,循环最多 120 次
ExecStart=/usr/sbin/connector-ctl vswitch serve ${SWITCH_NAME} ... --mgmt-extract=...:${MGMT_EXTRACT_CIDRS}
ExecStartPost=...  # Apply MGMT_ADDRS with idempotent ip addr replace.
ExecStartPost=...  # Enable route_localnet on the management device.
TimeoutStartSec=60
Restart=on-failure
LimitMEMLOCK=infinity
```

两个 `ExecStartPre`:第一个幂等地创建命名空间;第二个在交换机尚未存在时等待
`${TRANSIT_DEV}` 出现(例如等驱动加载)。120 次一秒循环还受单元 **TimeoutStartSec=60**
约束,不能解释为 systemd 保证等待 120 秒。上面的省略号是结构说明,不是可直接安装的完整单元。
management extraction 与接口地址显式分离:

```ini
MGMT_EXTRACT_CIDRS=169.254.169.254/32
MGMT_ADDRS=169.254.169.254/32
```

`MGMT_EXTRACT_CIDRS` 只传给 `--mgmt-extract`;逗号分隔的 `MGMT_ADDRS` 由第一个
`ExecStartPost` 使用 `ip addr replace` 幂等配置。`MGMT_ADDRS=` 可留空,此时 extraction
peer 保持无 IPv4 地址。该逻辑按 `MGMT_NETNS` 自动在 host netns 或 named netns 执行。
第二个 `ExecStartPost` 在 mgmt 设备上开启
`net.ipv4.conf.<dev>.route_localnet`,使 `--mgmt-service` 可指向 loopback target。

随附 ExecStart 传入 extraction flags,不会因为配置了 backend 或 route_localnet 就自动
传 `--mgmt-service`。使用静态服务映射时,必须把它显式加入实际服务命令/配置,
并保留地址、路由与 listener 设置。

**Host-netns 管理平面**:把 `MGMT_NETNS=` 留空(mgmt/metadata 服务直接跑在 host 上)
时,生成的 `--mgmt-extract=:<dev>:<cidrs>` 让 mgmt veth peer 留在调用方 netns,
第一个 `ExecStartPre` 也会自动跳过空值,无需手动创建 mgmt netns。`MGMT_ADDRS` 非空时
地址直接配置在 host 侧 peer;为空时该 peer 保持无地址。

### 首次启动

1. 将 binary 安装到模板使用的 `/usr/sbin/connector-ctl`,并按上表安装所选模板。
   用 `ip -br link` 确认专用 transit,编辑 `/etc/connector/switch.conf` 的
   TRANSIT_DEV、TRANSIT_DEV_ADDR 等。
2. 将该空闲专用设备置 DOWN:`ip link set "$TRANSIT_DEV" down`;启动会移入 switch
   netns。确认物理 underlay 支持配置的封装 MTU。
3. `sudo systemctl daemon-reload`,再 `sudo systemctl start connector-vswitch`。
   这是随附 **connector-vswitch.service** 文件对应的服务名。
4. 检查 `systemctl status connector-vswitch` 为 active,
   `connector-ctl vswitch status sw0 --ready` 返回 0,`ip netns list` 包含配置的命名空间。
   READY=1 可能早于所有端口 provision 完成([两阶段启动](vswitch_zh.md#两阶段启动))。
5. `sudo systemctl enable connector-vswitch` 启用开机启动。

## 手动创建首个交换机

以下用 Bash 和 `jq` 演示新建交换机。以 root 运行,使用可安全移入 `sw_ns` 的专用空闲 `eth1`;underlay 必须支持配置后的 transit MTU。`sw1`、`sw_ns` 和 `mgmt_ns` 三个名称均不得已被占用。执行 `open-port` 前,支持 TAPFD 的 VMM 接收端必须已监听 `TAPFD_SOCKET` 指定的本次运行私有路径。生产值取决于部署网络:

```bash
set -euo pipefail
: "${TAPFD_SOCKET:?Set the existing run-owned VMM receiver socket path}"
ip netns add sw_ns
ip netns add mgmt_ns
ip link set eth1 down

connector-ctl vswitch start sw1 \
    --netns=sw_ns \
    --ports=128 \
    --mac-addr=02:00:00:00:00:01 \
    --floating-ip-base=100.100.96.0 \
    --mgmt-extract=mgmt_ns:eth0:169.254.169.254/32 \
    --transit-dev=eth1 \
    --transit-dev-addr=10.0.0.1/24:10.0.0.2 \
    --transit-dev-mtu=auto

ip netns exec mgmt_ns ip addr replace 169.254.169.254/32 dev eth0

attach_json="$(connector-ctl vswitch attach sw1 \
    --inner-ip=169.254.1.1 \
    --transit-gateway-ip=10.0.0.2 \
    --transit-geneve-vni=100)"
port="$(printf '%s\n' "$attach_json" \
    | jq -er '.port | select(type == "number" and . >= 1 and . <= 128 and floor == .)')"

TAPFD_SOCKET="$TAPFD_SOCKET" connector-ctl vswitch open-port sw1 --port="$port"
```

保留 `attach_json`、实际 `port` 及返回的 attachment generation，供观测和清理使用。此时交换机与 VMM 可用于[双端验收](#双端验收)，应在清理之前完成这些检查。测试结束后，先经 VMM/consumer 的所属控制流程停止消费者并关闭其 TAP queue 引用，再在同一 shell 中执行以下清理：

```bash
connector-ctl vswitch detach sw1 --port="$port"
connector-ctl vswitch stop sw1
ip netns del mgmt_ns
ip netns del sw_ns
```

这些是文档示例地址,不是生产拓扑。从应接收归还 transit 设备的 namespace 执行 `stop`。检查端口与 transit 的实际 MTU:当前两阶段 provision 未把 `--mtu` 传给新建 TAP/veth 端口。完整命令参考与部署操作见 [vSwitch 运维](vswitch-operations_zh.md);转发和生命周期约束归属于 [vSwitch 设计](vswitch_zh.md)。

这是人工操作顺序,不是自动失败清理脚本。任何命令失败都应停下,检查实际分配结果,并且只移除本次运行创建的资源。不得强制停止预存交换机或删除陌生 namespace。

## 命令行与配置参考

多数查询和一次性命令输出 JSON;`serve` 常驻并报告健康/进度。BPF、设备与 namespace
操作以具有所需能力的 root 运行,见 [所需权限](vswitch_zh.md#所需权限)。

### 子命令总览

| 命令 | 用途 |
| --- | --- |
| `start [switch_name]` | 创建并启动交换机(StartReserved + 同步 ProvisionPorts),返回后用户态退出 |
| `serve [switch_name]` | systemd `Type=notify` 长驻:StartReserved → tapfd listen(可选) → READY=1 → 后台 ProvisionPorts → 健康检查循环 |
| `stop <name>` | 清理所属端口/交换机资源与 pinned maps,把 transit 移入 stop 调用方的 netns |
| `attach <name>` | 分配端口(CAS Free→IP);veth 模式可把端口设备移入沙箱 netns |
| `set-port-up <name> --port=N` | 为已分配但尚未启用的 attachment 提交完整最终配置并放行流量。 |
| `detach <name> --port=N` | 释放端口(CAS Allocated→Free);不借用 Reserved 作为过渡态 |
| `reserve <name> --port=N` | 把端口标记为 Reserved,阻止后续 attach(升级/排空) |
| `provision <name>` | 为 Reserved slot 创建端口设备;支持批量与单点修复 |
| `open-port <name> --port=N` | 打开 tap 端口的队列 fd,经 `TAPFD_SOCKET` 递交 consumer([TAPFD 动态获取契约](tapfd_zh.md#动态获取契约normative) 的 provider helper) |
| `status <name>` | 交换机状态(Conditions);`--ready` 以退出码表达 |
| `stats <name>` | per-port 流量计数(mgmt/transit × rx/tx × packets/bytes) |
| `show slots\|config <name>` | dump slot 表 / in-kernel 配置 |
| `dhcp request\|serve` | 内嵌 DHCP 客户端/服务器(调试与测试场景) |


### `connector-ctl vswitch start` / `serve`

`start` 同步完成全部初始化后退出;`serve` 用于 systemd `Type=notify` 长驻([两阶段启动](vswitch_zh.md#两阶段启动))。
`switch_name` 可省略,从 `--config` 文件([配置文件(`--config`)](#配置文件--config))读取。

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `--netns` | ✓ | 交换机内部 netns(必须已存在) |
| `--mac-addr` | ✓ | 虚拟 MAC base,前 4 字节用于派生所有 MAC([MAC 派生](vswitch_zh.md#mac-派生)) |
| `--ports` | ✓ | 端口数(1–4096) |
| `--floating-ip-base` | ✓ | floating IP 基地址(按 slot_id 递增) |
| `--generation-bits` | 否 | 固定 12 位 slot identity 之上的 generation 位数，0–20，默认 0 仅允许 generation 0；整个 FloatingIP 范围必须能容纳在 IPv4 中。 |
| `--port-netns` | veth 模式 ✓ | 端口设备初始 netns;tap 模式或 `--reserved` 下可省 |
| `--mode` | – | 自动 provision 的端口类型:`tap`(默认)或 `veth`;配合 `--reserved` 时仅作参数校验提示,不持久化 |
| `--mgmt-extract` | – | 管理平面提取匹配 `<netns>:<dev>:<cidr1>,<cidr2>,...`,可重复(每 slot 最多 3 条路由);CIDR 不会被配置为接口地址;`<netns>` 留空(`:<dev>:<cidrs>`)则 mgmt veth peer 留在调用方/主机 netns |
| `--mgmt-service` | – | 管理服务地址转换 `<VIP>:<vport>:<targetIP>:<targetPort>`,可重复;VIP 须落在某条 `--mgmt-extract` 路由内,`(targetIP,targetPort)` 须全局唯一,TCP/UDP 均转换([数据包流向](vswitch_zh.md#数据包流向));loopback target 需 mgmt 设备 `route_localnet=1` |
| `--transit-dev` | – | 外部上行设备,start 时从调用 netns 移入 switch netns;必须处于 **DOWN**(防止接管在用网卡) |
| `--transit-dev-addr` | – | `<ip>/<prefix>:<nexthop>` 或 `auto`(DHCP,[DHCP 网关推算](vswitch_zh.md#dhcp-网关推算)) |
| `--transit-dev-mtu` | – | `auto` 或具体数值;默认不修改,仅校验([MTU 校验](vswitch_zh.md#mtu-校验)) |
| `--geneve-locator` | – | `port`(默认)、`vni` 或 `tlv`,定义外部网关如何定位零基 `slot_id`([GENEVE 隧道](vswitch_zh.md#geneve-隧道)) |
| `--geneve-port-base` | – | 仅 `port` locator 使用的 GENEVE UDP 端口基值(默认 50000) |
| `--geneve-tlv-locator` | `tlv` locator ✓ | 精确 wire `CLASS:TYPE`,例如 `0102:81`([GENEVE 隧道](vswitch_zh.md#geneve-隧道)) |
| `--geneve-encap-eth` | – | 启用 Ether-over-GENEVE(默认 IP-over-GENEVE) |
| `--mtu` | – | 请求的启动 MTU,用于管理设备与初始 transit budget 检查;当前两阶段 provision 不把它传给新 TAP/veth 端口,须检查实际端口 MTU([MTU 校验](vswitch_zh.md#mtu-校验)) |
| `--port-mac-addr` | – | `fixed`(默认)/`per-port`/具体 MAC([MAC 派生](vswitch_zh.md#mac-派生)) |
| `--reserved` | – | 仅做 StartReserved,不自动 ProvisionPorts。port-netns 由 start 写入交换机配置、`provision` 无独立 flag 覆盖,故计划用 veth 端口时 start 仍需给 `--port-netns` |
| `--config` | – | 从 JSON 文件读取以上参数([配置文件(`--config`)](#配置文件--config)) |

`serve` 复用 `start` 的交换机参数,差异:无 `--reserved` flag,另有:

| 参数 | 说明 |
| --- | --- |
| `--watch-interval` | 健康检查间隔,默认 30s |
| `--tapfd-listen` | 持久 vswitch/tapfd UDS。支持 `TAPFD/1 PREPARE` / `OPEN` / `SET_PORT_UP` / `RELEASE`;`OPEN` 返回 `TAPFD/1 OK` + metadata + SCM_RIGHTS;详见 [tapfd_zh.md](tapfd_zh.md) [网关互操作验收与恢复](#网关互操作验收与恢复) |

`start` 示例输出(值用于展示,不是前面 128-port 命令的实际结果):

```json
{
  "switch": "sw1",
  "switch_netns": "netns_switch",
  "switch_maps": {
    "slots":           "/sys/fs/bpf/sw1/slots_v2",
    "config":          "/sys/fs/bpf/sw1/config",
    "stats":           "/sys/fs/bpf/sw1/stats",
    "ifindex_to_slot": "/sys/fs/bpf/sw1/ifindex_to_slot",
    "geneve_opts":     "/sys/fs/bpf/sw1/geneve_opts",
    "metadata":        "/sys/fs/bpf/sw1/metadata",
    "mgmt_svc_fwd":    "/sys/fs/bpf/sw1/mgmt_svc_fwd",
    "mgmt_svc_rev":    "/sys/fs/bpf/sw1/mgmt_svc_rev"
  },
  "port_netns": "netns_ports",
  "ports": 4096, "ports_used": 0, "ports_available": 4096,
  "floating_ip_base": "100.100.96.0",
  "mgmt_planes": [
    { "index": 0, "mgmt_netns": "netns_mgmt", "mgmt_dev": "eth0",
      "service_routes": ["169.254.169.254/32"], "return_route_metric": 100 }
  ],
  "mgmt_services": [
    { "vip": "169.254.169.254", "vport": 80,
      "target_ip": "127.0.0.1", "target_port": 19254, "protocols": "tcp,udp" }
  ],
  "transit_type": "overlay-geneve",
  "transit_dev": "eth1",
  "transit_dev_ip": "10.200.12.3",
  "geneve_locator": "port",
  "geneve_port": 50000,
  "geneve_port_base": 50000
}
```

`mgmt_services` 仅在配置了 `--mgmt-service` 时出现;`status` 与 `show config` 同样
回显 `mgmt_planes`/`mgmt_services`(取自 metadata map)。输出字段
`mgmt_planes[].service_routes` 保留现有名称,其值是 extraction match CIDR,不表示
management 接口已持有这些地址。

### `connector-ctl vswitch stop`

若配置的交换机命名空间已经无法通过名称访问，stop 仅释放遗留 slot 记录并 unpin 交换机，不会把其中保存的接口编号用于调用者命名空间，也不会删除调用者链路或从调用者命名空间迁出 transit 设备。配置名有意留空时仍在调用者命名空间清理；其他命名空间查询错误正常返回。删除命名空间名称不证明已无进程持有原命名空间，仍需单独检查保留的命名空间和孤儿设备。

内部分为 ReleasePorts 与 StopReleased:删除所属端口、管理/dummy 设备和 TC 引用,
unpin maps,把 transit 移入 **stop 调用方的 namespace**。若要还给原 Host netns,
须从那里执行 stop;实现并不保存并自动恢复另一个 origin namespace。

| 参数 | 说明 |
| --- | --- |
| `--force` | 先释放所有 in-use 端口再 stop(两轮清理),用于强制关停 |
| `--force-clean` | 损坏状态恢复:仅 unpin BPF 资源,不清理设备;须检查/清理遗留 netdev 和 TC 引用,不能据此断言转发已停止 |

### `connector-ctl vswitch attach`

分配端口：CAS Free→IP；veth 模式可同时把端口设备移入沙箱 netns。未 provision 的端口不可使用；异步启动期间，调用方应处理尚未 provision、分配失败或无可用端口的状态，并按[就绪条件](vswitch_zh.md#两阶段启动)重试。

| 参数 | 说明 |
| --- | --- |
| `--inner-ip=IP` | 沙箱内部 IP(必填) |
| `--generation=N` | 调用方提供的 attachment generation，默认 0；要求 `0 <= N < 2^generation_bits`，未配置 generation bits 时仅允许 0；它与内部统计计数代次相互独立。 |
| `--port=N` | 指定槽位(省略则自动分配) |
| `--to-netns=NS` | 把端口设备移入目标 netns(仅 veth 模式) |
| `--transit-gateway-ip=IP` | GENEVE 外层目标 IP |
| `--transit-geneve-vni=N` | GENEVE VNI |
| `--transit-geneve-opt=CLASS:TYPE:DATA` | 单向出站 opaque GENEVE option,可重复;十六进制 data 长度须为 4 字节整数倍,空 data 写作 `CLASS:TYPE:`([GENEVE 隧道](vswitch_zh.md#geneve-隧道)) |
| `--transit-mac-addr=MAC` | Ether-over-GENEVE 内层目标 MAC(省略则广播) |
| `--skip-device` | 跳过 veth namespace 移动,仍进行 slot/map 控制更新;tap attachment 拒绝 |
| `--open-port` | tap 模式:分配后经 TAPFD_SOCKET 递交 fd;失败时尝试 detach/回滚,清理也失败时须先核对状态再重试 |
| `--admin-down` | 分配并准备 attachment，但暂不启用流量。完成 FD 交付与 guest 配置后，使用 `set-port-up` 提交全部最终网络字段。默认 false。 |

`attach` 输出示例(veth 模式,展示选定字段):

```json
{
  "port": 4, "port_dev": "sw1-p4", "port_netns": "sandbox_ns_4",
  "port_mac": "02:00:00:00:80:01",
  "inner_ip": "169.254.1.1",
  "floating_ip": "100.100.96.3",
  "transit_type": "overlay-geneve",
  "geneve_port": 50003,
  "geneve_locator": "port",
  "transit_gateway_ip": "10.200.12.1",
  "transit_geneve_vni": 1004,
  "wire_geneve_vni": 1004
}
```

attach/show JSON 的 `geneve_opts_len` 为 locator 加 opaque options 的总 wire 字节数,
0 时省略。原始 slot 同名字段只存 opaque bytes,两者不同([数据面 ABI](vswitch_zh.md#数据面-abi))。

`attach --open-port` 输出示例(选定字段):

```json
{
  "port": 4, "port_dev": "sw1-t4",
  "port_mac": "02:00:00:00:80:01",
  "inner_ip": "169.254.4.1",
  "tap_sent_to": "/tmp/recv.sock"
}
```

Attach 可重复提供 `--transit-geneve-opt=CLASS:TYPE:DATA`:

```bash
connector-ctl vswitch attach sw0 --inner-ip=169.254.1.1 \
    --transit-gateway-ip=10.0.0.2 --transit-geneve-vni=42 \
    --transit-geneve-opt=0102:02:0000002a \
    --transit-geneve-opt=0102:83:1122334455667788
```

### `connector-ctl vswitch detach`

释放端口:支持 `PORT_F_UP` 的 Attach/Detach 不持有全局锁,也不等待管理 EX 锁。Detach 完成可失败的设备操作后清 publication/options hint,最后 CAS→Free;释放后不再写 slot。管理接管是预期行为;Reserved→Free 有独立、严格的管理进出边界,不作为旧请求与立即复用任意交错的步骤。全局 attachment 锁属于实现缺陷,不保留兼容回退。缺少 `PORT_F_UP` 的旧 pinned switch 在 Attach/Detach 修改状态前报错,须经管理流程重建;仍可查询和管理清理。
`Reserved` 只表示显式 reserve/provision/stop 状态,Detach 不把它用作过渡态。固定长度 options map value 和其它 transit fields 不在 Detach 中清理;
Free slot 不会被数据面使用,下一次 Attach 在发布新 hint 前完整覆盖。缺少新能力或必需
`geneve_opts` map 的 switch 不允许 Attach/Detach,不会回退到旧实现。tap slot 无设备操作;veth slot
给 `--from-netns` 则把设备移回 port netns,省略则校验设备已在 port netns。

| 参数 | 说明 |
| --- | --- |
| `--port=N` | 槽位编号(必填) |
| `--from-netns=NS` | 端口设备当前所在的沙箱 netns(veth 模式) |
| `--skip-device` | 跳过设备移动/校验(veth/tap 均可) |

### `connector-ctl vswitch reserve`

把端口标记为 Reserved,阻止后续 attach;用于升级/排空,或为 `provision --mode` 切换
端口类型做准备([端口模式:veth 与 tap](vswitch_zh.md#端口模式veth-与-tap))。

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `--port=N` | ✓ | 槽位编号(1-based) |
| `--force` | – | 允许覆盖 Allocated → Reserved(默认仅 Free → Reserved) |

### `connector-ctl vswitch provision`

为 Reserved slot 创建端口设备并使其对 attach 可见。幂等:Free/Allocated slot 跳过,
失败的 Reserved slot 保留状态,可单点修复。

| 参数 | 说明 |
| --- | --- |
| `--port=N` | 仅处理指定槽位(单点修复);与 `--count` 互斥 |
| `--count=N` | 限制本次创建的设备数(0 = 全部);与 `--port` 互斥 |
| `--mode=tap\|veth` | 端口类型(默认 `tap`);在 Reserved slot 上切换类型时先建新设备、commit 新 ifindex、再删旧设备 |

### `connector-ctl vswitch open-port`

[TAPFD 动态获取契约](tapfd_zh.md#动态获取契约normative) 动态获取契约的 provider helper:进入 switch netns,对持久 tap
执行 `open(/dev/net/tun)` + `TUNSETIFF(IFF_TAP|IFF_NO_PI|IFF_VNET_HDR)`,把队列 fd 连同
元数据经 `SCM_RIGHTS` 发往 `TAPFD_SOCKET` 指定的套接字(`fd=N` 或路径,tapfd.md [套接字位置的通告:`TAPFD_SOCKET`](tapfd_zh.md#套接字位置的通告tapfd_socket))。
环境变量 `TAPFD_WANT_NETNS` 为真值时在 tap fd 后追加 switch netns fd 并置
`netns_fd=1`(tapfd.md [请求 netns fd:`TAPFD_WANT_NETNS`](tapfd_zh.md#请求-netns-fdtapfd_want_netns))。

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `--port=N` | ✓ | tap 槽位编号(1-based) |

前置条件:slot 为 tap 类型、已 provision(`ifindex != 0`)、已 attach(inner IP 为
真实 IP)——任一不满足在触碰套接字/tap 之前即拒绝。交换机未运行时退出码 `3`。

```bash
# 先启动实现 TAPFD metadata 与 SCM_RIGHTS 的 receiver,见 tapfd.md
TAPFD_SOCKET=/run/vm1.sock connector-ctl vswitch open-port sw0 --port=3
TAPFD_SOCKET=fd=3 connector-ctl vswitch open-port sw0 --port=3      # 继承 fd 形式
```

输出:

```json
{
  "port": 3, "tap_dev": "sw0-t3", "sent_to": "/run/vm1.sock",
  "mac": "02:00:00:00:80:01", "inner_ip": "169.254.3.1",
  "netns_sent": false
}
```

### `connector-ctl vswitch status`

输出交换机 JSON 状态,Conditions 风格:`Ready`、`PortDevicesReady`、
`MgmtDevicesReady`、`TransitDeviceReady`;ProvisionPorts 未完成(或
`start --reserved` 之后)还会出现 `PortReserved`。

`PortReserved` 是信息项。设备检查跳过 Reserved slot,所以即使全部端口仍 Reserved,
`Ready` 与 `PortDevicesReady` 也可能为 True。判断可分配容量须检查
`ports_available`/`ports_reserved` 或目标 slot;不能只凭 `status --ready`。
见 [status 实现](../pkg/vswitch/status.go)。

| 参数 | 说明 |
| --- | --- |
| `--ready` | 不打 JSON,按 Conditions 退出:`0`=Ready,`3`=NotExist,`4`=NotReady |

```json
{
  "switch": "sw1",
  "state": "running",
  "conditions": [
    { "type": "Ready",              "status": "True" },
    { "type": "PortDevicesReady",   "status": "True" },
    { "type": "MgmtDevicesReady",   "status": "True" },
    { "type": "TransitDeviceReady", "status": "True" }
  ],
  "ports": 4096, "ports_used": 128, "ports_available": 3968,
  "mgmt_planes": [{ "index": 0, "mgmt_netns": "netns_mgmt", "mgmt_dev": "eth0",
                    "service_routes": ["169.254.169.254/32"], "return_route_metric": 100 }],
  "transit_dev": "eth1", "transit_dev_ip": "10.200.12.3"
}
```

全部 4096 个端口仍 Reserved、没有非 Reserved 设备可检查时的 Conditions 片段:

```json
"conditions": [
  { "type": "Ready", "status": "True" },
  { "type": "PortDevicesReady", "status": "True",
    "message": "0 ports to check (all reserved)" },
  { "type": "PortReserved", "status": "True", "message": "4096 ports reserved" }
]
```

### `connector-ctl vswitch stats`

per-port 流量计数,从沙箱视角:mgmt/transit × rx/tx × packets/bytes。

| 参数 | 说明 |
| --- | --- |
| `--port=N` | 可重复;省略则列出所有已分配端口 |

```json
{
  "switch": "sw1",
  "ports": [
    { "port": 1,
      "mgmt_rx_packets": 42,  "mgmt_rx_bytes": 3528,
      "mgmt_tx_packets": 42,  "mgmt_tx_bytes": 3528,
      "transit_rx_packets": 100, "transit_rx_bytes": 8400,
      "transit_tx_packets": 100, "transit_tx_bytes": 8400 }
  ]
}
```

`rx` 表示送往沙箱,`tx` 表示来自沙箱. packets 是既有 BPF 观测点的包计数,不是应用请求数或速率. management bytes 使用端口/management ingress 观测到的以太网帧长度. transit TX 使用原始帧长度;transit RX 扣除外层 GENEVE 头并保留以太网头. 这是观测字节数,不是物理链路开销总和. management 和 transit 保持分开,不把重叠观测相加成统一总流量.

`pkg/vswitch.Stats(name, ports)` 和 `Interface.Stats(ports)` 提供同一份按端口列表读取的能力,不启动 CLI 子进程. 消费方应按交换机组织当前绑定并限制批量大小. 生命周期锁占用、交换机替换、map 读取失败或 attach 清零未确认时,整个读取失败,不能替换为 0 或旧样本. Free/Reserved 端口不属于当前观测. detach 不擦除 map,但其计数不能作为 live attachment 查询. reset 失败不使 attach 失败,该 attachment 的 Stats 保持不可用;重新 attach 且清零成功后发布有效的 0 计数. 新计数 ARRAY 使用内核锁与内部代次隔离并发 TC 写入;旧 PERCPU_ARRAY 交换机须重建后才能采集. 读取前后均核验当前 map 身份,force cleanup 也会使读中样本失效.

### `connector-ctl vswitch show`

- `show slots <name> [slot_id]` — dump slot 表为 JSON(单槽或全部)。
- `show config <name>` — dump in-kernel `switch_config`,并附 metadata 中的
  `transit_dev`/`mgmt_planes`/`mgmt_services`。

`show slots` 回显已分配槽的 configured `transit_geneve_vni` 与 `geneve_opts_len`,后者是 locator
加 opaque options 的总 wire 字节数;默认不打印 opaque data。`show config` 在 TLV 模式
例如输出:

```json
{
  "geneve_locator": "tlv",
  "geneve_port": 6081,
  "geneve_tlv_locator": "0102:81"
}
```

### `connector-ctl vswitch dhcp`

内嵌 DHCP 客户端与服务器,服务于 transit `auto` 寻址的调试与 e2e 测试拓扑。

- `dhcp request --dev=<iface> [--timeout=5s] [--retries=3]` — 在指定设备上跑一次
  DHCP 并打印结果。
- `dhcp serve --dev=<iface> --server-ip=<ip> --pool=<a.b.c.d-a.b.c.e>
  [--gateway=<ip>] [--dns=<ip,...>] [--lease-time=1h]` — 简易 DHCP 服务器,
  `--gateway` 默认取 `--server-ip`。

### `connector-ctl tapfd get`

这是同一个 connector-ctl 二进制中、与 switch 状态无关的 tapfd provider 子命令:打开 tap,把其
`IFF_VNET_HDR` 队列 fd 经 `TAPFD_SOCKET` 以 `SCM_RIGHTS` 递交 consumer。用于不经
vswitch 数据面、只需要"拿一个 tap fd"的场景(测试、简单拓扑)。

```
connector-ctl tapfd get <tap>            # 打开已存在的 tap 并交接其队列 fd
connector-ctl tapfd get --new [<tap>]    # 不存在则创建;省略名时内核自动分配
```

| 参数 | 说明 |
| --- | --- |
| `--new` | 不存在则创建 `<tap>`(缺省要求 tap 已存在) |
| `--host-cidr=IP/N` | 给 `<tap>` 分配宿主侧 IP/CIDR 并拉起(点对点对端,便于连通性测试) |
| `--mac=...` | 写入交接元数据的 guest MAC |
| `--ip=...` | 写入元数据的 guest inner IP(裸地址或 CIDR) |

经 `--new` 创建的 tap **不是**持久设备:交接出去的 fd 维持其存活,所有引用关闭后设备
随之消失(对比 vswitch 端口的持久 tap,[端口模式:veth 与 tap](vswitch_zh.md#端口模式veth-与-tap))。

### 配置文件(`--config`)

`start`/`serve` 接受 JSON 配置文件,字段与同名 flags 一一对应:

| 字段 | 对应 flag |
| --- | --- |
| `switch_name` | positional `switch_name` |
| `switch_netns` | `--netns` |
| `port_netns` | `--port-netns` |
| `num_ports` | `--ports` |
| `mac_addr` | `--mac-addr` |
| `floating_ip_base` | `--floating-ip-base` |
| `generation_bits` | `--generation-bits`，默认 0。 |
| `mgmt_extracts` (数组) | `--mgmt-extract` |
| `mgmt_services` (数组) | `--mgmt-service` |
| `transit_dev` / `transit_dev_addr` / `transit_dev_mtu` | `--transit-dev*` |
| `geneve_locator` / `geneve_port_base` / `geneve_tlv_locator` / `geneve_encap_eth` | `--geneve-*` |
| `mtu` | `--mtu` |
| `port_mac_addr` | `--port-mac-addr` |

```json
{
  "switch_name": "sw0",
  "switch_netns": "sw0_vswitch",
  "num_ports": 4096,
  "mac_addr": "02:00:00:00:00:01",
  "floating_ip_base": "100.100.96.0",
  "mgmt_extracts": [":sw0_m0:169.254.169.254/32"],
  "mgmt_services": ["169.254.169.254:80:127.0.0.1:19254"],
  "transit_dev": "eth1",
  "transit_dev_addr": "auto",
  "transit_dev_mtu": "auto",
  "geneve_locator": "tlv",
  "geneve_tlv_locator": "0102:81"
}
```

使用 `--config` 时,位置参数覆盖文件中的 switch_name,但普通 switch flags 并不会
逐字段叠加覆盖该文件。`--mode` 仍控制 CLI 的自动 provision 类型;稍后的 Reserved
slot 操作用 `provision --mode`。所有管理 plane 的 CIDR **总数应不超过三条**:slot
ABI 只有三个位置,当前 provision 达上限便停止写入。JSON 解析成功不证明更多路由
已进入数据面;部署检查应读取实际 slots。


### `connector-ctl vswitch set-port-up`

`attach --admin-down` 返回已分配但流量阻断的端口(`admin_down: true`);省略此标志仍为普通立即 up 的 Attach。down TAP 端口可以正常 open-port/交付 FD,随后一次性提交最终配置:

```bash
connector-ctl vswitch attach sw0 --port=3 --inner-ip=169.254.1.1 --admin-down
# owner 此时可交付 TAP FD,并通过 runtime 通道准备 guest 的最终地址。
connector-ctl vswitch set-port-up sw0 --port=3 --inner-ip=169.254.2.2 \
  --transit-gateway-ip=10.0.0.2 --transit-geneve-vni=42 \
  --transit-geneve-opt=0102:02:0000002a --transit-mac-addr=02:00:00:00:00:09
connector-ctl vswitch show slots sw0 2
```

`--port` 与 `--inner-ip` 必填;transit 参数是可选的最终值,省略表示清空初始值/options。set-port-up 不重新分配端口或交付 FD,拒绝 Free、Reserved 和已 up 端口。准备失败保留 down,成功后的响应丢失不回滚发布。owner 必须顺序调用同端口操作,没有新全局锁。Detach 同时接受 up 和已完成的 down attachment。参见[架构约束](vswitch_zh.md#延迟启用端口)及[TAPFD 请求](tapfd_zh.md#延迟启用请求)。

## 故障排除

| 症状 | 原因 / 处理 |
| --- | --- |
| `transit device not found` | 核对预期 caller netns 中的 TRANSIT_DEV/ip link;运行中的 switch 可能已把设备移入 switch netns。 |
| `transit device eth1 must be DOWN before use` | 启动安全检查;`ip link set eth1 down` 后重启 |
| `failed to pin maps: ...bpffs not mounted` | `mount -t bpf bpf /sys/fs/bpf`,并加入 `/etc/fstab` |
| `switch already exists` | 先检查已有 switch/配置;确需替换时正常 stop,不把活跃转发下删除 pins 当常规重启流程。 |
| 升级后 ABI 不兼容 | 先排空/停止 consumer,正常或强制 cleanup;损坏状态的 force-clean 只删 pins,还须检查/清理孤儿设备/TC 并还回 transit,再 recreate。 |
| `port not provisioned` 或 Reserved slot 无法 attach | 检查 `ports_available`/`ports_reserved` 或目标 slot,等待/重试或显式修复 Reserved slot;仅凭 `PortDevicesReady=True` 不能证明有可分配容量 |
| open-port 报 `port not attached` | 先 attach 再 open-port |

### GENEVE 抓包

按实际 switch namespace、transit 设备和配置的 locator 端口调整命令;下方 filter 只是示例,不是通用端口范围。只抓取已授权流量,并保护可能含敏感 payload 与拓扑的抓包结果。

抓包调试可在 switch netns 的 transit 设备执行:

```bash
ip netns exec sw0_vswitch tcpdump -ni eth1 -vv -XX 'udp port 6081 or udp portrange 50000-54095'
connector-ctl vswitch show config sw0
connector-ctl vswitch show slots sw0
```

在 pcap 中核对 UDP dst、24-bit VNI、`OptLen`、base `C`、option class/type/length/data
及 inner payload 起始偏移。TLV locator data 应是零基 slot_id 的 big-endian 32-bit 值。

## 网关互操作验收与恢复

使用隔离测试 switch/namespace 和部署方管理的网关。Connector 提供主机交换机
及 TAP 交接，不提供外部网关产品或策略引擎。网关实现、路由/NAT、DNS、策略与
审计由其运营方负责。[GENEVE 线协议](vswitch_zh.md)、[MTU 契约](vswitch_zh.md)
及 [TAP 所有权](tapfd_zh.md) 是权威来源。

### 已准备平台的网络验证

产品 E2E 与以上源码/构建目标分开。使用包含匹配 connector case 和平台公共 runner 的预构建平台目录，先准备新工作区，再运行 network suite：

```bash
PLATFORM=/path/to/prebuilt-platform
WORKDIR=/path/to/new-network-workspace
python3 "$PLATFORM/test/e2e/e2e" prepare --release-dir "$PLATFORM" --workdir "$WORKDIR"
sudo python3 "$WORKDIR/test/e2e/e2e" run --workdir "$WORKDIR" --suite network
```

CI 使用同一个平台 runner，只消费预构建产品执行所选 case，不编译 Go 代码，也不调用组件自有 runner。仅在隔离测试环境运行，并满足每个已选 case 的前置条件；缺少条件属于失败，不是成功跳过。

网络 case 启动时会检查 root 权限。统一 runner 不会自动提权，因此用 `--include network.tap.sh` 单独选择 case 时，也必须保留 `sudo`（或使用 root shell）。

### 双端验收

1. 约定 IP-over-GENEVE/Ether-over-GENEVE、port/vni/tlv locator、UDP 目的、
   VNI 和 opaque 策略选项。Linux GENEVE bridge peer 需要 Ethernet 模式。
   保存实际 attach 结果：CLI port 从 1 开始，wire slot 从 0 开始，并保留配置
   的 generation。回包必须使用配置的 gateway 源 IP 及合法 VNI/locator；
   不得回显 outbound opaque options，TLV 回包仅携带规定 locator。普通
   GENEVE endpoint 不证明符合此契约。
2. 检查 underlay 路由/邻居及双向 UDP，按真实封装和选项计算 MTU，检查 transit、
   实际 port/Guest MTU。当前两阶段 provision 不把启动 `--mtu` 传给新 port。
   核对网关到主机回程；仅有出站抓包不算成功。
3. 在[手动创建首个交换机](#手动创建首个交换机)的清理步骤之前，使用已分配并交付 TAP FD 的 `port`，在 Guest 与受控网关侧端点
   间发已知请求/响应，双向比对 nonce/payload。测试小包、接近有效 MTU 的包、
   TCP/UDP 及所需 Guest DNS。按 [GENEVE 抓包](#geneve-抓包) 双端抓包，比对
   `connector-ctl vswitch stats sw1 --port="$port"` 增量和网关观测；计数器不证明应用或策略成功。
4. 仅在私有 fixture 验证允许与网关拒绝的目标/租户，对照分配身份核查决策；
   分别验证无直接 sandbox-to-sandbox 转发、无效回包 locator/VNI 被拒及管理
   专用目的地。不要对生产网络应用测试策略或伪造流量。跨身份投递立即停止。
5. 关闭测试 VMM/FD owner，仅 detach 保存的端口并停止测试 switch。确认专用
   transit 设备返回预期 namespace；网关运营方仅清理本 fixture 路由/策略。

具体 TCP 请求/响应探针可由网关运营方在批准的测试 IP 暴露临时 Python 3
端点。只把 curl 命令放入已 attach 且安装 curl 的 Guest 执行，须返回精确 proof
行；记录前后双端抓包和端口 stats。这验证回程，还需用网关 UDP/DNS fixture
和 allow/deny 策略场景复测，不能以单次 HTTP 成功代表完整策略验收。

```bash
# Gateway-side test endpoint, in the operator-selected test network
TEST_ROOT=$(mktemp -d)
printf 'kuasar-return-path-proof\n' > "$TEST_ROOT/probe"
python3 -m http.server 18080 --bind "$TEST_IP" --directory "$TEST_ROOT" &
TEST_PID=$!
```

```bash
# Run inside the attached test guest, with the same reachable TEST_IP:
curl --fail --max-time 5 "http://$TEST_IP:18080/probe"
```

```bash
# Back at the gateway-side endpoint, after verification:
kill "$TEST_PID"
wait "$TEST_PID" 2>/dev/null || true
rm -rf -- "$TEST_ROOT"
```

### 按故障域恢复

| 故障 | 安全恢复与验收 |
|---|---|
| serve 退出，namespace/device/TC/pin 完整 | 检查 status/config，以原配置重启服务。内核转发可能存活；验证 health/TAPFD 及原有双向流量，不要把全部 detach 当作重启步骤。 |
| namespace、TAP/transit device 或 pinned 状态损坏 | 停止准入，协调 orchestrator/sandboxer 排空或停止消费者。盘点 owner、port/generation 和已提交 checkpoint；owner 释放后按管理操作修复/重建，由 owner 重新 attach。旧 FD/端口不会自动有效，须验证新流量并显式清理孤儿资源。 |
| ABI 升级，包括旧 stats PERCPU_ARRAY | 排空消费者、保留所需快照、停止旧 switch，以匹配 userspace/BPF ABI 重建，再由 owner 分配新绑定。不要原地替换活跃 map/TC 迎合新 reader。force cleanup 是损坏处理，可能遗留 device/TC，重建前检查。 |

serve 重启或 switch 重建均不恢复丢失的 Guest 内存。暂停沙箱由 orchestrator/
sandboxer 负责恢复资格、网络重绑定与资源准入，Connector 不重分配平台身份。
恢复后再次验证 allow/deny 和回程，再开放准入。

## 相关文档

- [网络不变量](vswitch_zh.md)
- [TAPFD 协议](tapfd_zh.md)
- [构建与验证](../CONTRIBUTING_zh.md#build-and-validation)
