# vswitch — eBPF 虚拟交换机

基于 eBPF/TC 的高性能虚拟交换机,为单台宿主机上最多 4096 个沙箱(microVM)提供互相
隔离、可独立访问管理平面与外部网络的通道。CLI 为 `connector-ctl vswitch`,并提供 `connector-ctl tapfd get` tapfd provider 子命令。

数据面纯内核:配置完成后用户态进程即退出,所有转发由 TC ingress 上的 eBPF 程序承载,
数据路径上没有任何用户态守护进程。转发判定自始至终基于 slot_id(从入口 ifindex、
floating IP 或 GENEVE UDP 端口算术推导),永不信任沙箱报文里的源 IP/源 MAC;eBPF
程序中不存在 port→port 转发分支,ARP 全部代答,源 MAC 在出口强制改写——沙箱间隔离是
程序的结构性质,可静态审计。

tap 模式下端口 fd 经 `SCM_RIGHTS` 直接递交 VMM(Cloud Hypervisor、Firecracker 等),
交接协议(provider/consumer 双侧契约)独立成文:[tapfd.md](tapfd.md)。

## 1. 概述

### 1.1 业务问题

为单机数千个 microVM 提供网络通道,要求同时满足:纯内核转发(数据路径无用户态进程)、
沙箱级隔离(互不可见)、4K 级密度、控制面与数据面解耦(控制进程崩溃不断流)。现有路径
各有不契合:Linux bridge + iptables 每端口一份 netfilter 规则,随密度膨胀,ARP/广播
默认在沙箱间穿越;OVS/OVN 功能完备但流表查找/upcall 开销大,fast-path 之外仍需常驻
守护进程;逐 VM veth + 自定义脚本把隔离与路由策略散落在 iptables 里,难以审计。

vswitch 把全部转发判定集中在一份 ~1K 行的 eBPF C 程序里,控制面只在 attach/detach 时
操作内存映射的 BPF map。选择 eBPF/TC 的直接收益:

- 转发零拷贝、零上下文切换,完全在内核完成;
- TC 程序与 BPF map 持久化在 bpffs,控制面进程退出/崩溃后数据面无中断;
- 一份 C 程序即完整转发逻辑,比散落在 nftables 链 + bridge fdb 中更易推理与审计;
- BPF map 天然支持 per-CPU 计数与 `bpftool` 调试。

### 1.2 设计原则

1. **强隔离**:沙箱间不可见(无 port→port 转发路径);ARP 全代答;MAC 由交换机分配并
   在出口改写。
2. **无状态转发**:eBPF 程序不维护连接表,所有判定基于 slot 配置 + IP/UDP 端口算术。
3. **进程生命周期与数据面解耦**:`start`/`attach`/`detach` 返回后用户态退出,转发由
   内核 eBPF 持续执行。
4. **并发安全**:attach/detach 跨进程并发不需要全局互斥,依赖 mmap + 原子 CAS;复合
   控制操作经 flock 串行化。
5. **可观测**:per-port、per-direction、per-class(mgmt/transit)流量计数;状态查询用
   Kubernetes Conditions 风格。
6. **systemd-native**:`Type=notify` 集成,watchdog keepalive,崩溃重启后经 bpffs
   重新挂接。

### 1.3 边界

- 单 transit 上行设备;外部 ECMP/链路绑定由上游网络处理。
- 不做数据面限速/QoS,委托给 VMM、TC qdisc 或 cgroup BPF。
- 不做连接跟踪/NAT 状态表/L7 过滤,只做无状态二层/三层封装与代答。
- 管理平面(`--mgmt-extract`/`--mgmt-service`)在 `start` 时固化,变更需重建交换机。
- `MAX_PORTS = 4096` 在 BPF C 中编译期固定。
- 单机控制面,不做跨宿主机同步;每台宿主一个独立实例。

### 1.4 部署形态

```
                            ┌─────────────────────┐
                            │  mgmt / metadata    │
                            │  169.254.169.254    │  (mgmt netns)
                            └──────────┬──────────┘
                                       │
                          ┌────────────┴────────────┐
                          │   connector       │
                          │   ┌─────────────────┐   │
   microVM #1 ───── tap ──┤   │ eBPF on TC      │   │── transit dev ── GENEVE ──▶ gateway
   microVM #2 ──── veth ──┤   │ ingress (shared │   │
   ...                    │   │ block, 4096)    │   │
   microVM #N ──── veth ──┤   └─────────────────┘   │
                          └─────────────────────────┘
```

适用:单宿主机高密度 microVM 平台(Firecracker、Cloud Hypervisor、QEMU/KVM),每个 VM
需要受控网络出口,整体规模不超过 4K 并发实例。不适用:跨宿主机分布式 SDN、需要细粒度
L4+ 策略的多租户控制面、需要连接跟踪/L7 过滤的安全网关。

## 2. 命令行接口

所有命令默认输出 JSON。运行需要 root(`CAP_SYS_ADMIN` + `CAP_NET_ADMIN`,见 §7.3)。

### 2.1 子命令总览

| 命令 | 用途 |
| --- | --- |
| `start [switch_name]` | 创建并启动交换机(StartReserved + 同步 ProvisionPorts),返回后用户态退出 |
| `serve [switch_name]` | systemd `Type=notify` 长驻:StartReserved → tapfd listen(可选) → READY=1 → 后台 ProvisionPorts → 健康检查循环 |
| `stop <name>` | 卸载 eBPF、删除 pinned maps、删除 veth/tap、把 transit 设备还回原 netns |
| `attach <name>` | 分配端口(CAS Free→IP);veth 模式可把端口设备移入沙箱 netns |
| `detach <name> --port=N` | 释放端口(CAS IP→Free) |
| `reserve <name> --port=N` | 把端口标记为 Reserved,阻止后续 attach(升级/排空) |
| `provision <name>` | 为 Reserved slot 创建端口设备;支持批量与单点修复 |
| `open-port <name> --port=N` | 打开 tap 端口的队列 fd,经 `TAPFD_SOCKET` 递交 consumer([tapfd.md](tapfd.md) §3 的 provider helper) |
| `status <name>` | 交换机状态(Conditions);`--ready` 以退出码表达 |
| `stats <name>` | per-port 流量计数(mgmt/transit × rx/tx × packets/bytes) |
| `show slots\|config <name>` | dump slot 表 / in-kernel 配置 |
| `dhcp request\|serve` | 内嵌 DHCP 客户端/服务器(调试与测试场景) |

典型流程(tap 模式,默认):

```bash
# 创建交换机
connector-ctl vswitch start sw1 --netns=sw_ns --ports=128 \
    --mac-addr=02:00:00:00:00:01 --floating-ip-base=100.100.96.0 \
    --mgmt-extract=mgmt_ns:eth0:169.254.169.254/32 \
    --transit-dev=eth1 --transit-dev-addr=10.0.0.1/24:10.0.0.2

# 分配端口,把 tap fd 交给等在 /tmp/recv.sock 的 VMM
connector-ctl vswitch attach sw1 --inner-ip=169.254.1.1 \
    --transit-gateway-ip=10.0.0.2 --transit-geneve-vni=100
TAPFD_SOCKET=/tmp/recv.sock connector-ctl vswitch open-port sw1 --port=1

# 释放端口、停止交换机
connector-ctl vswitch detach sw1 --port=1
connector-ctl vswitch stop sw1
```

### 2.2 `connector-ctl vswitch start` / `serve`

`start` 同步完成全部初始化后退出;`serve` 用于 systemd `Type=notify` 长驻(§6.5)。
`switch_name` 可省略,从 `--config` 文件(§2.14)读取。

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `--netns` | ✓ | 交换机内部 netns(必须已存在) |
| `--mac-addr` | ✓ | 虚拟 MAC base,前 4 字节用于派生所有 MAC(§6.1) |
| `--ports` | ✓ | 端口数(1–4096) |
| `--floating-ip-base` | ✓ | floating IP 基地址(按 slot_id 递增) |
| `--port-netns` | veth 模式 ✓ | 端口设备初始 netns;tap 模式或 `--reserved` 下可省 |
| `--mode` | – | 自动 provision 的端口类型:`tap`(默认)或 `veth`;配合 `--reserved` 时仅作参数校验提示,不持久化 |
| `--mgmt-extract` | – | 管理平面定义 `<netns>:<dev>:<route1>,<route2>,...`,可重复(每 slot 最多 3 条路由);`<netns>` 留空(`:<dev>:<routes>`)则 mgmt veth peer 留在调用方/主机 netns |
| `--mgmt-service` | – | 管理服务地址转换 `<VIP>:<vport>:<targetIP>:<targetPort>`,可重复;VIP 须落在某条 `--mgmt-extract` 路由内,`(targetIP,targetPort)` 须全局唯一,TCP/UDP 均转换(§4.3);loopback target 需 mgmt 设备 `route_localnet=1` |
| `--transit-dev` | – | 外部上行设备,start 时从调用 netns 移入 switch netns;必须处于 **DOWN**(防止接管在用网卡) |
| `--transit-dev-addr` | – | `<ip>/<prefix>:<nexthop>` 或 `auto`(DHCP,§6.9) |
| `--transit-dev-mtu` | – | `auto` 或具体数值;默认不修改,仅校验(§6.8) |
| `--geneve-port-base` | – | GENEVE UDP 端口基值(默认 50000) |
| `--geneve-encap-eth` | – | 启用 Ether-over-GENEVE(默认 IP-over-GENEVE) |
| `--mtu` | – | 所有 port/mgmt veth 的 MTU;默认保留内核默认值 |
| `--port-mac-addr` | – | `fixed`(默认)/`per-port`/具体 MAC(§6.1) |
| `--reserved` | – | 仅做 StartReserved,不自动 ProvisionPorts。port-netns 由 start 写入交换机配置、`provision` 无独立 flag 覆盖,故计划用 veth 端口时 start 仍需给 `--port-netns` |
| `--config` | – | 从 JSON 文件读取以上参数(§2.14) |

`serve` 复用 `start` 的交换机参数,差异:无 `--reserved` flag,另有:

| 参数 | 说明 |
| --- | --- |
| `--watch-interval` | 健康检查间隔,默认 30s |
| `--tapfd-listen` | 持久 vswitch/tapfd UDS。支持 `TAPFD/1 PREPARE` / `OPEN` / `RELEASE`;`OPEN` 返回 `TAPFD/1 OK` + metadata + SCM_RIGHTS;详见 [tapfd.md](tapfd.md) §4 |

`start` 输出:

```json
{
  "switch": "sw1",
  "switch_netns": "netns_switch",
  "switch_maps": {
    "slots":           "/sys/fs/bpf/sw1/slots",
    "config":          "/sys/fs/bpf/sw1/config",
    "stats":           "/sys/fs/bpf/sw1/stats",
    "ifindex_to_slot": "/sys/fs/bpf/sw1/ifindex_to_slot",
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
  "geneve_port_base": 50000
}
```

`mgmt_services` 仅在配置了 `--mgmt-service` 时出现;`status` 与 `show config` 同样
回显 `mgmt_planes`/`mgmt_services`(取自 metadata map)。

### 2.3 `connector-ctl vswitch stop`

卸载 eBPF 程序、删除 pinned maps、删除 veth/tap/dummy 设备、把 transit 设备还回原
netns。内部分两步 `ReleasePorts` + `StopReleased`。

| 参数 | 说明 |
| --- | --- |
| `--force` | 先释放所有 in-use 端口再 stop(两轮清理),用于强制关停 |
| `--force-clean` | 损坏交换机救场:仅 unpin BPF 资源,跳过设备清理;可能留下需手工删除的孤儿 netdev |

### 2.4 `connector-ctl vswitch attach`

分配端口:CAS Free→IP;veth 模式可同时把端口设备移入沙箱 netns。端口未 provision 时
返回 `port not provisioned`,调用方应重试(§6.5)。

| 参数 | 说明 |
| --- | --- |
| `--inner-ip=IP` | 沙箱内部 IP(必填) |
| `--port=N` | 指定槽位(省略则自动分配) |
| `--to-netns=NS` | 把端口设备移入目标 netns(仅 veth 模式) |
| `--transit-gateway-ip=IP` | GENEVE 外层目标 IP |
| `--transit-geneve-vni=N` | GENEVE VNI |
| `--transit-mac-addr=MAC` | Ether-over-GENEVE 内层目标 MAC(省略则广播) |
| `--skip-device` | 跳过设备 netns 移动,仅做 CAS;仅 veth 模式可用,tap slot 拒绝 |
| `--open-port` | tap 模式:CAS 成功后立即经 `TAPFD_SOCKET` 递交 fd(合并 attach + open-port);`SCM_RIGHTS` 失败时回滚 CAS 分配 |

`attach` 输出(veth 模式):

```json
{
  "port": 4, "port_dev": "sw1-p4", "port_netns": "sandbox_ns_4",
  "port_mac": "02:00:00:00:80:01",
  "inner_ip": "169.254.1.1",
  "floating_ip": "100.100.96.3",
  "transit_type": "overlay-geneve",
  "geneve_port": 50003,
  "transit_gateway_ip": "10.200.12.1",
  "transit_geneve_vni": 1004
}
```

`attach --open-port` 输出(合并形式):

```json
{
  "port": 4, "port_dev": "sw1-t4",
  "port_mac": "02:00:00:00:80:01",
  "inner_ip": "169.254.4.1",
  "tap_sent_to": "/tmp/recv.sock"
}
```

### 2.5 `connector-ctl vswitch detach`

释放端口:CAS IP→Free。tap slot 无设备操作;veth slot 给 `--from-netns` 则把设备移回
port netns,省略则校验设备已在 port netns。

| 参数 | 说明 |
| --- | --- |
| `--port=N` | 槽位编号(必填) |
| `--from-netns=NS` | 端口设备当前所在的沙箱 netns(veth 模式) |
| `--skip-device` | 跳过设备移动/校验(veth/tap 均可) |

### 2.6 `connector-ctl vswitch reserve`

把端口标记为 Reserved,阻止后续 attach;用于升级/排空,或为 `provision --mode` 切换
端口类型做准备(§6.6)。

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `--port=N` | ✓ | 槽位编号(1-based) |
| `--force` | – | 允许覆盖 Allocated → Reserved(默认仅 Free → Reserved) |

### 2.7 `connector-ctl vswitch provision`

为 Reserved slot 创建端口设备并使其对 attach 可见。幂等:Free/Allocated slot 跳过,
失败的 Reserved slot 保留状态,可单点修复。

| 参数 | 说明 |
| --- | --- |
| `--port=N` | 仅处理指定槽位(单点修复);与 `--count` 互斥 |
| `--count=N` | 限制本次创建的设备数(0 = 全部);与 `--port` 互斥 |
| `--mode=tap\|veth` | 端口类型(默认 `tap`);在 Reserved slot 上切换类型时先建新设备、commit 新 ifindex、再删旧设备 |

### 2.8 `connector-ctl vswitch open-port`

[tapfd.md](tapfd.md) §3 动态获取契约的 provider helper:进入 switch netns,对持久 tap
执行 `open(/dev/net/tun)` + `TUNSETIFF(IFF_TAP|IFF_NO_PI|IFF_VNET_HDR)`,把队列 fd 连同
元数据经 `SCM_RIGHTS` 发往 `TAPFD_SOCKET` 指定的套接字(`fd=N` 或路径,tapfd.md §3.3)。
环境变量 `TAPFD_WANT_NETNS` 为真值时在 tap fd 后追加 switch netns fd 并置
`netns_fd=1`(tapfd.md §3.4)。

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `--port=N` | ✓ | tap 槽位编号(1-based) |

前置条件:slot 为 tap 类型、已 provision(`ifindex != 0`)、已 attach(inner IP 为
真实 IP)——任一不满足在触碰套接字/tap 之前即拒绝。交换机未运行时退出码 `3`。

```bash
# VMM 侧先监听: socat UNIX-LISTEN:/run/vm1.sock,fork ...
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

### 2.9 `connector-ctl vswitch status`

输出交换机 JSON 状态,Conditions 风格:`Ready`、`PortDevicesReady`、
`MgmtDevicesReady`、`TransitDeviceReady`;ProvisionPorts 未完成(或
`start --reserved` 之后)还会出现 `PortReserved`。

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

ProvisionPorts 完成前的过渡形态:

```json
"conditions": [
  { "type": "Ready",        "status": "False", "reason": "PortsReserved" },
  { "type": "PortReserved", "status": "True",
    "message": "all 4096 ports still in Reserved state (ProvisionPorts pending)" }
]
```

### 2.10 `connector-ctl vswitch stats`

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

### 2.11 `connector-ctl vswitch show`

- `show slots <name> [slot_id]` — dump slot 表为 JSON(单槽或全部)。
- `show config <name>` — dump in-kernel `switch_config`,并附 metadata 中的
  `transit_dev`/`mgmt_planes`/`mgmt_services`。

### 2.12 `connector-ctl vswitch dhcp`

内嵌 DHCP 客户端与服务器,服务于 transit `auto` 寻址的调试与 e2e 测试拓扑。

- `dhcp request --dev=<iface> [--timeout=5s] [--retries=3]` — 在指定设备上跑一次
  DHCP 并打印结果。
- `dhcp serve --dev=<iface> --server-ip=<ip> --pool=<a.b.c.d-a.b.c.e>
  [--gateway=<ip>] [--dns=<ip,...>] [--lease-time=1h]` — 简易 DHCP 服务器,
  `--gateway` 默认取 `--server-ip`。

### 2.13 `connector-ctl tapfd get`

与交换机无关的tapfd provider 子命令(单独二进制):打开一个 tap 设备,把其
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
随之消失(对比 vswitch 端口的持久 tap,§6.6)。

### 2.14 配置文件(`--config`)

`start`/`serve` 接受 JSON 配置文件,字段与同名 flags 一一对应:

| 字段 | 对应 flag |
| --- | --- |
| `switch_name` | positional `switch_name` |
| `switch_netns` | `--netns` |
| `port_netns` | `--port-netns` |
| `num_ports` | `--ports` |
| `mac_addr` | `--mac-addr` |
| `floating_ip_base` | `--floating-ip-base` |
| `mgmt_extracts` (数组) | `--mgmt-extract` |
| `mgmt_services` (数组) | `--mgmt-service` |
| `transit_dev` / `transit_dev_addr` / `transit_dev_mtu` | `--transit-dev*` |
| `geneve_port_base` / `geneve_encap_eth` | `--geneve-*` |
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
  "transit_dev_mtu": "auto"
}
```

## 3. 部署

### 3.1 系统要求

- Linux **5.10+**(BTF + TC BPF);BTF 可访问于 `/sys/kernel/btf/vmlinux`。
- bpffs 挂载在 `/sys/fs/bpf`(`mount -t bpf bpf /sys/fs/bpf`)。
- 运行:root 或 `CAP_SYS_ADMIN + CAP_NET_ADMIN`(§7.3)。
- 构建:**Go 1.24+**;重新生成 eBPF 字节码额外需 **Clang/LLVM 12+**。

### 3.2 构建

```bash
make build                      # 产物: bin/<arch>/connector-ctl(并在 bin/ 建同名软链)
make build TARGET_ARCH=aarch64  # 交叉编译(纯 Go,无需交叉工具链);别名 amd64 / arm64
make release                    # 打包: build/dist/connector-<ver>-linux-<arch>.tar.gz
make generate                   # 仅修改 bpf/*.c 时需要(clang 12+);仓库自带预生成 .o
make test                       # 单元测试
sudo make test-integration      # 集成测试(root + BPF 内核)
sudo make test-e2e              # 端到端(examples/*_test.sh all)
sudo make bench                 # 性能基准(root + iperf3)
make lint / make fmt            # go vet / go fmt + clang-format
make vmlinux                    # 重新生成 bpf/vmlinux.h(需 bpftool)
```

### 3.3 systemd 集成

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
ExecStartPre=...   # 2) 交换机尚未存在时等待 ${TRANSIT_DEV} 出现(最多 120 s)
ExecStart=/usr/sbin/connector-ctl vswitch serve ${SWITCH_NAME} --netns=... --mode=... ...
ExecStartPost=...  # 对 ${SWITCH_NAME}_m0 开 route_localnet(容许 loopback 的 mgmt-service target)
Restart=on-failure
LimitMEMLOCK=infinity
```

两个 `ExecStartPre`:第一个幂等地创建命名空间;第二个在交换机尚未存在时等待
`${TRANSIT_DEV}` 出现(例如等内核驱动加载完毕)。`ExecStartPost` 在 mgmt 设备上开启
`net.ipv4.conf.<dev>.route_localnet`,使 `--mgmt-service` 可指向 loopback target。

**Host-netns 管理平面**:把 `MGMT_NETNS=` 留空(mgmt/metadata 服务直接跑在 host 上)
时,生成的 `--mgmt-extract=:<dev>:<routes>` 让 mgmt veth peer 留在调用方 netns,
第一个 `ExecStartPre` 也会自动跳过空值,无需手动创建 mgmt netns。

### 3.4 首次启动

1. 识别 transit 网卡(`ip -br link`),编辑 `/etc/connector/switch.conf`
   (`TRANSIT_DEV`/`TRANSIT_DEV_ADDR` 等)。
2. 确保 transit 处于 DOWN:`ip link set "$TRANSIT_DEV" down`(service 会把它移入
   switch netns)。
3. `sudo systemctl start connector`。
4. 验证:`systemctl status connector` 为 active;
   `connector-ctl vswitch status sw0 --ready` 退出 0;`ip netns list` 列出所配置的命名空间。
5. `sudo systemctl enable connector`。

## 4. 网络架构

### 4.1 拓扑与设备命名

```
 sandbox netns (one per sandbox)        switch netns                      mgmt netns (optional)
┌──────────────┐                ┌─────────────────────────────────┐     ┌─────────────────────┐
│  sw1-p1      │◀── veth pair ──│─▶ sw1-n1 ──┐                    │     │ eth0 (mgmt dev)     │
└──────────────┘                │            │                    │     │ mgmt service        │
┌──────────────┐                │    ...     │  eBPF TC ingress   │     │ 169.254.169.254     │
│  sw1-p2      │◀── veth pair ──│─▶ sw1-n2 ──┤  shared block 100  │     └──────────▲──────────┘
└──────────────┘                │            │  anchor: sw1-dummy │                │
                                │  sw1-t3 ───┘   │           │    │                │
   VMM ◀──── tap fd ────────────│── (tap mode)   ▼           │    │                │
        (SCM_RIGHTS handoff)    │             sw1-m0 ◀───────┼────┼─── veth pair ──┘
                                │                            ▼    │
                                │              transit dev ═══════╪══ GENEVE ══▶ gateway
                                └─────────────────────────────────┘
```

设备命名约定 `<switch-name>-{p,n,m,t}<id>`:`sw1-p7`(沙箱端 veth)/`sw1-n7`(交换机端
veth)/`sw1-m0`(管理端)/`sw1-t7`(持久 tap)。`<sw>-dummy` 是一个无 IP 的 dummy
设备,持有 TC shared block 100 上的 BPF filter 引用(StartReserved 创建、Stop 删除),
让 filter 在所有端口设备都未挂载时仍存活。所有沙箱端设备共用 `ingress_block=100`,
BPF 程序经 `skb->ingress_ifindex` 在程序内部分派 slot。

### 4.2 netns 布局

| netns | 用途 | 包含的设备 |
| --- | --- | --- |
| `netns_switch` | 交换机内部网络 | `<sw>-nX`、`<sw>-mX`、`<sw>-tX`(tap 模式)、`<sw>-dummy`、transit 设备 |
| `netns_ports` | 沙箱端口的初始位置(veth 模式) | `<sw>-pX`,attach 后移入沙箱 netns |
| `netns_mgmt` | 管理服务所在网络 | 管理网卡(如 `eth0`);可省略——mgmt veth peer 留在调用方/主机 netns |
| 沙箱 netns | 沙箱自身 | `<sw>-pX`(veth 模式,从 `netns_ports` 移入) |

### 4.3 数据包流向

**沙箱 → 管理服务**(如 `169.254.169.254`):

```
sandbox(src=169.254.1.1, dst=169.254.169.254)
  → sw-pX → sw-nX
  → [TC: match mgmt_cidrs[]; SNAT src→floating_ip; stats.mgmt_tx++]
  → sw-mX → eth0
  → mgmt service (sees src=100.100.96.X)
```

**管理服务 → 沙箱**:

```
mgmt(src=169.254.169.254, dst=floating_ip)
  → eth0 → sw-mX
  → [TC: slot_id = dst − floating_ip_base;
         DNAT dst→inner_ip; h_dest = derived port MAC; stats.mgmt_rx++]
  → sw-nX → sw-pX → sandbox
```

**回程路由(mgmt netns 内)**:管理服务回包目的为 floating IP,必须经 `sw-mX` 才能被
TC DNAT 回沙箱。`start` 在每个 mgmt netns 内安装**限定在 floating 段的定向路由**而非
默认路由——固定 /20(等于 floating 段最大容量 4096),以 `floating_ip_base` 所在 /20
为准,metric=`100+index`:

```
ip route add <floating_ip_base>/20 dev <mgmt-dev> metric <100+index>
```

这样不会劫持 mgmt netns 的默认出向流量(`<netns>` 留空 = host netns 时不污染主机默认
路由)。`floating_ip_base` 不要求 /20 对齐:不对齐时该段跨两个相邻 /20,两条都装;
相邻 /20 中未被 floating 使用的目的地址会被引向 mgmt 设备,但 TC 不匹配 floating 段
即丢弃。

**管理服务地址转换(`--mgmt-service`,可选)**:`--mgmt-extract` 只改写源/目的中的
inner_ip↔floating_ip,目的 IP/端口保持不变——管理服务必须真的监听在 VIP 上。
`--mgmt-service=<VIP>:<vport>:<targetIP>:<targetPort>` 在此之上叠加一层带端口的、
确定性的、无状态 NAT,让后端监听在 `targetIP:targetPort` 即可,沙箱仍按 VIP 访问。
两个方向对称改写,只对 TCP/UDP 生效(其它协议走原 mgmt 路径):

```
egress   sandbox(src=inner, dst=VIP:vport)
  → sw-nX → [TC: match mgmt_cidrs[]; SNAT src→floating_ip;
                 mgmt_svc_fwd hit → DNAT dst:vport→targetIP:targetPort]
  → sw-mX → backend on targetIP:targetPort (sees src=floating_ip)

ingress  backend(src=targetIP:targetPort, dst=floating_ip:sport)
  → sw-mX → [TC: slot_id = dst − floating_ip_base; DNAT dst→inner_ip;
                 mgmt_svc_rev hit → SNAT src:targetPort→VIP:vport]
  → sw-nX → sandbox (sees src=VIP:vport)
```

映射来自 `start` 固化的静态配置,TC 侧无连接跟踪:出向查 `mgmt_svc_fwd`
(`{VIP,vport,proto}→{targetIP,targetPort}`),入向查 `mgmt_svc_rev`
(`{targetIP,targetPort,proto}→{VIP,vport}`),各 O(1)。未命中 service 表的 VIP 流量
走原 mgmt 路径。约束:每个 VIP 须落在某条 `--mgmt-extract` 路由内(否则选不出 mgmt
设备);每个 `(targetIP,targetPort)` 全局唯一(入向反查 key);仅 IPv4。改写后 target
在 mgmt netns 内的可达性由部署侧保证:loopback target 需在 mgmt 设备上开
`net.ipv4.conf.<dev>.route_localnet=1`(随仓 systemd 单元已处理,§3.3),否则内核按
martian 丢弃。

**沙箱 → 外部网络**(GENEVE 封装):

```
sandbox(dst=8.8.8.8)
  → sw-pX → sw-nX
  → [TC: no mgmt_cidrs match; GENEVE encap; inner src=port MAC, dst=transit MAC;
         stats.transit_tx++]
  → transit dev
  → outer src=transit_ip, dst=gateway_ip; UDP src=hash(5-tuple), dst=base+slot_id; VNI
  → gateway
```

**外部网络 → 沙箱**(GENEVE 解封装):

```
gateway → GENEVE packet (UDP dst = geneve_port_base + slot_id)
  → transit dev
  → [TC: slot_id = UDP_dst − geneve_port_base; verify outer src == transit_gateway_ip;
         verify VNI; decap; h_dest = derived port MAC; stats.transit_rx++]
  → sw-nX → sw-pX → sandbox
```

**关键不变量**:

- 转发判定 key 自始至终是 `slot_id`,从入口 ifindex / floating_ip / geneve_port 三者
  之一推导;永不信任沙箱报文里的源 IP/源 MAC。
- `h_dest` 在解封装/转发回沙箱时被重写为派生的 port MAC,与端口设备 MAC 精确一致,
  保证内核接收。

## 5. 数据面

### 5.1 eBPF 程序挂载点

| 设备 | 挂载点 | 程序 | 功能 |
| --- | --- | --- | --- |
| `<sw>-nX` | TC ingress(shared block 100) | `tc_ingress_nx` | ARP 代答;管理流量提取 + SNAT(含可选 service DNAT);GENEVE 封装;统计 mgmt_tx/transit_tx |
| `<sw>-mX` | TC ingress | `tc_ingress_mx` | ARP 代答;floating→inner DNAT(含可选 service 反向 SNAT);投递;统计 mgmt_rx |
| transit 设备 | TC ingress | `tc_ingress_transit` | GENEVE 解封装;外层源 IP 与 VNI 校验;投递;统计 transit_rx |

GENEVE 内层同时识别 IPv4 与 IPv6(管理平面与 `slot.inner_ip` 为 IPv4)。

### 5.2 Pinned maps(`/sys/fs/bpf/<sw>/`)

| map | 类型 | 规格 | nx | mx | transit | 内容 |
| --- | --- | --- | --- | --- | --- | --- |
| `slots` | ARRAY + MMAPABLE | 4096 × 112 B | R | R | R | per-slot 配置;用户态 mmap 后对 `inner_ip` 做原子 CAS 完成分配/释放(§6.3) |
| `config` | ARRAY | 1 × 40 B | R | R | R | `switch_mac`/`n_ports`/`floating_ip_base`/`geneve_port_base`/`geneve_encap_eth`/`transit_nexthop`/`port_mac` |
| `metadata` | ARRAY | 1 × 4096 B | – | – | – | JSON 编码的 `SwitchMetadata`,仅用户态读写;新增字段无需重编译 BPF |
| `stats` | PERCPU_ARRAY | 4096 | W | W | W | per-slot `mgmt_{rx,tx}` + `transit_{rx,tx}` 包/字节计数,沙箱视角;attach 时清零,detach 保留 |
| `ifindex_to_slot` | HASH | – | R | – | – | 入口 ifindex → slot_id 反查,仅出方向无法用 IP/UDP 推导时使用 |
| `mgmt_svc_fwd` | HASH | 可选 | R | – | – | `{VIP,vport,proto}→{targetIP,targetPort}`,每条 service 按 TCP/UDP 各一条 |
| `mgmt_svc_rev` | HASH | 可选 | – | R | – | `{targetIP,targetPort,proto}→{VIP,vport}` |

索引计算原则:`slot_id` 由算术得到(`dst_ip − floating_ip_base` 或
`udp_dst − geneve_port_base`),避免 hash map 查找。

### 5.3 数据面 ABI

直接以字节偏移读写下列 C 结构的 Go 代码全部隔离在 `pkg/internal/`(§11):字段偏移
变动等同 ABI 变更,Go 与 BPF 两侧必须同步。

```c
struct slot_item {                          // 108 字节,cache-line 优化
    // ── cache line 0 (hot path) ─────────────────────────────────
    __u32 ifindex;                          // offset  0
    __u32 inner_ip;                         // offset  4 — 0=Free, 0xFFFFFFFF=Reserved, 其他=Allocated
    __u32 transit_ifindex;                  // offset  8
    __u32 transit_ip;                       // offset 12
    __u32 transit_gateway_ip;               // offset 16
    __u32 transit_geneve_vni;               // offset 20
    __u8  transit_mac[6];                   // offset 24
    __u8  mode;                             // offset 30 — 0=veth, 1=tap(用户态元数据,BPF 不读)
    __u8  _pad_mac;                         // offset 31
    __u32 mgmt_cidr_count;                  // offset 32
    struct mgmt_cidr mgmt_cidrs_0;          // offset 36 (20B) — 内联第一条(热路径)
    __u8  _pad_cl0[8];                      // offset 56
    // ── cache line 1 (cold path) ────────────────────────────────
    struct mgmt_cidr mgmt_cidrs_ext[MAX_MGMT_CIDR_EXT]; // offset 64 (40B)
    __u8  _pad_cl1[4];                      // offset 104
};   // 108 字节;mmap 后按 8 对齐 → 112 字节/槽 → 4096 槽 ≈ 448 KB

struct switch_config {                      // 40 字节
    __u8  switch_mac[6];
    __u16 _pad;
    __u32 n_ports;
    __u32 floating_ip_base;
    __u32 geneve_port_base;
    __u8  geneve_encap_eth;
    __u8  _pad3[3];
    __u32 transit_nexthop;
    __u8  port_mac[6];                      // 全零 → 派生;非零 → 固定
    __u8  _pad4[2];
    __u8  _pad5[4];
};

struct slot_stats {                         // per-CPU
    __u64 mgmt_rx_packets, mgmt_rx_bytes;
    __u64 mgmt_tx_packets, mgmt_tx_bytes;
    __u64 transit_rx_packets, transit_rx_bytes;
    __u64 transit_tx_packets, transit_tx_bytes;
};
```

每个程序入口都有显式边界检查(verifier-friendly):ETH header 长度;IPv4 `ihl == 5`
或 IPv6 fixed header;decap 长度 `< skb->len`;slot 有效性(`inner_ip != 0`、
`ifindex != 0`);`slot_id < n_ports`;transit decap 校验外层源 IP 与 VNI。

## 6. 关键机制

### 6.1 MAC 派生

交换机使用统一 MAC 命名空间,所有 ARP 代答 MAC 和设备 MAC 都从用户提供的
`switch_mac` 派生。派生公式 `SS:SS:SS:SS:BB:LL`:

- byte0..3 = `switch_mac[0..3]`
- **byte4 (BB)** = `((switch_mac[4] ^ 0x80) & 0x80) | (id >> 8)`
- **byte5 (LL)** = `id & 0xFF`

其中沙箱端口 `id = slot_id`(`0x000`–`0xFFF`),管理网卡 `id = 0x7FF0 + mgmt_idx`。
派生 MAC 的 byte4 MSB 始终是 `switch_mac[4]` MSB 的反位,故派生 MAC 与 `switch_mac`
不冲突,对 `switch_mac` 没有输入约束;slot_id 高 4 位放在 byte4 低 4 位,正好支撑
4096 端口。Go 与 BPF 按相同公式各自重算,改公式两侧必须同步。

`--port-mac-addr` 决定端口设备 MAC:

| 模式 | 端口 MAC | 适用场景 |
| --- | --- | --- |
| `fixed`(默认) | 按 `slot_id=1` 派生,所有端口共享同一 MAC | 快照恢复:microVM 可落到任意空闲 slot,无需在 VM 内重配网络 |
| `per-port` | 按各自 `slot_id` 派生,每端口唯一 | 测试/需要网关侧按 MAC 区分 |
| 显式 MAC | 用户指定,所有端口共享 | 特殊兼容需求 |

### 6.2 GENEVE 隧道

封装模式(解封装按 `geneve->proto_type` 自动识别,无须配置):

| 模式 | `proto_type` | 内层 | 用途 |
| --- | --- | --- | --- |
| **IP-over-GENEVE**(默认) | `ETH_P_IP`/`ETH_P_IPV6` | 裸 IP 报文 | 省 14 字节;适合 vswitch-to-vswitch |
| **Ether-over-GENEVE** | `ETH_P_TEB`(0x6558) | 完整以太网帧 | 兼容标准 Linux GENEVE 设备/网关桥接 |

端口方案——不使用标准 GENEVE 端口 6081,每个沙箱独享一个 UDP 端口:

- 出方向:`UDP src = hash(inner 5-tuple)`,`UDP dst = geneve_port_base + slot_id`;
- 入方向:`slot_id = UDP_dst − geneve_port_base`,O(1) 算术,无 hash map 查找;
- UDP 源端口用 Jenkins one-at-a-time 哈希内层 5-tuple 映射到 49152–65535,让底层网络
  能在外层 UDP 源端口上做 ECMP/RSS。

L2 寻址:外层以太网由 `bpf_redirect_neigh` 经内核邻居子系统解析,eBPF 程序不维护
ARP 缓存;内层(仅 Ether-over-GENEVE)目标 MAC 取 `--transit-mac-addr`(未指定则
广播),源 MAC 为派生端口 MAC,与端口设备一致,便于网关侧网桥 L2 学习。

### 6.3 slot 分配与状态机

并发 attach 下,BPF map 的 Lookup + Update 是两次 syscall,经典 TOCTOU:两个进程同时
读到 slot 空闲,后写者覆盖先写者。解决:`slots` map 启用 `BPF_F_MMAPABLE`,用户态把
整个 array mmap 进进程,对 `inner_ip` 字段做 `atomic.CompareAndSwapUint32`——单 slot
分配/释放无须任何锁。

```
inner_ip = 0x00000000          → Free        port allocatable
inner_ip = 0xFFFFFFFF          → Reserved    after StartReserved / reserve
inner_ip = <real IP>           → Allocated   attached

StartReserved          ProvisionPorts            Attach              Detach
[Free] ─CAS(0→0xFFFF)─▶ [Reserved] ─CAS(0xFFFF→0)─▶ [Free] ─CAS(0→IP)─▶ [Allocated]
                                                                          │
                                                  [Free] ◀─CAS(IP→0)──────┘

reserve --port=N [--force]:
   [Free]      ─CAS(0→0xFFFF)──▶ [Reserved]
   [Allocated] ─CAS(IP→0xFFFF)─▶ [Reserved]   (--force only)
```

| 操作 | 语义 | CAS |
| --- | --- | --- |
| Attach | Free → Allocated | `CAS(inner_ip, 0, innerIP)` |
| Detach | Allocated → Free | `CAS(inner_ip, currentIP, 0)` |
| Reserve | Free → Reserved | `CAS(inner_ip, 0, 0xFFFFFFFF)` |
| Provision 完成 | Reserved → Free | `CAS(inner_ip, 0xFFFFFFFF, 0)` |

CAS 失败的进程回滚已做的中间状态(如设备移动),不留半分配 slot。

### 6.4 控制操作互斥

CAS 只保证单 slot 原子;多 slot/多资源的复合控制操作经 `flock(LOCK_EX)` 在 bpffs pin
目录 `/sys/fs/bpf/<sw>/` 上互斥:

| 操作 | flock | CAS |
| --- | --- | --- |
| Start(StartReserved) | ✓ | ✓(所有 slot 置 Reserved) |
| Stop / `stop --force` | ✓ | – |
| ProvisionPorts | ✓ | ✓(逐槽 Reserved→Free) |
| Attach / Detach / Reserve | – | ✓(轻量,无锁) |

### 6.5 两阶段启动

为支持 systemd `Type=notify` 与快速冷启动,`start` 拆为两阶段。

**阶段 1 — StartReserved(~100 ms)**:校验配置;加载 eBPF objects;pin maps/programs
到 bpffs;写 `config` 与 `metadata`(`--transit-dev-addr=auto` 的 DHCP 在此执行);
mmap `slots` 并把所有 slot CAS 置 Reserved;创建 `<sw>-dummy`(block anchor);创建
管理平面(veth + TC + mgmt netns 配置,含 `mgmt_svc_*` 表写入);配置 transit 设备
(移入 switch netns、MTU、IP、up)。完成后交换机可响应 `status`,但 attach 全部失败
(slot 处于 Reserved)。

**阶段 2 — ProvisionPorts(耗时主体)**:遍历 Reserved slot——创建 veth pair(或持久
tap)、挂 TC ingress(shared block 100)、一次性写入 slot 全部字段、CAS Reserved→Free
使端口对 attach 可见。幂等:Free/Allocated 跳过;失败的 slot 保留 Reserved,可
`provision --port=X` 单点修复。

`serve` 的 systemd 集成:

```
serve:
  1. StartReserved()              ─── ~100 ms
  2. sd_notify(READY=1)           ← systemd marks the service ready
  3. go ProvisionPorts()          ─── async port device creation
  4. main loop:
       periodic health check (status conditions)
       sd_notify(WATCHDOG=1) keepalive
       SIGTERM / SIGINT → exit (data plane unaffected)
```

依赖交换机的服务在 READY=1 后即可启动,不必等所有端口创建完毕;端口尚未 provision 时
attach 返回 `port not provisioned`,调用方重试即可。

### 6.6 端口模式:veth 与 tap

每个 slot 在 `slot_item.mode` 记录端口类型。该字段纯属用户态元数据,BPF 数据面不读——
两种模式数据路径完全相同(同样的 TC ingress 程序,同样按 ifindex 路由),差别只在
控制面走哪条 attach/detach/open-port 逻辑。

|  | **veth**(`mode=0`) | **tap**(`mode=1`,CLI 默认) |
| --- | --- | --- |
| 交换机端设备 | `<sw>-nX`(veth 对端) | `<sw>-tX`(持久 tap,`TUNSETPERSIST`) |
| 沙箱端 | `<sw>-pX`(attach 时移入沙箱 netns) | 无设备——沙箱经 `SCM_RIGHTS` 拿 fd |
| `--port-netns` | 必需 | 不需要(tap 留在 switch netns) |
| attach | CAS + 移动 `<sw>-pX` 进沙箱 netns | 仅 CAS(`slot.ifindex == 0` 则拒绝) |
| detach | CAS + 把 `<sw>-pX` 移回 port netns | 仅 CAS |
| 取 fd | n/a | `open-port`(§2.8)或 `attach --open-port` |

模式切换:`provision --mode=<new>` 在 Reserved slot 上先创建新模式设备 → commit 新
`slot.ifindex` → 再删旧模式设备(新旧设备名不冲突,可短暂共存)。

**核心不变量**:attach 和 detach 永远不创建/删除设备(两种模式皆然)。设备生命周期由
`provision`(创建)与 `stop`/`stop --force`(删除)完全拥有;`stop --force-clean` 只
unpin BPF 资源、不删设备。`--skip-device` 只跳过 veth 的 netns 移动,不绕过"必须
provisioned"的前提。

### 6.7 tap fd 交接

交接遵循 [tapfd.md](tapfd.md) 的厂商无关协议(`SCM_RIGHTS` + NUL 结尾 `key=value`
元数据 + `TAPFD_SOCKET` 获取契约),协议规格独立可读,第三方 VMM 据此即可对接。本节
只记录 connector 作为 provider 实现的具体取舍。

**元数据字段**(tapfd.md §2.3):除必填的 `fd=` 外,发送 `mac`(端口派生 MAC,VMM 须
mirror 到 virtio-net——数据面据此识别端口)、`ip`(沙箱 inner IP),并附扩展
字段 `port`(1-based slot 编号,仅供诊断,consumer 可忽略):

```
port=1 mac=02:00:00:00:80:01 ip=169.254.1.1 fd=1\0
```

consumer 经 `TAPFD_WANT_NETNS` 请求时(tapfd.md §3.4),在 tap fd 之后追加 switch
netns 的 fd 并置 `netns_fd=1`,供 consumer `setns(2)` 进入该 netns 操作设备本体。

**provider helper 行为**:`open-port` 读 `TAPFD_SOCKET`(`fd=N` 或路径),进入 switch
netns,`open(/dev/net/tun)` + `TUNSETIFF(IFF_TAP|IFF_NO_PI|IFF_VNET_HDR)`——fd 带
virtio-net header,主流 virtio VMM 的预期帧格式;vnet_hdr 是本次 attach 的属性,与
持久设备的创建标志无关。发送成功后关闭本地 fd 退出(持久 tap 经 `TUNSETPERSIST`
存活,consumer 可随时重新交接获取新队列 fd)。`attach --open-port` 把 CAS 分配与 fd
交接合并为一步,`SCM_RIGHTS` 失败时回滚 CAS 分配,不留半 attached slot。

**前置校验**(触碰 socket/tap 之前即拒绝):slot 必须是 tap 类型、已
provision(`ifindex != 0`)、已 attach(inner IP 为真实 IP,故 `ip` 字段总是真实值)。
交换机未运行 → 退出码 `3`。

**接收方**:第三方实现 tapfd.md §2 即可;本仓提供 Go 参考库 `pkg/tapfd`
(`RecvFd`/`RecvFds`/`RecvFdsWithNetns`)与源码树示例 `examples/tapfd_receiver/`。

### 6.8 MTU 校验

GENEVE 封装增加报文长度,必须保证 `transit_mtu >= port_mtu + encap_overhead`:

| 模式 | overhead |
| --- | --- |
| IP-over-GENEVE | ETH(14) + IP(20) + UDP(8) + GENEVE(8) = **50** |
| Ether-over-GENEVE | 上述 + 内层 ETH(14) = **64** |

`--mtu` 设置所有 port/mgmt veth 的 MTU,默认保留内核默认值。`--transit-dev-mtu`:
未指定——不改 transit MTU,仅校验现值;`auto`——自动设为 `port_mtu + overhead`;
数字——设为该值并验证够用。校验时机:给了 `--mtu` 则在任何资源创建之前(快路径);
未给则等所有 veth 创建后取实际 MTU 最大值再校验(慢路径)。校验失败示例:

```
transit device eth1 MTU 1500 is too small:
  requires at least 1564 (port MTU 1500 + Ether-over-GENEVE overhead 64)
```

### 6.9 DHCP 网关推算

`--transit-dev-addr=auto` 时,StartReserved 阶段在 transit 设备 up 之后执行 DHCP:
响应含 Router Option(3)则直接采用;不含网关则推算子网首个可用 IP 作为网关(如
`192.168.1.100/24` → `192.168.1.1`)并打印提示——处理私有 DHCP 服务器只下发 IP 不
下发网关的常见情况。

## 7. 安全与隔离

### 7.1 威胁模型

connector 是 microVM 之外的**纵深防御**层,hypervisor 仍是首要安全边界;沙箱
代码按半信任对待(可能恶意,但被 VMM 约束)。

| # | 威胁 | 缓解 |
| --- | --- | --- |
| T1 | 沙箱伪造源 IP/MAC 绕过隔离 | 路由判定仅基于 `slot_id`(从 ifindex/floating_ip/geneve_port 推导);MAC 在出口改写 |
| T2 | 沙箱直接访问其他沙箱 | eBPF 程序无 port→port 分支,仅 port→mgmt 与 port→transit |
| T3 | 沙箱伪造 GENEVE 流量 | transit decap 验证外层源 IP == `transit_gateway_ip` 并校验 VNI,其它来源丢弃 |
| T4 | ARP 广播泄漏 | 所有 ARP 由交换机代答;广播帧在 ingress 即被消费,从不出端口 |
| T5 | 控制面进程崩溃 → 数据面瘫痪 | 数据面(TC filter + pinned maps + 内核设备)与进程解耦;`serve` 崩溃重启后经 bpffs 重新挂接(§8.1) |
| T6 | 并发 attach 竞态分配同一 slot | mmap + 原子 CAS,失败者退回 |

### 7.2 隔离不变量

1. **No port-to-port path**:eBPF 源码可静态审计——不存在从 `<sw>-nX` 转发到另一个
   `<sw>-nY` 的分支。
2. **ARP 代答完全由交换机执行**:ARP request 在 `<sw>-nX` ingress 上被消费,由 BPF
   构造 reply 直接 redirect 回端口,不会到达其它端口。
3. **源 MAC 强制改写**:转发出口的源 MAC 总是 `switch_mac` 或派生 MAC,沙箱发出的
   源 MAC 在数据面被忽略。
4. **入端口受限**:transit decap 拒绝任何非 `transit_gateway_ip` 来源或 VNI 不匹配的
   GENEVE 包。
5. **管理流量地址转换**:出向 SNAT 源到 floating IP,入向 DNAT 目的到 inner IP;
   管理服务永远看不到沙箱原始 IP。

### 7.3 所需权限

| 操作 | capabilities | 原因 |
| --- | --- | --- |
| start / serve | `CAP_SYS_ADMIN` + `CAP_NET_ADMIN` | 加载 BPF、pin maps、创建 netns/veth、配置 TC |
| attach / detach | `CAP_SYS_ADMIN` + `CAP_NET_ADMIN` | mmap BPF map、跨 netns 移动设备 |
| stop | `CAP_NET_ADMIN` + (`CAP_SYS_ADMIN` 或 `CAP_BPF`) | 卸载 TC、删除 veth、unpin bpffs |
| status / stats / show | `CAP_SYS_ADMIN` | 经 pin fd 读 BPF map |

Linux 5.8+ 上 `CAP_BPF` 可替代部分 `CAP_SYS_ADMIN`;TC 与 netns 操作仍需
`CAP_NET_ADMIN`。

### 7.4 已知限制

| # | 限制 | 现状 |
| --- | --- | --- |
| L1 | attach 中 CAS 完成到 transit 字段写入之间有 ~1µs 窗口,期间命中的入站 GENEVE 包丢弃 | 窗口不可被外部控制;由 VMM/上层重传弥补 |
| L2 | 沙箱 netns 在 detach 前被外部销毁 → slot 泄漏(设备消失但 slot 仍 Allocated) | 泄漏上限受 `MAX_PORTS=4096` 约束;`stop --force` 整体重置回收 |
| L3 | transit 设备物理故障 | 由上游 ECMP/网卡绑定处理;启动安全检查要求 transit 进入 `start` 时必须 DOWN,防止接管在用网卡 |
| L4 | `MAX_PORTS = 4096` | 编译期常量,提升需重编 BPF |
| L5 | mgmt CIDR 掩码过宽会把非预期流量引入管理平面 | 建议每路由 /32;每 slot 最多 3 条 |
| L6 | `--mgmt-service` target 不可达(尤其 loopback) | `start` 校验 VIP∈mgmt-extract 路由、target 唯一;loopback target 需 mgmt 设备 `route_localnet=1`(§3.3) |

## 8. 可靠性

### 8.1 资源生命周期与崩溃恢复

| 资源 | 持久化机制 | 控制面进程崩溃后 |
| --- | --- | --- |
| BPF 程序 | TC filter refcount | 保留 |
| BPF maps | bpffs pin `/sys/fs/bpf/<sw>/` | 保留 |
| veth / tap / dummy / transit | 内核 netns | 保留 |
| flock | 进程退出自动释放 | 不阻塞下次 start/stop |

`serve` 崩溃 → systemd `Restart=on-failure` → 新进程 `Open(switchName)` 经 bpffs
重新挂接现有 maps + programs → ProvisionPorts 跳过已 Free/Allocated 的 slot →
继续服务。数据面在整个过程中持续转发。

### 8.2 故障排除

| 症状 | 原因 / 处理 |
| --- | --- |
| `transit device not found` | 配置中 `TRANSIT_DEV` 与 `ip link` 不一致;纠正后重启 |
| `transit device eth1 must be DOWN before use` | 启动安全检查;`ip link set eth1 down` 后重启 |
| `failed to pin maps: ...bpffs not mounted` | `mount -t bpf bpf /sys/fs/bpf`,并加入 `/etc/fstab` |
| `switch already exists` | 上次未干净 stop;`connector-ctl vswitch stop <name>`,最后手段 `rm -rf /sys/fs/bpf/<name>` |
| 升级后 ABI 不兼容 | `rm -rf /sys/fs/bpf/<name>` 后重启 service |
| `port not provisioned` | ProvisionPorts 尚未完成;等 `status` 的 `PortDevicesReady` 转 True 后重试 |
| open-port 报 `port not attached` | 先 attach 再 open-port |

## 9. 性能特征

以下数字测于 WSL2 + Linux 5.15,为参考量级;生产环境随 CPU、网卡、内核版本、负载
形态有显著差异。

### 9.1 数据面(2 端口拓扑)

| 指标 | baseline(裸 veth) | GENEVE 路径 | 相对开销 |
| --- | --- | --- | --- |
| TCP 吞吐(单流) | ~110 Gbps | ~55 Gbps | ~50% |
| UDP 64B PPS | ~1100 Kpps | ~250 Kpps | ~77% |
| RTT(端到端) | — | ~0.09 ms | — |
| `tc_ingress_nx` 单次执行 | — | ~110 ns | — |
| `tc_ingress_transit` 单次执行 | — | ~110 ns | — |

PPS 下降(~77%)大于带宽下降(~50%):瓶颈是每包固定成本(BPF + veth + GENEVE 各
阶段)而非带宽。大 TCP 流经 GRO/GSO 摊薄每包成本;小包/突发负载由 BPF 与 GENEVE
encap/decap 主导耗时。

### 9.2 控制面(128 端口)

| 阶段 | 测量值 | 瓶颈 |
| --- | --- | --- |
| Start(完整) | ~8.7 s | TC attach 占 97%,受内核 RTNL 全局锁串行约束 |
| StartReserved(单独) | ~100 ms | 仅 BPF 加载 + map 创建,无 RTNL |
| Stop(128 端口) | ~18 s | ~70 ms/pair(无 BPF)– ~145 ms/pair(含 filter 卸载);RTNL 串行 |
| Stop(256 端口) | ~35 s | 线性增长 |

异步启动时间线(128 端口):

```
t=0 ms      connector-ctl vswitch serve starts
t=100 ms    sd_notify READY=1            ← dependent services may start
t=200 ms    ~first port attachable (Free)
t=8700 ms   all 128 ports Free
```

## 10. 测试

### 10.1 分层

| 层 | 文件 | 权限 | 内容 |
| --- | --- | --- | --- |
| 单元 | `*_test.go` | 普通用户 | 纯逻辑;mock 注入 BPF/netlink |
| 集成 | `*_integration_test.go` | root | 真实 eBPF 加载、netlink 操作;`-tags=integration -exec sudo` |
| 端到端 | `examples/*_test.sh` | root | 完整网络拓扑 + 真实包;`setup`/`test`/`teardown`/`all` 子命令 |
| 基准 | `examples/perf_bench.sh`、`examples/start_perf_bench.sh` | root + iperf3 | 数据面吞吐/PPS/RTT(不同端口密度)与控制面 Start 耗时 |

### 10.2 eBPF 三层验证

1. **结构对齐** — `pkg/internal/bpf/*_integration_test.go` 校验 Go ↔ BPF C 结构内存
   布局(偏移、大小、对齐)。
2. **`BPF_PROG_TEST_RUN`** — 直接执行 eBPF 程序,喂入手工构造的报文,断言返回 action
   与输出字节。`BPF_PROG_TEST_RUN` 不易设置 `skb->ingress_ifindex`,对 `tc_ingress_nx`
   经 `ifindex=0 → slot_id` 的 map 项绕过。
3. **真实拓扑** — `examples/*_test.sh` 建立完整网络拓扑,用真实 ping/iperf 验证转发。

### 10.3 e2e 套件

| 脚本 | 覆盖场景 |
| --- | --- |
| `mgmt_isolation_test.sh` | 管理平面连通 + 沙箱间隔离不变量 |
| `geneve_eth_test.sh` | Ether-over-GENEVE 经网关桥接 |
| `geneve_ip_test.sh` | IP-over-GENEVE 交换机对交换机 |
| `provision_test.sh` | 两阶段启动 + Reserved 修复 + show |
| `tap_test.sh` | tap 模式、open-port、`attach --open-port`、模式切换 |

`examples/manage_switch.sh` 是 JSON 配置驱动的交换机管理脚本
(setup/teardown/status/exec),用于运维操作与手工搭建拓扑。

## 11. 内部组织

```
cmd/connector-ctl/        CLI(cobra);printJSON 与依赖注入函数变量留在此处
cmd/connector-ctl/          tapfd provider 子命令
pkg/tapfd/      (公开)  tapfd 协议参考库,收发两侧:PortMetadata/OpenTap/SendFd/
                        RecvFd/RecvFds/RecvFdsWithNetns/ConnectUnix/UnixConnFromFd
pkg/vswitch/    (公开)  交换机生命周期编排(主 Go API):
                          context.go(Interface/Open) lifecycle.go(Start/StartReserved)
                          provision.go stop.go attach.go(Attach/Detach/Reserve)
                          status.go(Status/Stats) config.go(Config/FileConfig)
                          metadata.go flock.go exports.go
pkg/netlink/    (公开)  veth/tap/TC/批量 netlink 操作
pkg/netns/      (公开)  netns enter/move/exec
pkg/dhcp/       (公开)  内嵌 DHCP 客户端 + 服务器
pkg/daemon/     (公开)  systemd sd_notify
pkg/internal/bpf/       (私有,BPF-ABI)cilium/ebpf 生成绑定 + 类型 + 加载器
pkg/internal/bpfmap/    (私有,BPF-ABI)与 BPF 内存布局耦合的原语:
                          mmap slots、原子 CAS、stats、MAC 派生
bpf/                    eBPF C 源(switch_kern.c + common.h + vmlinux.h)
examples/               e2e 测试脚本 + 源码树 tapfd_receiver 消费端示例
dist/                   systemd 单元与配置模板
```

可见性规则:直接以字节偏移读写 BPF C 结构的代码必须位于 `pkg/internal/`(字段偏移
变动等同 ABI 变更),Go internal 规则限制其只在 `pkg/*` 同级可见;其余 `pkg/*` 均为
公开 API。`cmd/` 不直接 import `pkg/internal/*`:所需低层 helper 经
`pkg/vswitch/exports.go` 重导出,CLI 走外部嵌入者同一条公开 API。

依赖箭头(无环):

```
cmd/connector-ctl ──▶ pkg/vswitch ──▶ pkg/internal/bpfmap ──▶ pkg/internal/bpf
                  └─▶ pkg/tapfd
                  └─▶ pkg/{netlink, netns, dhcp, daemon}

pkg/vswitch ──▶ pkg/{netlink, netns, dhcp, daemon}
pkg/tapfd   : self-contained (stdlib + golang.org/x/sys)
```

## 12. See Also

- [tapfd.md](tapfd.md) — tap 设备文件描述符交接协议规格(provider/consumer 双侧契约)。
- `sandboxer/docs/sandbox.md` — 消费侧:sandbox-ctl 按 tapfd 契约 exec helper
  获取沙箱网卡。
- RFC 8926 — GENEVE: Generic Network Virtualization Encapsulation。
- kernel commit `fc9702273e2e` — bpf: add mmap() support for `BPF_MAP_TYPE_ARRAY`。
- sd_notify(3) — systemd `Type=notify` 集成。
- `github.com/cilium/ebpf`、`github.com/vishvananda/netlink` — 本项目使用的 Go
  eBPF/netlink 库。
