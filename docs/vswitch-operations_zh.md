[English](vswitch-operations.md) | [简体中文](vswitch-operations_zh.md)

# vSwitch 运维

本篇提供 connector vSwitch 的构建、配置、部署、检查和维护流程。[vswitch_zh.md](vswitch_zh.md) 统一定义转发、BPF ABI、身份、隔离、并发和资源生命周期不变量。[tapfd_zh.md](tapfd_zh.md) 仍为可独立实现的 provider/consumer 交接协议，使用该协议不要求采用此 vSwitch。

## 1. 部署与前置条件

### 1.1 系统要求

- 文档基线为 Linux **5.10+**,需相应 TC/BPF 配置,且 `/sys/kernel/btf/vmlinux`
  可访问。应验证实际内核配置与特权测试,版本号本身不足以保证可用。
- bpffs 挂载在 `/sys/fs/bpf`(`mount -t bpf bpf /sys/fs/bpf`)。
- 特权路径以具有所需能力的 root 运行;能力裁剪条件见 [§5.3](vswitch_zh.md#53-所需权限)。
- 构建:**Go 1.26.1+**;重新生成 eBPF 字节码额外需 **Clang/LLVM 12+**。

### 1.2 构建

```bash
make build                      # 产物: bin/<arch>/connector-ctl(并在 bin/ 建同名软链)
make build TARGET_ARCH=aarch64  # 交叉编译(纯 Go,无需交叉工具链);别名 amd64 / arm64
make release VERSION=vX.Y.Z     # 打包并校验 build/release-bundle
make generate                   # 仅修改 bpf/*.c 时需要(clang 12+);仓库自带预生成 .o
make test                       # 单元测试
sudo make test-integration      # 集成测试(root + BPF 内核)
sudo make test-e2e              # 端到端(test/e2e/run_all.sh)
sudo make bench                 # 性能基准(root + iperf3)
make lint                       # go vet
make fmt                        # Go formatting 与 clang-format
make vmlinux                    # 重新生成 bpf/vmlinux.h(需 bpftool)
```

### 1.3 systemd 集成

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

### 1.4 首次启动

1. 将 binary 安装到模板使用的 `/usr/sbin/connector-ctl`,并按上表安装所选模板。
   用 `ip -br link` 确认专用 transit,编辑 `/etc/connector/switch.conf` 的
   TRANSIT_DEV、TRANSIT_DEV_ADDR 等。
2. 将该空闲专用设备置 DOWN:`ip link set "$TRANSIT_DEV" down`;启动会移入 switch
   netns。确认物理 underlay 支持配置的封装 MTU。
3. `sudo systemctl daemon-reload`,再 `sudo systemctl start connector-vswitch`。
   这是随附 **connector-vswitch.service** 文件对应的服务名。
4. 检查 `systemctl status connector-vswitch` 为 active,
   `connector-ctl vswitch status sw0 --ready` 返回 0,`ip netns list` 包含配置的命名空间。
   READY=1 可能早于所有端口 provision 完成([§4.5](vswitch_zh.md#45-两阶段启动))。
5. `sudo systemctl enable connector-vswitch` 启用开机启动。


## 2. 命令行与配置参考

多数查询和一次性命令输出 JSON;`serve` 常驻并报告健康/进度。BPF、设备与 namespace
操作以具有所需能力的 root 运行,见 [§5.3](vswitch_zh.md#53-所需权限)。

### 2.1 子命令总览

| 命令 | 用途 |
| --- | --- |
| `start [switch_name]` | 创建并启动交换机(StartReserved + 同步 ProvisionPorts),返回后用户态退出 |
| `serve [switch_name]` | systemd `Type=notify` 长驻:StartReserved → tapfd listen(可选) → READY=1 → 后台 ProvisionPorts → 健康检查循环 |
| `stop <name>` | 清理所属端口/交换机资源与 pinned maps,把 transit 移入 stop 调用方的 netns |
| `attach <name>` | 分配端口(CAS Free→IP);veth 模式可把端口设备移入沙箱 netns |
| `detach <name> --port=N` | 释放端口(CAS Allocated→Free);不借用 Reserved 作为过渡态 |
| `reserve <name> --port=N` | 把端口标记为 Reserved,阻止后续 attach(升级/排空) |
| `provision <name>` | 为 Reserved slot 创建端口设备;支持批量与单点修复 |
| `open-port <name> --port=N` | 打开 tap 端口的队列 fd,经 `TAPFD_SOCKET` 递交 consumer([tapfd_zh.md](tapfd_zh.md) §3 的 provider helper) |
| `status <name>` | 交换机状态(Conditions);`--ready` 以退出码表达 |
| `stats <name>` | per-port 流量计数(mgmt/transit × rx/tx × packets/bytes) |
| `show slots\|config <name>` | dump slot 表 / in-kernel 配置 |
| `dhcp request\|serve` | 内嵌 DHCP 客户端/服务器(调试与测试场景) |

典型流程(tap 模式,默认):

```bash
# 准备 namespace 与可安全交接的专用空闲 transit 设备
ip netns add sw_ns
ip netns add mgmt_ns
ip link set eth1 down

# 创建交换机;underlay 必须支持最终 MTU
connector-ctl vswitch start sw1 --netns=sw_ns --ports=128 \
    --mac-addr=02:00:00:00:00:01 --floating-ip-base=100.100.96.0 \
    --mgmt-extract=mgmt_ns:eth0:169.254.169.254/32 \
    --transit-dev=eth1 --transit-dev-addr=10.0.0.1/24:10.0.0.2 \
    --transit-dev-mtu=auto
# 显式配置服务拥有的 VIP
ip netns exec mgmt_ns ip addr replace 169.254.169.254/32 dev eth0

# 分配端口;支持 TAPFD 的 VMM receiver 应已监听 /tmp/recv.sock
connector-ctl vswitch attach sw1 --inner-ip=169.254.1.1 \
    --transit-gateway-ip=10.0.0.2 --transit-geneve-vni=100
TAPFD_SOCKET=/tmp/recv.sock connector-ctl vswitch open-port sw1 --port=1

# 释放端口;在应接收 transit 的 namespace 中 stop
connector-ctl vswitch detach sw1 --port=1
connector-ctl vswitch stop sw1
```

### 2.2 `connector-ctl vswitch start` / `serve`

`start` 同步完成全部初始化后退出;`serve` 用于 systemd `Type=notify` 长驻([§4.5](vswitch_zh.md#45-两阶段启动))。
`switch_name` 可省略,从 `--config` 文件([§2.14](#214-配置文件--config))读取。

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `--netns` | ✓ | 交换机内部 netns(必须已存在) |
| `--mac-addr` | ✓ | 虚拟 MAC base,前 4 字节用于派生所有 MAC([§4.1](vswitch_zh.md#41-mac-派生)) |
| `--ports` | ✓ | 端口数(1–4096) |
| `--floating-ip-base` | ✓ | floating IP 基地址(按 slot_id 递增) |
| `--port-netns` | veth 模式 ✓ | 端口设备初始 netns;tap 模式或 `--reserved` 下可省 |
| `--mode` | – | 自动 provision 的端口类型:`tap`(默认)或 `veth`;配合 `--reserved` 时仅作参数校验提示,不持久化 |
| `--mgmt-extract` | – | 管理平面提取匹配 `<netns>:<dev>:<cidr1>,<cidr2>,...`,可重复(每 slot 最多 3 条路由);CIDR 不会被配置为接口地址;`<netns>` 留空(`:<dev>:<cidrs>`)则 mgmt veth peer 留在调用方/主机 netns |
| `--mgmt-service` | – | 管理服务地址转换 `<VIP>:<vport>:<targetIP>:<targetPort>`,可重复;VIP 须落在某条 `--mgmt-extract` 路由内,`(targetIP,targetPort)` 须全局唯一,TCP/UDP 均转换([§2.3](vswitch_zh.md#23-数据包流向));loopback target 需 mgmt 设备 `route_localnet=1` |
| `--transit-dev` | – | 外部上行设备,start 时从调用 netns 移入 switch netns;必须处于 **DOWN**(防止接管在用网卡) |
| `--transit-dev-addr` | – | `<ip>/<prefix>:<nexthop>` 或 `auto`(DHCP,[§4.9](vswitch_zh.md#49-dhcp-网关推算)) |
| `--transit-dev-mtu` | – | `auto` 或具体数值;默认不修改,仅校验([§4.8](vswitch_zh.md#48-mtu-校验)) |
| `--geneve-locator` | – | `port`(默认)、`vni` 或 `tlv`,定义外部网关如何定位零基 `slot_id`([§4.2](vswitch_zh.md#42-geneve-隧道)) |
| `--geneve-port-base` | – | 仅 `port` locator 使用的 GENEVE UDP 端口基值(默认 50000) |
| `--geneve-tlv-locator` | `tlv` locator ✓ | 精确 wire `CLASS:TYPE`,例如 `0102:81`([§4.2](vswitch_zh.md#42-geneve-隧道)) |
| `--geneve-encap-eth` | – | 启用 Ether-over-GENEVE(默认 IP-over-GENEVE) |
| `--mtu` | – | 请求的启动 MTU,用于管理设备与初始 transit budget 检查;当前两阶段 provision 不把它传给新 TAP/veth 端口,须检查实际端口 MTU([§4.8](vswitch_zh.md#48-mtu-校验)) |
| `--port-mac-addr` | – | `fixed`(默认)/`per-port`/具体 MAC([§4.1](vswitch_zh.md#41-mac-派生)) |
| `--reserved` | – | 仅做 StartReserved,不自动 ProvisionPorts。port-netns 由 start 写入交换机配置、`provision` 无独立 flag 覆盖,故计划用 veth 端口时 start 仍需给 `--port-netns` |
| `--config` | – | 从 JSON 文件读取以上参数([§2.14](#214-配置文件--config)) |

`serve` 复用 `start` 的交换机参数,差异:无 `--reserved` flag,另有:

| 参数 | 说明 |
| --- | --- |
| `--watch-interval` | 健康检查间隔,默认 30s |
| `--tapfd-listen` | 持久 vswitch/tapfd UDS。支持 `TAPFD/1 PREPARE` / `OPEN` / `RELEASE`;`OPEN` 返回 `TAPFD/1 OK` + metadata + SCM_RIGHTS;详见 [tapfd_zh.md](tapfd_zh.md) §4 |

`start` 示例输出(值用于展示,不是前面 128-port 命令的实际结果):

```json
{
  "switch": "sw1",
  "switch_netns": "netns_switch",
  "switch_maps": {
    "slots":           "/sys/fs/bpf/sw1/slots",
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

### 2.3 `connector-ctl vswitch stop`

若配置的交换机命名空间已经无法通过名称访问，stop 仅释放遗留 slot 记录并 unpin 交换机，不会把其中保存的接口编号用于调用者命名空间，也不会删除调用者链路或从调用者命名空间迁出 transit 设备。配置名有意留空时仍在调用者命名空间清理；其他命名空间查询错误正常返回。删除命名空间名称不证明已无进程持有原命名空间，仍需单独检查保留的命名空间和孤儿设备。

内部分为 ReleasePorts 与 StopReleased:删除所属端口、管理/dummy 设备和 TC 引用,
unpin maps,把 transit 移入 **stop 调用方的 namespace**。若要还给原 Host netns,
须从那里执行 stop;实现并不保存并自动恢复另一个 origin namespace。

| 参数 | 说明 |
| --- | --- |
| `--force` | 先释放所有 in-use 端口再 stop(两轮清理),用于强制关停 |
| `--force-clean` | 损坏状态恢复:仅 unpin BPF 资源,不清理设备;须检查/清理遗留 netdev 和 TC 引用,不能据此断言转发已停止 |

### 2.4 `connector-ctl vswitch attach`

分配端口：CAS Free→IP；veth 模式可同时把端口设备移入沙箱 netns。未 provision 的端口不可使用；异步启动期间，调用方应处理尚未 provision、分配失败或无可用端口的状态，并按[就绪条件（§4.5）](vswitch_zh.md#45-两阶段启动)重试。

| 参数 | 说明 |
| --- | --- |
| `--inner-ip=IP` | 沙箱内部 IP(必填) |
| `--port=N` | 指定槽位(省略则自动分配) |
| `--to-netns=NS` | 把端口设备移入目标 netns(仅 veth 模式) |
| `--transit-gateway-ip=IP` | GENEVE 外层目标 IP |
| `--transit-geneve-vni=N` | GENEVE VNI |
| `--transit-geneve-opt=CLASS:TYPE:DATA` | 单向出站 opaque GENEVE option,可重复;十六进制 data 长度须为 4 字节整数倍,空 data 写作 `CLASS:TYPE:`([§4.2](vswitch_zh.md#42-geneve-隧道)) |
| `--transit-mac-addr=MAC` | Ether-over-GENEVE 内层目标 MAC(省略则广播) |
| `--skip-device` | 跳过 veth namespace 移动,仍进行 slot/map 控制更新;tap attachment 拒绝 |
| `--open-port` | tap 模式:分配后经 TAPFD_SOCKET 递交 fd;失败时尝试 detach/回滚,清理也失败时须先核对状态再重试 |

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
0 时省略。原始 slot 同名字段只存 opaque bytes,两者不同([§3.3](vswitch_zh.md#33-数据面-abi))。

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

### 2.5 `connector-ctl vswitch detach`

释放端口:在新 switch 的 per-switch control flock 内直接 CAS Allocated→Free,随后清零
options fast-path hint。`Reserved` 只表示显式 reserve/provision/stop 状态,Detach 不把它
用作过渡态。固定长度 options map value 和其它 transit fields 不在 Detach 中清理;
Free slot 不会被数据面使用,下一次 Attach 在发布新 hint 前完整覆盖。缺少
`geneve_opts` map 的旧 switch 保持 CAS-only 兼容路径。tap slot 无设备操作;veth slot
给 `--from-netns` 则把设备移回 port netns,省略则校验设备已在 port netns。

| 参数 | 说明 |
| --- | --- |
| `--port=N` | 槽位编号(必填) |
| `--from-netns=NS` | 端口设备当前所在的沙箱 netns(veth 模式) |
| `--skip-device` | 跳过设备移动/校验(veth/tap 均可) |

### 2.6 `connector-ctl vswitch reserve`

把端口标记为 Reserved,阻止后续 attach;用于升级/排空,或为 `provision --mode` 切换
端口类型做准备([§4.6](vswitch_zh.md#46-端口模式veth-与-tap))。

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

[tapfd_zh.md](tapfd_zh.md) §3 动态获取契约的 provider helper:进入 switch netns,对持久 tap
执行 `open(/dev/net/tun)` + `TUNSETIFF(IFF_TAP|IFF_NO_PI|IFF_VNET_HDR)`,把队列 fd 连同
元数据经 `SCM_RIGHTS` 发往 `TAPFD_SOCKET` 指定的套接字(`fd=N` 或路径,tapfd.md [§3.3](tapfd_zh.md#33-套接字位置的通告tapfd_socket))。
环境变量 `TAPFD_WANT_NETNS` 为真值时在 tap fd 后追加 switch netns fd 并置
`netns_fd=1`(tapfd.md [§3.4](tapfd_zh.md#34-请求-netns-fdtapfd_want_netns))。

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

### 2.9 `connector-ctl vswitch status`

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

`rx` 表示送往沙箱,`tx` 表示来自沙箱. packets 是既有 BPF 观测点的包计数,不是应用请求数或速率. management bytes 使用端口/management ingress 观测到的以太网帧长度. transit TX 使用原始帧长度;transit RX 扣除外层 GENEVE 头并保留以太网头. 这是观测字节数,不是物理链路开销总和. management 和 transit 保持分开,不把重叠观测相加成统一总流量.

`pkg/vswitch.Stats(name, ports)` 和 `Interface.Stats(ports)` 提供同一份按端口列表读取的能力,不启动 CLI 子进程. 消费方应按交换机组织当前绑定并限制批量大小. 生命周期锁占用、交换机替换、map 读取失败或 attach 清零未确认时,整个读取失败,不能替换为 0 或旧样本. Free/Reserved 端口不属于当前观测. detach 不擦除 map,但其计数不能作为 live attachment 查询. reset 失败不使 attach 失败,该 attachment 的 Stats 保持不可用;重新 attach 且清零成功后发布有效的 0 计数. 新计数 ARRAY 使用内核锁与内部代次隔离并发 TC 写入;旧 PERCPU_ARRAY 交换机须重建后才能采集. 读取前后均核验当前 map 身份,force cleanup 也会使读中样本失效.

### 2.11 `connector-ctl vswitch show`

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

### 2.12 `connector-ctl vswitch dhcp`

内嵌 DHCP 客户端与服务器,服务于 transit `auto` 寻址的调试与 e2e 测试拓扑。

- `dhcp request --dev=<iface> [--timeout=5s] [--retries=3]` — 在指定设备上跑一次
  DHCP 并打印结果。
- `dhcp serve --dev=<iface> --server-ip=<ip> --pool=<a.b.c.d-a.b.c.e>
  [--gateway=<ip>] [--dns=<ip,...>] [--lease-time=1h]` — 简易 DHCP 服务器,
  `--gateway` 默认取 `--server-ip`。

### 2.13 `connector-ctl tapfd get`

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
随之消失(对比 vswitch 端口的持久 tap,[§4.6](vswitch_zh.md#46-端口模式veth-与-tap))。

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


## 3. 故障排除

| 症状 | 原因 / 处理 |
| --- | --- |
| `transit device not found` | 核对预期 caller netns 中的 TRANSIT_DEV/ip link;运行中的 switch 可能已把设备移入 switch netns。 |
| `transit device eth1 must be DOWN before use` | 启动安全检查;`ip link set eth1 down` 后重启 |
| `failed to pin maps: ...bpffs not mounted` | `mount -t bpf bpf /sys/fs/bpf`,并加入 `/etc/fstab` |
| `switch already exists` | 先检查已有 switch/配置;确需替换时正常 stop,不把活跃转发下删除 pins 当常规重启流程。 |
| 升级后 ABI 不兼容 | 先排空/停止 consumer,正常或强制 cleanup;损坏状态的 force-clean 只删 pins,还须检查/清理孤儿设备/TC 并还回 transit,再 recreate。 |
| `port not provisioned` 或 Reserved slot 无法 attach | 检查 `ports_available`/`ports_reserved` 或目标 slot,等待/重试或显式修复 Reserved slot;仅凭 `PortDevicesReady=True` 不能证明有可分配容量 |
| open-port 报 `port not attached` | 先 attach 再 open-port |

### 3.1 GENEVE 抓包

按实际 switch namespace、transit 设备和配置的 locator 端口调整命令;下方 filter 只是示例,不是通用端口范围。只抓取已授权流量,并保护可能含敏感 payload 与拓扑的抓包结果。

抓包调试可在 switch netns 的 transit 设备执行:

```bash
ip netns exec sw0_vswitch tcpdump -ni eth1 -vv -XX 'udp port 6081 or udp portrange 50000-54095'
connector-ctl vswitch show config sw0
connector-ctl vswitch show slots sw0
```

在 pcap 中核对 UDP dst、24-bit VNI、`OptLen`、base `C`、option class/type/length/data
及 inner payload 起始偏移。TLV locator data 应是零基 slot_id 的 big-endian 32-bit 值。
