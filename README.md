# sandbox-vswitch

基于 eBPF TC 的高性能虚拟交换机，为单节点 ~4K 沙箱（microVM）提供隔离网络访问。命令行工具名为 `vswitch-ctl`。

> An eBPF/TC-based high-performance virtual switch that gives ~4K sandboxes (microVMs) on a single host isolated network access. The CLI is `vswitch-ctl`.

本仓是 [kuasar-sandbox](https://github.com/kuasar-sandbox/kuasar-sandbox) 平台的网络组件，独立演进。
对外导出 `pkg/tapfd`（tap-fd 交接规约 §5 的 SDK，被 `sandbox-runtime` 直接 import 作消费侧），
并附带提供侧助手 `tapfd-get`（`cmd/tapfd-get`，通过 `TAPFD_SOCKET` 经 SCM_RIGHTS 交接 vnet_hdr 队列 fd）。
协议见 `docs/tapfd.md`。

## 特性

- **纯内核数据面** — 配置完成后进程退出，eBPF 程序持续运行，无用户态守护进程依赖
- **沙箱隔离** — 各端口间无转发路径，ARP 全代答，MAC 强制重写
- **管理平面** — 沙箱通过 SNAT/DNAT 访问管理服务（如 metadata service）
- **GENEVE 隧道** — 支持 IP-over-GENEVE / Ether-over-GENEVE，IPv4 + IPv6
- **并发安全** — BPF map mmap + atomic CAS，无锁端口分配
- **最多 4096 端口**，per-CPU 流量统计

## 快速开始

```bash
# 构建（仓库已包含预生成的 eBPF 目标文件，普通构建无需 clang）
make build                      # 产物: bin/<arch>/{vswitch-ctl,tapfd-get}（并在 bin/ 建同名软链）
                                # tapfd-get 是 tapfd §5 的独立 provider helper（cmd/tapfd-get）
make build TARGET_ARCH=aarch64  # 交叉编译（纯 Go，无需交叉工具链）；别名 amd64 / arm64
make release                    # 打包: build/dist/sandbox-vswitch-<ver>-linux-<arch>.tar.gz

# 仅在修改 bpf/*.c 时需要重新生成（需 clang 12+）
make generate

# 创建交换机
vswitch-ctl start sw1 --mode=veth --netns=sw_ns --port-netns=port_ns --ports=2048 \
    --mac-addr=02:00:00:00:00:01 --floating-ip-base=100.100.96.0 \
    --mgmt-extract=mgmt_ns:eth0:169.254.169.254 \
    --transit-dev=eth1 --transit-dev-addr=10.0.0.1/24:10.0.0.2 \
    --geneve-port-base=50000 --geneve-encap-eth

# 分配端口
vswitch-ctl attach sw1 --to-netns=sandbox1 --inner-ip=169.254.1.1 \
    --transit-gateway-ip=10.0.0.2 --transit-geneve-vni=100

# 释放端口
vswitch-ctl detach sw1 --port=1 --from-netns=sandbox1

# 停止
vswitch-ctl stop sw1
```

详见 [docs/PROPOSAL.md](docs/PROPOSAL.md)。

## 系统要求

- Linux 5.10+（BTF + TC BPF）
- 运行：root 权限（`CAP_SYS_ADMIN` + `CAP_NET_ADMIN`）
- 构建：Go 1.24+；重新生成 eBPF 字节码额外需要 Clang/LLVM 12+

## 测试

```bash
make test                                        # 单元测试
sudo bash examples/geneve_eth_test.sh all        # Ether-over-GENEVE e2e
sudo bash examples/geneve_ip_test.sh all         # IP-over-GENEVE e2e
sudo bash examples/mgmt_isolation_test.sh all    # 管理平面 + 隔离
```

## 作为 Go 库使用 (Importing as a library)

CLI 之外，仓库以 `github.com/kuasar-sandbox/sandbox-vswitch/pkg/...` 暴露公开 API：

| 包 | 用途 |
|----|------|
| `pkg/tapfd` | tap fd 端到端递交：wire 协议 + `OpenTap` + `SendFd` + `RecvFd` / `RecvFds` / `RecvFdsWithNetns`（带 netns fd 变体）+ `ConnectUnix` / `UnixConnFromFd`（建连） |
| `pkg/vswitch` | 交换机生命周期编排：`Open`, `Start`, `Stop`, `Attach`, `Detach`, `ProvisionPorts` |
| `pkg/netlink`, `pkg/netns`, `pkg/dhcp`, `pkg/daemon` | 底层网络工具 (veth/tap, netns enter/exec, DHCP, sd_notify) |

`pkg/internal/{bpf,bpfmap}` 故意私有 — 这里的字节偏移与 BPF C 结构耦合，任何变更等同 ABI 变更，仅 `pkg/*` 同级目录可见。

**最常见用法**：在 VMM 编排进程里接收 vswitch-ctl 发来的 tap fd：

```go
package main

import (
    "log"
    "net"
    "os"

    "github.com/kuasar-sandbox/sandbox-vswitch/pkg/tapfd"
)

func main() {
    _ = os.Remove("/tmp/recv.sock")
    ln, err := net.Listen("unix", "/tmp/recv.sock")
    if err != nil {
        log.Fatal(err)
    }
    defer ln.Close()

    conn, _ := ln.Accept()
    defer conn.Close()

    f, meta, err := tapfd.RecvFd(conn.(*net.UnixConn))
    if err != nil {
        log.Fatal(err)
    }
    defer f.Close() // *os.File owning the tap fd; hand to your VMM

    log.Printf("got tap fd %d for port=%d mac=%s mtu=%d ip=%s",
        f.Fd(), meta.Port, meta.MAC, meta.MTU, meta.InnerIP)
}
```

配套发送端：`TAPFD_SOCKET=/tmp/recv.sock vswitch-ctl open-port <sw> --port=N` (或 `attach … --open-port` 合并 attach+发送两步)。协议规格见 [`docs/tapfd.md`](docs/tapfd.md)；完整可运行示例见 [`examples/tapfd_receiver/`](examples/tapfd_receiver/main.go)。

```bash
go doc github.com/kuasar-sandbox/sandbox-vswitch/pkg/tapfd
go doc github.com/kuasar-sandbox/sandbox-vswitch/pkg/vswitch
```

## 文档

完整设计、API、可靠性、性能、运维与测试都汇总在：

- **[docs/PROPOSAL.md](docs/PROPOSAL.md)** — sandbox-vswitch 的总设计提案 (动机 / 架构 / 关键机制 / API / 安全 / 性能 / 部署 / 测试 / 路线图)。
