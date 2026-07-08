# connector

基于 eBPF/TC 的虚拟交换机:为单节点最多 4096 个沙箱(microVM)提供隔离网络通道——
沙箱间无转发路径,管理平面经无状态 SNAT/DNAT,外部网络经 GENEVE 隧道;配置完成后
用户态进程退出,转发全部由内核 eBPF 承载。是
[kuasar-sandbox](https://github.com/kuasar-sandbox/kuasar-sandbox) 平台的网络组件,
独立演进。

对外导出 `pkg/tapfd`(tapfd 交接协议 SDK,`sandboxer` 作 consumer 直接
import);协议规格见 [docs/tapfd.md](docs/tapfd.md)。

## 组成

| 路径 | 角色 |
| --- | --- |
| `cmd/connector-ctl` | CLI:start/serve/stop、attach/detach、reserve/provision、open-port、status/stats/show、dhcp |
| `cmd/connector-ctl` | tapfd provider 子命令:开 tap,经 `TAPFD_SOCKET` 以 SCM_RIGHTS 递交 vnet_hdr 队列 fd |
| `pkg/tapfd` | **导出面**:tapfd 协议参考库,收发两侧(`OpenTap`/`SendFd`/`RecvFd`/`RecvFdsWithNetns`);仅 stdlib + x/sys |
| `pkg/vswitch` | 交换机生命周期编排(`Open`/`Start`/`Stop`/`Attach`/`Detach`/`ProvisionPorts`/`Status`/`Stats`) |
| `pkg/netlink` `pkg/netns` `pkg/dhcp` `pkg/daemon` | 底层工具:veth/tap/TC、netns enter/exec、DHCP 客户端+服务器、sd_notify |
| `pkg/internal/{bpf,bpfmap}` | 私有:与 BPF C 结构字节偏移耦合的绑定与原语(mmap slots/CAS/stats) |
| `bpf/` | eBPF C 源;预生成 `.o` 随仓,普通构建无需 clang |
| `dist/` | systemd 单元与配置模板 |

## 构建

```bash
make build                      # bin/<arch>/connector-ctl;纯 Go,CGO_ENABLED=0
make build TARGET_ARCH=aarch64  # 交叉编译(别名 amd64 / arm64)
make release                    # build/dist/connector-<ver>-linux-<arch>.tar.gz
make generate                   # 仅修改 bpf/*.c 时需要(clang 12+)
make test                       # 单元测试;集成/e2e 见 docs/vswitch.md §10
```

运行需要 Linux 5.10+(BTF + TC BPF)与 root;构建需要 Go 1.24+。

## 快速开始

```bash
connector-ctl vswitch start sw1 --netns=sw_ns --ports=128 \
    --mac-addr=02:00:00:00:00:01 --floating-ip-base=100.100.96.0 \
    --mgmt-extract=mgmt_ns:eth0:169.254.169.254/32 \
    --transit-dev=eth1 --transit-dev-addr=10.0.0.1/24:10.0.0.2

connector-ctl vswitch attach sw1 --inner-ip=169.254.1.1 \
    --transit-gateway-ip=10.0.0.2 --transit-geneve-vni=100
TAPFD_SOCKET=/tmp/recv.sock connector-ctl vswitch open-port sw1 --port=1   # tap fd → VMM

connector-ctl vswitch detach sw1 --port=1
connector-ctl vswitch stop sw1
```

命令与参数详见 [docs/vswitch.md](docs/vswitch.md) §2;Go 接收端(consumer)示例见
[docs/tapfd.md](docs/tapfd.md) §7 与源码树 `examples/tapfd_receiver/`。

## 文档

- [docs/vswitch.md](docs/vswitch.md) — 设计与命令参考:架构/数据面/关键机制/安全/
  可靠性/性能/测试。
- [docs/tapfd.md](docs/tapfd.md) — tapfd 交接协议规格(provider/consumer 双侧契约,
  normative)。
