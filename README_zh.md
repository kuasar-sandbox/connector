[English](README.md) | [简体中文](README_zh.md)

# connector

基于 eBPF/TC 的虚拟交换机:编译期最多 4096 个沙箱端口,不保证任意节点/负载都能承载
同等数量的活跃 MicroVM。提供隔离网络通道——
沙箱间无转发路径,管理平面经无状态 SNAT/DNAT,外部网络经 GENEVE 隧道;支持按 UDP
port、VNI 高 12 bits 或精确 TLV 定位 slot,并可在单向出站携带 per-port opaque Geneve
options。转发由内核 eBPF 承载;一次性配置命令可退出,`serve` 仍作为控制、
健康检查和 TAPFD provider 常驻,不转发数据包。是
[kuasar-sandbox](https://github.com/kuasar-sandbox/kuasar-sandbox) 平台的网络组件,
独立演进。

对外导出 `pkg/tapfd`(tapfd 交接协议 SDK,`sandboxer` 作 consumer 直接
import);协议规格见 [docs/tapfd_zh.md](docs/tapfd_zh.md)。

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
make release VERSION=v0.1.0     # build/release-bundle:archive + checksums + provenance
make generate                   # 仅修改 bpf/*.c 时需要(clang 12+)
make test                       # 单元测试;集成/e2e 见 docs/vswitch_zh.md §10
sudo make test-e2e              # 运行 test/e2e/run_all.sh
```

运行需要 Linux 5.10+(BTF + TC BPF)与 root;构建需要 Go 1.24+。

仓库 `main` 上受信任的 `Release` workflow 从调度器钉住的源码分支和精确 SHA
发布独立 `vX.Y.Z` 版本。发布包
`connector-vX.Y.Z-linux-x86_64.tar.gz` 可与其他 Kuasar Sandbox 组件直接解压到
同一部署目录,包含二进制、部署文件和运维/性能辅助脚本。本仓文档与 `test/e2e/`
仅由项目主仓从所选 tag 聚合进 platform 包,不在组件包中重复交付。
打包从选定的 Connector commit 建立全新 checkout,以 `GOWORK=off` 和只读 module
解析重新构建 Go 载荷。不复用被忽略的开发文件或预制二进制,拒绝 `RELEASE_BIN_DIR`。
构建命令使用私有 home/缓存,不继承云/发布凭据;可保留无凭据的 HTTPS module/network
proxy 路由。
归档名称记录请求的发行版本;来源记录只有在本地 Git Tag 指向所选 commit 时才保留
该版本,打 Tag 前使用 `git:<commit>`。验证器将所有 Go 载荷及项目来源 URL/摘要
绑定到同一 commit。发布者传入其预期 commit,在任何 Tag/Release 写入前拒绝不同
源码产生的包。
当前组件 Release 构建并打包 Linux x86_64 目标;项目聚合发布随后对所选组件的
真实发布资产组合运行集成测试,不能把组件打包成功等同于聚合集成测试通过。组件
`main` 用于主线,`release/vX.Y.x` 用于对应组件维护线。Preview 和维护分支 Stable
不更新 GitHub Latest;独立的幂等 Reconcile Latest 工作流按 `main` 源码提交先后协调
主线 Stable,同一提交才比较 SemVer。组件版本与平台聚合版本独立,平台始终按精确 Tag
选择本组件。
同版本发布与删除共用完整 workflow mutation group;若 GitHub 合并 pending 请求,项目主仓
协调器会把 cancelled 状态作为未完成操作自动重跑,不会把它当作发布或 GC 已完成。

## 快速开始

以下示例创建新交换机,以 root 运行。`eth1` 必须是可安全移入 `sw_ns` 的专用空闲设备,
underlay 必须支持配置后的 transit MTU。执行 `open-port` 前,支持 TAPFD 协议的 VMM
接收端必须已监听 `/tmp/recv.sock`。生产地址与拓扑需按部署调整。

```bash
ip netns add sw_ns
ip netns add mgmt_ns
ip link set eth1 down

connector-ctl vswitch start sw1 --netns=sw_ns --ports=128 \
    --mac-addr=02:00:00:00:00:01 --floating-ip-base=100.100.96.0 \
    --mgmt-extract=mgmt_ns:eth0:169.254.169.254/32 \
    --transit-dev=eth1 --transit-dev-addr=10.0.0.1/24:10.0.0.2 \
    --transit-dev-mtu=auto
# 部署显式分配服务拥有的地址;--mgmt-extract 只分类流量。
ip netns exec mgmt_ns ip addr replace 169.254.169.254/32 dev eth0

connector-ctl vswitch attach sw1 --inner-ip=169.254.1.1 \
    --transit-gateway-ip=10.0.0.2 --transit-geneve-vni=100
TAPFD_SOCKET=/tmp/recv.sock connector-ctl vswitch open-port sw1 --port=1   # tap fd → VMM

connector-ctl vswitch detach sw1 --port=1
connector-ctl vswitch stop sw1
```

从应接收归还 transit 设备的 namespace 执行 `stop`。检查端口与 transit 的实际 MTU:
当前两阶段 provision 未把 `--mtu` 传给新建 TAP/veth 端口。

命令与参数详见 [vSwitch 运维 — 命令行参考](docs/vswitch-operations_zh.md#2-命令行接口);Go 接收端(consumer)示例见
[docs/tapfd_zh.md](docs/tapfd_zh.md#8-交接示例) §8 与源码树 `examples/tapfd_receiver/`。

## 文档

- [vSwitch 运维](docs/vswitch-operations_zh.md) — 完整 CLI/配置、部署与故障排除。

- [docs/vswitch_zh.md](docs/vswitch_zh.md) — 设计:架构/数据面/关键机制/安全/
  可靠性/性能/测试。
- [docs/tapfd_zh.md](docs/tapfd_zh.md) — tapfd 交接协议规格(provider/consumer 双侧契约,
  normative)。

## License

本仓库的项目原创内容采用 [Apache License 2.0](LICENSE).eBPF 程序及其生成物的
GPL-2.0-only 边界见 [LICENSE_SCOPE_zh.md](LICENSE_SCOPE_zh.md).
贡献授权说明见 [CONTRIBUTING.md（英文）](CONTRIBUTING.md).
