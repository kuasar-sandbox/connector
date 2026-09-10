[English](README.md) | [简体中文](README_zh.md)

# connector

`connector` 是 [Kuasar Sandbox](https://github.com/kuasar-sandbox/kuasar-sandbox) 面向 MicroVM 的高密度 eBPF 网络组件。

它快速分配和释放沙箱网络资源,在 Linux 内核中转发已建立的流量,默认不提供沙箱间转发路径,为每个沙箱分配平台控制的网络身份,并为外部网络网关实施沙箱级策略提供基础。

本仓可作为完整 Kuasar Sandbox 平台的组成部分,也可通过 TAP 文件描述符交接契约独立集成其他 MicroVM runtime。

## 网络模型

基础 vSwitch 提供:

- 每沙箱隔离的网络通道;
- 控制面配置完成后由 eBPF/TC 在内核中转发;
- 由平台校验和改写沙箱网络身份,不信任 guest 自报的源身份;
- 对节点管理服务的受控访问;
- 通过 GENEVE 集成外部网络;
- 快速 attach、detach、reserve、provision 和 open-port;
- 通过 `connector-ctl` 检查统计与生命周期;
- 向 VMM/runtime 交接 TAP 与 network namespace 文件描述符。

组件目的不是某一种 Slot、VNI、UDP port 或 TLV 编码。这些机制让部署为各沙箱分配独立隧道面身份,并向外部策略网关携带可信的沙箱元数据。网关可据此实施沙箱级公网、私网、DNS、代理、审计和流量治理规则,不必将应用策略嵌入基础交换机。

节点本地的轻量 Egress 策略面作为[拟议扩展](https://github.com/kuasar-sandbox/connector/issues/9)跟踪,不是基础 vSwitch 已交付的功能。

<a id="组成"></a>

## 主要接口

| 路径 | 用途 |
| --- | --- |
| `cmd/connector-ctl` | start/serve/stop vSwitch;attach/detach、reserve/provision、open-port、状态/统计及 DHCP |
| `pkg/vswitch` | Go vSwitch 生命周期与端口管理 |
| `pkg/tapfd` | 经 Unix socket 交接 TAP 和 network namespace fd 的公共 provider/consumer SDK |
| `pkg/netlink`、`pkg/netns`、`pkg/dhcp`、`pkg/daemon` | Linux 网络、namespace、DHCP 与服务辅助能力 |
| `bpf/` | eBPF C 源码;预生成运行对象位于 `pkg/internal/bpf/` |
| `dist/` | systemd unit 与配置模板 |

TAP 交接的规范协议见 [`docs/tapfd_zh.md`](docs/tapfd_zh.md)。

<a id="构建"></a>

## 构建与测试

```bash
make build                      # bin/<arch>/connector-ctl;纯 Go 控制面
make build TARGET_ARCH=aarch64  # 交叉编译;接受 amd64/arm64 别名
make generate                   # 修改 bpf/*.c 后重新生成对象;需要 Clang/LLVM
make test                       # 单元测试
sudo make test-e2e              # 特权网络 owner suite
```

运行要求:

- Linux 5.10 或更新版本,支持 BTF 和 TC BPF;
- root 或等效的必要 capabilities;
- network namespace、TAP、veth、路由及 TC 支持;
- 源码构建需要 Go 1.24 或更新版本;
- 仅重新生成 BPF 对象时需要 Clang 12 或更新版本。

仓库包含预生成 BPF 对象,普通构建不需要 Clang。特权测试被跳过不等于网络验证完成。特权 E2E 必须在隔离的候选环境中运行,并清理本次运行拥有的全部 TAP、namespace、route、rule、BPF map 和 pin path。

<a id="快速开始"></a>

## 最小本地示例

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

port="$(connector-ctl vswitch attach sw1 \
    --inner-ip=169.254.1.1 \
    --transit-gateway-ip=10.0.0.2 \
    --transit-geneve-vni=100 \
    | jq -er '.port | select(type == "number" and . >= 1 and . <= 128 and floor == .)')"

TAPFD_SOCKET="$TAPFD_SOCKET" connector-ctl vswitch open-port sw1 --port="$port"

connector-ctl vswitch detach sw1 --port="$port"
connector-ctl vswitch stop sw1
ip netns del mgmt_ns
ip netns del sw_ns
```

这些是文档示例地址,不是生产拓扑。从应接收归还 transit 设备的 namespace 执行 `stop`。检查端口与 transit 的实际 MTU:当前两阶段 provision 未把 `--mtu` 传给新建 TAP/veth 端口。完整命令参考与部署操作见 [vSwitch 运维](docs/vswitch-operations_zh.md);转发和生命周期约束归属于 [vSwitch 设计](docs/vswitch_zh.md)。

这是人工操作顺序,不是自动失败清理脚本。任何命令失败都应停下,检查实际分配结果,并且只移除本次运行创建的资源。不得强制停止预存交换机或删除陌生 namespace。

## 与 sandboxer 集成

`sandboxer` 只 import `github.com/kuasar-sandbox/connector/pkg/tapfd`。`connector-ctl` 打开和配置 TAP queue,再通过 Unix socket 的 `SCM_RIGHTS` 交接 fd,按需同时传递 network namespace fd。这个窄接口避免把 eBPF 实现链接进 MicroVM 生命周期引擎。

## 发行模型

发行工作流在上传前把已完成归档的 SHA-256 记录为 build job output。发布者通过
`RELEASE_ARCHIVE_SHA256` 接收这一独立值,在任何 Tag/Release 写入前核对;不能用
下载后从 bundle 重新计算的值代替。即使重算 bundle 自身的校验和,全部载荷与材料
仍须匹配该次已完成构建。本地打包和独立验证不要求这个发布输入。该记录不证明
编译器来源,也不构成对不可信候选代码的隔离。

Go 依赖及工具链下载使用全新的私有 module/VCS 状态、已启用的 checksum database
和 `GOAUTH=off`。它们清除持久化 Go 设置、私有 module 绕过规则、Git 配置与调用者凭据,仅保留已验证的
无凭据路由。下载来源或工具链之前,上传的 Go 记录键必须匹配官方载荷的精确名称;
路径别名会被拒绝。这些发行检查不改变普通开发中的 module 认证方式。
来源清单在逐行处理前拒绝重复或过量记录;每份元数据表上限为 16 MiB,
来源清单上限为 16,384 行。

可信发布端根据已验证请求生成标准发行正文及来源/Preview 标记。下载的
`release-notes.md` 只是本地 bundle 辅助说明,不能决定公开发行正文或对账来源。

打包从选定的 Connector commit 建立全新 checkout,以 `GOWORK=off` 和只读 module 解析重新构建 Go 载荷。不复用被忽略的开发文件或预制二进制,拒绝 `RELEASE_BIN_DIR`。构建命令使用私有 home/缓存,不继承云/发布凭据;可保留无凭据的 HTTPS module/network proxy 路由。
构建保留 `GOSUMDB`(包括无凭据的 HTTPS checksum mirror)与 `GOTOOLCHAIN`,
不会把发行工作流的 `local` 策略静默改为自动下载工具链。未显式设置时,打包使用
`sum.golang.org` 和本地 Go 工具链。

发行打包记录全新构建上下文实际选定的 Go 编译器,在构建前后将其分发输入与匹配的
`golang.org/toolchain` 归档逐项比较;归档由配置的 checksum database 认证。这覆盖
编译器、标准库源码及该分发中的其他文件。完整 Go 安装中额外的非构建 `api`、
`doc`、`misc`、`test` 文件不在认证范围,也不作为发行许可来源;核对时处理标准的
`go.mod`/`_go.mod` 安装转换。Go 许可/NOTICE 正文来自已验证归档,包括编译器和
标准库内嵌依赖的材料,保留各自相对路径。独立验证还会
重新核对其字节、来源 URL 和 module h1。版本字符串或重算 bundle 校验和不能替代
来源核对。验证要求启用 checksum database 并取得匹配的归档/缓存;即使采用
`GOTOOLCHAIN=local`,也可能获取核验材料,但不切换构建编译器或静默启用工具链
自动选择。这些检查以可信构建主机为前提,不证明已失陷主机可信。

独立验证还从选定 commit 的 Git blob 重建完整项目许可证集合,包括嵌套的
`LICENSES` 文件,逐项比较发行材料的字节和文件名。即使重算 bundle 两层校验和,
声明被修改、缺失或额外加入时仍会被拒绝。该过程只读取 Git 对象,不执行候选
源码,也不获取任意材料 URL。

归档名称记录请求的发行版本。来源记录仅在本地 Git Tag 指向所选 commit 时保留该版本;打 Tag 前使用 `git:<commit>`。验证器把全部 Go 载荷和项目来源 URL/摘要绑定到同一 commit。发布者传入预期 commit,在任何 Tag 或 Release 写入前拒绝不同来源的 bundle。
验证要求 Go 载荷为 Connector module 的
`github.com/kuasar-sandbox/connector/cmd/connector-ctl` main package,目标为
Linux/amd64;同一 commit 中的其他示例不能替代该 CLI。验证绑定内嵌 eBPF 的来源与
许可标识,并把每个部署
文件和辅助脚本与选定 Git blob 逐字节比较。这些文件从全新 checkout 复制,不取
开发工作区内容。验证器要求本地对象数据库包含该 commit;可信发布端获取源码
历史,但不执行候选辅助脚本。
构建与发布作业使用相同的无凭据 module/checksum 路由和本地编译器选择策略,
独立材料验证也沿用这些设置。
许可证收集遇到不可读子目录或不完整遍历时失败;可读的顶层 LICENSE 不能代替被
遗漏的嵌套材料。官方组件包不支持没有已认证 module 校验和的第三方本地 Go
替换,应选择带版本的 module 替换。现有 Kuasar 兄弟仓本地替换和普通源码开发不变。

`connector` 独立发布 `vX.Y.Z` 组件版本。x86_64 组件归档包含 `connector-ctl`、部署文件和组件发行合同选定的运维辅助脚本。设计文档和 E2E 源码从选定组件 Tag 收集到项目平台归档。用 `make release VERSION=vX.Y.Z` 构建并验证相同的本地 bundle 布局。

项目主仓独立发布 `release-vX.Y.Z` 聚合版本,选择精确的 Connector Tag 与其他发行单元,并验证组合后的平台。组件与聚合版本号相互独立。

参见[项目发行文档](https://github.com/kuasar-sandbox/kuasar-sandbox/blob/main/docs/release_zh.md)和[最新 Stable 聚合渠道](https://github.com/kuasar-sandbox/kuasar-sandbox/releases/latest)。

## 文档

- [vSwitch 运维](docs/vswitch-operations_zh.md) - 完整 CLI/配置、部署与故障排除。

详细设计和参考文档提供完整英中版本:

- [vSwitch - 英文](docs/vswitch.md) / [中文](docs/vswitch_zh.md) - 架构、数据路径、管理与外部网络、安全、可靠性、性能和测试;
- [TAPFD - 英文](docs/tapfd.md) / [中文](docs/tapfd_zh.md) - provider/consumer 的规范 TAP fd 交接协议。

README 提供完整公开组件入口。详细 locator 编码与报文字段布局保留在专题设计文档中,不在公开概览重复定义。

## 项目边界

- 节点与集群编排归属 [`orchestrator`](https://github.com/kuasar-sandbox/orchestrator);
- MicroVM 生命周期和 TAP consumer 归属 [`sandboxer`](https://github.com/kuasar-sandbox/sandboxer);
- 镜像/快照数据基础组件归属 [`accelerator`](https://github.com/kuasar-sandbox/accelerator);
- guest Runtime 与内核发行物归属 [`guest-runtime`](https://github.com/kuasar-sandbox/guest-runtime);
- 系统设计、共享集成测试、Demo 和聚合发行归属 [`kuasar-sandbox/kuasar-sandbox`](https://github.com/kuasar-sandbox/kuasar-sandbox)。

## 贡献与安全

请阅读本仓[贡献指南](CONTRIBUTING.md)与[组织贡献指南](https://github.com/kuasar-sandbox/.github/blob/main/CONTRIBUTING.md)。网络协议、TAP 交接或跨仓契约变更需要关联 Companion PR 并执行精确源码的项目级验证。

不要公开凭据、真实内部拓扑、包含敏感载荷的抓包或尚未修补的漏洞。请使用 [Kuasar Sandbox 安全政策](https://github.com/kuasar-sandbox/kuasar-sandbox/security/policy)和 GitHub 私密漏洞报告。

## License

项目原创内容采用 [Apache License 2.0](LICENSE)。eBPF 程序与生成对象保留 [`LICENSE_SCOPE_zh.md`](LICENSE_SCOPE_zh.md)定义的 GPL-2.0-only 边界。保留 Linux、工具链、vendor code 与生成物的署名和许可。
