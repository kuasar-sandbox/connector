[English](README.md) | [简体中文](README_zh.md)

# connector

首次启动沙箱，请按项目[快速开始](https://github.com/kuasar-sandbox/kuasar-sandbox/blob/main/docs/quickstart_zh.md)，用 `docker pull` 拉取 node-infra 镜像、`docker run` 启动节点，再在 Guest 中执行命令。部署持久节点或集群时，继续阅读平台部署指南并提供明确的站点配置。quickstart profile 使用专用数据卷；自定义工作负载使用已完成站点配置的实例。

独立部署组件或接入其他 runtime 时，再使用本仓指南。使用所选版本及架构配套的二进制、配置示例和指南。[Workbench](https://github.com/kuasar-sandbox/kuasar-sandbox/blob/main/workbench/README_zh.md)用于源码开发、演示和集成验证。

`connector` 是 [Kuasar Sandbox](https://github.com/kuasar-sandbox/kuasar-sandbox) 面向 MicroVM 的高密度 eBPF 网络组件。

它快速分配和释放沙箱网络资源,在 Linux 内核中转发已建立的流量,默认不提供沙箱间转发路径,为每个沙箱分配平台控制的网络身份,并为外部网络网关实施沙箱级策略提供基础。

本仓可作为完整 Kuasar Sandbox 平台的组成部分,也可通过 TAP 文件描述符交接契约独立集成其他 MicroVM runtime。

## 按任务阅读

| 任务 | 文档 |
|---|---|
| 通过本地或远端网关提供沙箱 IPv4 出口 | [Egress 运维](docs/egress_zh.md) |
| 部署、分配端口、观测流量或恢复交换机 | [vSwitch 运维](docs/vswitch-operations_zh.md) |
| 对接网关，审查隔离、身份与 ABI | [网络架构与契约](docs/vswitch_zh.md) |
| 实现 TAP provider 或 consumer | [TAPFD 协议](docs/tapfd_zh.md) |
| 构建、测试或修改组件 | [贡献指南](CONTRIBUTING_zh.md) |

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

沙箱的隧道身份让网关依据平台分配的身份选择网络策略。vSwitch 提供转发和身份，部署方选择网关及策略。仅启动 vSwitch 不会自动提供 Internet 访问。

[Geneve Egress 网关](docs/egress_zh.md)提供 IPv4 路由、有序 ACL、DNAT 和原生 NAT，本地与远端部署使用同一套 Area/Pool 配置，有效流量自动创建状态。可选择 node-infra 管理的本地网关、独立交换机的专用本地接线，或通过自有 underlay 访问远端网关。DNS/域名策略和应用代理由网关之外的服务提供。

从同一组件版本安装匹配的 `connector-ctl` 和全静态 `connector-vpp`，保留在同一 `bin/` 目录中，无需另装 VPP、插件目录或沙箱登记服务。源码构建与原生验收见 [Egress 构建与验收](egress/README_zh.md)。

## 主要接口

| 路径 | 用途 |
| --- | --- |
| `cmd/connector-ctl` | start/serve/stop vSwitch;attach/detach、reserve/provision、open-port、状态/统计及 DHCP |
| `pkg/egress` | 文件配置/reload、网关进程管理和自有本地链路生命周期 |
| `pkg/vswitch` | Go vSwitch 生命周期与端口管理 |
| `pkg/tapfd` | 经 Unix socket 交接 TAP 和 network namespace fd 的公共 provider/consumer SDK |
| `pkg/netlink`、`pkg/netns`、`pkg/dhcp`、`pkg/daemon` | Linux 网络、namespace、DHCP 与服务辅助能力 |
| `bpf/` | eBPF C 源码;预生成运行对象位于 `pkg/internal/bpf/` |
| `dist/` | systemd unit 与配置模板 |

TAP 交接的规范协议见 [`docs/tapfd_zh.md`](docs/tapfd_zh.md)。

当前 attachment 流量读取与清零/错误语义见 [vSwitch stats](docs/vswitch-operations_zh.md#connector-ctl-vswitch-stats). Go Stats API 可批量读取端口,无需逐端口启动 CLI.

## 与 sandboxer 集成

`sandboxer` 只 import `github.com/kuasar-sandbox/connector/pkg/tapfd`。`connector-ctl` 打开和配置 TAP queue,再通过 Unix socket 的 `SCM_RIGHTS` 交接 fd,按需同时传递 network namespace fd。这个窄接口避免把 eBPF 实现链接进 MicroVM 生命周期引擎。

## 获取发行物

组件使用 `vX.Y.Z`，平台以独立的 `release-vX.Y.Z` 聚合版本选择精确组件 Tag。组件包提供 `bin/connector-ctl`、配套的全静态 `bin/connector-vpp`、`bin/vpp-runtime.json`、部署模板及选定 helper；聚合包提供选定指南和已准备 E2E 输入。可用架构以所选发行资产为准。参见[安装指南](https://github.com/kuasar-sandbox/kuasar-sandbox/blob/main/docs/installation_zh.md)与[组件打包](CONTRIBUTING_zh.md#组件打包与发行)。

## 项目边界

- 节点与集群编排归属 [`orchestrator`](https://github.com/kuasar-sandbox/orchestrator);
- MicroVM 生命周期和 TAP consumer 归属 [`sandboxer`](https://github.com/kuasar-sandbox/sandboxer);
- 镜像/快照数据基础组件归属 [`accelerator`](https://github.com/kuasar-sandbox/accelerator);
- guest Runtime 与内核发行物归属 [`guest-runtime`](https://github.com/kuasar-sandbox/guest-runtime);
- 系统设计、共享集成测试、Demo 和聚合发行归属 [`kuasar-sandbox/kuasar-sandbox`](https://github.com/kuasar-sandbox/kuasar-sandbox)。

## 贡献与安全

请阅读本仓[贡献指南](CONTRIBUTING_zh.md)与[组织贡献指南](https://github.com/kuasar-sandbox/.github/blob/main/CONTRIBUTING.md)。网络协议、TAP 交接或跨仓契约变更需要关联 Companion PR 并执行精确源码的项目级验证。

不要公开凭据、真实内部拓扑、包含敏感载荷的抓包或尚未修补的漏洞。请使用 [Kuasar Sandbox 安全政策](https://github.com/kuasar-sandbox/kuasar-sandbox/security/policy)和 GitHub 私密漏洞报告。

## License

项目原创内容采用 [Apache License 2.0](LICENSE)。eBPF 程序与生成对象保留 [`LICENSE_SCOPE_zh.md`](LICENSE_SCOPE_zh.md)定义的 GPL-2.0-only 边界。保留 Linux、工具链、vendor code 与生成物的署名和许可。
