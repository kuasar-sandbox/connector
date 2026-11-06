[English](README.md) | [简体中文](README_zh.md)

# connector

首次运行跨组件沙箱或 Demo，推荐从项目[快速开始](https://github.com/kuasar-sandbox/kuasar-sandbox/blob/main/docs/quickstart_zh.md)
使用匹配聚合版本的 [workbench](https://github.com/kuasar-sandbox/kuasar-sandbox/blob/main/workbench/README_zh.md)。
本组件仍可独立构建和部署，workbench 不是生产运行的强制依赖。预构建架构以所选
发布版的实际资产为准；源码支持某架构不意味着所有历史版本都提供该架构制品。

`connector` 是 [Kuasar Sandbox](https://github.com/kuasar-sandbox/kuasar-sandbox) 面向 MicroVM 的高密度 eBPF 网络组件。

它快速分配和释放沙箱网络资源,在 Linux 内核中转发已建立的流量,默认不提供沙箱间转发路径,为每个沙箱分配平台控制的网络身份,并为外部网络网关实施沙箱级策略提供基础。

本仓可作为完整 Kuasar Sandbox 平台的组成部分,也可通过 TAP 文件描述符交接契约独立集成其他 MicroVM runtime。

## 按任务阅读

| 任务 | 文档 |
|---|---|
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

组件目的不是某一种 Slot、VNI、UDP port 或 TLV 编码。这些机制让部署为各沙箱分配独立隧道面身份,并向外部策略网关携带可信的沙箱元数据。网关可据此实施沙箱级公网、私网、DNS、代理、审计和流量治理规则,不必将应用策略嵌入基础交换机。

节点本地的轻量 Egress 策略面作为[拟议扩展](https://github.com/kuasar-sandbox/connector/issues/9)跟踪,不是基础 vSwitch 已交付的功能。

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

当前 attachment 流量读取与清零/错误语义见 [vSwitch stats](docs/vswitch-operations_zh.md#connector-ctl-vswitch-stats). Go Stats API 可批量读取端口,无需逐端口启动 CLI.

## 与 sandboxer 集成

`sandboxer` 只 import `github.com/kuasar-sandbox/connector/pkg/tapfd`。`connector-ctl` 打开和配置 TAP queue,再通过 Unix socket 的 `SCM_RIGHTS` 交接 fd,按需同时传递 network namespace fd。这个窄接口避免把 eBPF 实现链接进 MicroVM 生命周期引擎。

## 获取发行物

组件使用 `vX.Y.Z`，平台以独立的 `release-vX.Y.Z` 聚合版本选择精确组件 Tag。组件包提供原生 `connector-ctl`、部署模板与选定 helper；聚合包提供选定指南和已准备 E2E 输入。可用架构以所选发行资产为准。参见[安装指南](https://github.com/kuasar-sandbox/kuasar-sandbox/blob/main/docs/installation_zh.md)与[组件打包](CONTRIBUTING_zh.md#组件打包与发行)。

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
