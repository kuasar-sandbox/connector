# tapfd 协议规格：tap 设备文件描述符交接

| 字段 | 值 |
| --- | --- |
| **协议名** | tapfd handoff protocol |
| **版本** | v1 |
| **状态** | 稳定 |
| **受众** | 实现本协议的 **provider**（tap 提供方，如交换机 / 网络后端）与 **consumer**（消费方，如 VMM / 编排器：cloud-hypervisor、Firecracker、QEMU 等） |
| **规范性** | §4（wire 协议）、§5（动态获取契约）均为 **normative**。consumer 如何在自身配置中建模网络不属于本协议（见 §1）。 |
| **参考实现** | sandbox-vswitch（`vswitch-ctl`）实现本协议；Go 参考库 `github.com/fullof-work/sandbox-vswitch/pkg/tapfd`，可运行示例 `examples/tapfd_receiver/` |
| **License** | Apache-2.0 |

本文档自洽：provider 与 consumer 双方据此对接，无需了解任何具体实现的内部逻辑。具体实现（如 sandbox-vswitch）是本规格的一个实现，而非本规格的依据。

---

## 1. 概述与范围

某些虚拟化网络方案中，网络接口（一个 tap 设备）由 **provider** 创建并管理，而 **consumer**（VMM）需要拿到它来驱动 virtio-net。本协议让 provider 通过一次 **文件描述符交接（fd handoff）**，把已绑定该 tap 的队列 fd 连同必要元数据交给 consumer，免去“按名打开 + 另行查询配置”。

本协议规定：

1. **句柄交接 wire 协议（§4，normative）**：给定一个已连接的 unix 套接字，provider 用 `SCM_RIGHTS` 把 fd 连同一行元数据交给 consumer。这是 consumer **必须**实现的最小契约。
2. **动态获取契约（§5，normative）**：当 consumer 以 exec 子进程的方式驱动一个 provider helper 时，如何建立该套接字并告知 helper。

consumer 如何在自身配置中建模网络（YAML / JSON 等格式、L3/路由/DNS 等字段）是 consumer 的实现细节，**不属于**本协议。

---

## 2. 术语与约定

- **provider（发送方 / sender / helper）**：打开 tap 队列 fd 并经套接字发出的一方。
- **consumer（接收方 / receiver / VMM）**：接收 fd 并据元数据配置网卡的一方。
- **runtime**：consumer 侧负责建立套接字、按 §5 exec helper 的编排逻辑。
- **规范性关键词**：**必须 / 禁止 / 应当 / 不应 / 可** 对应 RFC 2119 的 MUST / MUST NOT / SHOULD / SHOULD NOT / MAY。

---

## 3. 协议分层

```
Layer 2  动态获取契约（normative，§5）  —— 仅 exec 模型需要
         runtime 经 TAPFD_SOCKET 告知被 exec 的 provider helper 套接字位置
            │
            ▼
Layer 1  句柄交接 wire 协议（normative，§4）
         SCM_RIGHTS 传 fd + NUL 结尾的 key=value 元数据行
```

直接连接 provider（provider 拨号、或 consumer 连接一个常驻 provider）的 consumer 只需实现 **Layer 1**；以 exec 子进程获取 fd 的 consumer 再加 **Layer 2**。

---

## 4. 句柄交接 wire 协议（normative）

### 4.1 传输

- provider 与 consumer 之间**必须**为一个已连接的 `AF_UNIX`、`SOCK_STREAM` 套接字。
- 一次成功交接由**单个** `sendmsg(2)` / `recvmsg(2)` 完成：携带 fd 的 ancillary 数据与元数据 payload 在同一条消息中。
- 套接字的建立方向（谁监听、谁拨号、或是否为 `socketpair` 继承）不属于本层，见 §5。

### 4.2 fd 传递

- provider **必须**通过 `SCM_RIGHTS` 携带 **至少 1 个** fd，并在 payload 的 `fd=` 中声明个数。一次交付多个 fd 即多队列：consumer 收取全部 N 个，并按 `fd=N` 校验。
- 被传递的 fd **必须**是对 `/dev/net/tun` 执行 `TUNSETIFF(IFF_TAP | IFF_NO_PI)` 绑定到目标 tap 设备得到的队列 fd。
- provider **应当**以非阻塞模式（`O_NONBLOCK`）交付该 fd：tap 队列只有在 `TUNSETIFF` 之后才被内核登记进 poll，使用带运行时轮询的语言（如 Go）的 consumer 依赖此点。
- 交接成功后，provider **应当**关闭其本地 fd；consumer 此时持有该队列的引用（生命周期见 §6）。

### 4.3 元数据 payload

payload 为单行 ASCII 文本，由空格分隔的 `key=value` 组成，**必须**以单个 `NUL`（`0x00`）结尾：

```
mac=02:00:00:00:80:01 mtu=1500 ip=169.254.1.1 fd=1\0
```

**帧规则**：

- consumer **必须**扫描第一个 `NUL`，仅解析其之前的字节，并**必须**忽略其后的任何字节。
- token 内以**第一个** `=` 分隔 key 与 value；value 可包含其后的 `=`；不含 `=` 的 token 为非法。
- payload（含结尾 `NUL`）**不应**超过 **512 字节**；consumer **应当**以 ≥512 字节缓冲区执行 `recvmsg`。
- consumer **必须**按 key 解析、**不应**依赖字段顺序。

**字段**：

- **必填** —— `fd`：本条消息 `SCM_RIGHTS` 携带的 fd 个数（十进制，≥1）。它既满足内核“`SCM_RIGHTS` 须伴随非空数据”的要求，也供 consumer 与实收 fd 数交叉校验。
- **推荐可选** —— provider 需要传达下列信息时**应当**使用这些约定名称，consumer 识别后**应当**采用：

  | key | 格式 | 含义 |
  | --- | --- | --- |
  | `mac` | `xx:xx:xx:xx:xx:xx` | provider 为该接口分配的 MAC。provider 可能据此识别该接口的流量，consumer 与之不一致可能导致丢包。 |
  | `mtu` | 十进制整数 | 接口 MTU。 |
  | `ip`  | IPv4 点分四段 | 接口的 L3 地址。 |

- **扩展** —— provider **可**加入任何其他 key（如端口 / 诊断标识等）；consumer **必须**忽略其无法识别的 key。这是本协议唯一的演进方式（§8）。

### 4.4 接收方算法（参考）

1. 以 ≥512 字节的数据缓冲区与可容纳预期 fd 数的 ancillary 缓冲区执行一次 `recvmsg`（ancillary 至少应能容纳 4 个 `int`）。
2. 从所有 `SOL_SOCKET / SCM_RIGHTS` 控制消息中**收集全部** fd——即使预期只有 1 个，也要全收以免泄漏。
3. 在数据缓冲区中扫描首个 `NUL`，解析其前的元数据行。
4. 若 `fd=` 之值与实际收到的 fd 数不一致，**必须**视为错误并关闭全部已收 fd。
5. 任意一步出错时，**必须**关闭所有已收 fd 后再返回，避免描述符泄漏。

fd 是对 tun 队列的内核引用，跨 network namespace 有效；consumer **无需**与 tap 设备处于同一 netns（见 §6）。

### 4.5 fd 的 TUN flags

v1 交付的 fd 固定设置 `IFF_TAP | IFF_NO_PI`，**不**含 `IFF_VNET_HDR`：fd 上没有 virtio-net header，TSO/GSO/checksum 等 offload 一律关闭。consumer 据此配置其后端，本协议不就 offload 进行协商。

---

## 5. 动态获取契约（normative）

当 consumer 不直接连接 provider，而是以子进程方式 **exec 一个 provider helper** 来获取 fd 时，适用本契约：runtime 负责建立套接字并经 `TAPFD_SOCKET` 告知 helper，由 helper 经该套接字执行 §4 交接。

### 5.1 runtime（consumer 侧）职责

1. 建立一个已连接的 `AF_UNIX SOCK_STREAM` 套接字（§5.2）。
2. 在 helper 的环境中设置 `TAPFD_SOCKET`（§5.3），然后 exec helper 命令。
3. 等待 helper 经该套接字发出**恰好一条** §4 消息，随后 helper **必须**以退出码 `0` 退出。
4. **必须**对整个过程施加超时；helper 非零退出或超时**必须**视为失败，此时 runtime **不应**启用该网卡。

### 5.2 套接字提供方式（二选一）

- **R1 — 继承的 socketpair fd（推荐）**：runtime `socketpair(AF_UNIX, SOCK_STREAM)` 建对，将其中一端通过 fd 继承交给 helper、自己读另一端。无文件系统对象、无路径竞争、生命周期随进程。
- **R2 — 监听路径**：runtime 在某 unix 套接字路径上监听，由 helper 拨号回连。适合 helper 与 runtime 非父子关系的场景。

### 5.3 套接字位置的通告：`TAPFD_SOCKET`

runtime **必须**在 helper 的环境变量 `TAPFD_SOCKET` 中告知套接字位置，helper **必须**读取它并据此发送交接消息：

```
TAPFD_SOCKET=fd=<N>     # R1：已连接 unix 套接字的继承 fd N
TAPFD_SOCKET=<path>     # R2：helper 拨号连接的文件系统路径
```

值以 `fd=` 前缀时，`<N>` 为 helper 继承到的已连接套接字 fd；否则整个值为一个路径，helper **必须**拨号连接之。该约定与具体 provider 无关：任意 helper 只要读取 `TAPFD_SOCKET` 并完成 §4，即可被任意 runtime 驱动，exec 命令中**无需**为某个 helper 硬编码套接字参数。

### 5.4 helper（provider 侧）职责

被 exec 的 helper **必须**：

1. 读取 `TAPFD_SOCKET`（缺失则以非零退出）。
2. 在打开 tap 或写套接字之前，**应当**校验目标接口处于可服务状态；若不可服务，**必须**以非零退出且**不**发送任何 fd。
3. 按 §4 经该套接字发送 fd + 元数据。
4. 成功后**应当**关闭本地 fd 并以退出码 `0` 退出；任何失败**必须**以非零退出。

若 helper 在一次调用中既分配接口又交接 fd，交接失败时**应当**回滚其分配，避免“已分配但未交付”的中间态。退出码约定见附录 B。

---

## 6. 生命周期与幂等

- **设备与 fd 解耦**：tap 设备的生命周期由 provider 独立管理，与交接出去的 fd 解耦。被传递的 fd 只是该设备的一个队列引用；consumer 关闭 fd **不会**销毁设备。provider **应当**以持久 tap（`TUNSETPERSIST`）承载该设备，使其在 fd 关闭后仍存在。
- **重新获取幂等**：consumer 进程退出会关闭其队列 fd（队列从 tap 解绑），但设备仍在；consumer **可**再次向 provider 发起交接，获取一个新的队列 fd。
- **fd 跨 netns**：tap 设备可能位于 provider 的某个 network namespace，但队列 fd 是内核引用，consumer **无需**进入该 netns 即可使用。

---

## 7. 安全考量

- **套接字访问即网络访问授权**：任何能读到该 unix 套接字的进程都会收到 tap 队列 fd。runtime **应当**严格限制套接字（如 `0600` 与受限父目录权限）；R1（继承 fd）天然不暴露文件系统对象，优于 R2。
- **fd 是能力（capability）**：持有该 fd 即可在该接口收发任意 L2 帧。请按“等同于授予该接口网络接入”来对待 fd 的传递与持有。
- **隔离 / 防伪由 provider 保证，而非 consumer**：L2 隔离、源地址防伪等安全属性应由 provider 的数据面保证（例如在出口改写源 MAC、按受信任的端口标识而非报文自带地址转发、代答 ARP 等）。即便 guest 伪造源地址，隔离性仍由 provider 维持；consumer 只需如实采用 §4.3 中 provider 给出的 `mac`。

---

## 8. 版本与前向兼容

本协议无显式版本字段；兼容性完全由“固定帧 + 扩展 key + 忽略未知 key”保证（§4.3）：provider 需要传达新信息时只增加新的 key，旧 consumer 会安全忽略之。consumer **禁止**因出现未知 key 而失败。帧结构（`SOCK_STREAM` + 单条 `recvmsg` + `SCM_RIGHTS` + NUL 结尾文本）本身不变。

---

## 9. 完整交接示例

R2（监听路径）一次握手的时序：

```
consumer (runtime)                          provider helper（被 exec，环境 TAPFD_SOCKET=/run/vm5.sock）
 │ listen(AF_UNIX, /run/vm5.sock)
 │ exec helper（注入 TAPFD_SOCKET）────────▶ │ 读 TAPFD_SOCKET；（应当）校验接口可服务
 │                                           │ open(/dev/net/tun)+TUNSETIFF(IFF_TAP|IFF_NO_PI)
 │                                           │ payload: mac=.. mtu=1500 ip=169.254.1.5 fd=1\0
 │ recvmsg() ◀──────────────────────────────  │ sendmsg(payload, SCM_RIGHTS[tapfd]); close(fd); exit 0
 │ 解析 payload；取 fd；以 mac=.. 配置 virtio-net；把 fd 交给 VMM 后端（如 CH --net fd=、Firecracker tap-fd）
```

接收侧最小实现（Go，使用参考库）：

```go
ln, _ := net.Listen("unix", "/run/vm5.sock")
c, _ := ln.Accept()
tapFile, meta, err := tapfd.RecvFd(c.(*net.UnixConn)) // 收 1 个 fd + 解析元数据
if err != nil { log.Fatal(err) }
// 若 meta.MAC 非空，必须镜像到 virtio-net；tapFile.Fd() 交给 VMM 的 tap 后端
fmt.Printf("mac=%s mtu=%d ip=%s\n", meta.MAC, meta.MTU, meta.InnerIP)
```

不依赖参考库时，可按 §4.4 直接基于 `recvmsg(2)` + `SCM_RIGHTS` 实现。可运行示例见 `examples/tapfd_receiver/`。

---

## 附录 A：元数据 payload ABNF

```abnf
message     = line NUL *OCTET        ; 接收方扫描首个 NUL，其后字节忽略
line        = pair *( SP pair )
pair        = key "=" value          ; 以首个 "=" 分隔；value 可含其后的 "="
key         = 1*( ALPHA / DIGIT / "_" )
value       = 1*VCHAR-no-SP          ; 可见 ASCII，不含 SP 与 NUL
SP          = %x20
NUL         = %x00
```

## 附录 B：helper 退出码约定

| 码 | 含义 |
| --- | --- |
| `0` | 成功，已交付 fd |
| 非零 | 失败：`TAPFD_SOCKET` 缺失 / 接口不可服务 / 打开 tap 失败 / `SCM_RIGHTS` 交接失败等。helper 失败时**不得**发送 fd；若为组合操作，应回滚已做的接口分配。 |
