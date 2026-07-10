# tapfd — tap 设备文件描述符交接协议

某些虚拟化网络方案中,网络接口(一个 tap 设备)由 **provider**(交换机/网络后端)创建并
管理,而 **consumer**(VMM/编排器:cloud-hypervisor、Firecracker、QEMU 等)需要拿到它来
驱动 virtio-net。本协议让 provider 通过一次**文件描述符交接(fd handoff)**,把已绑定该
tap 的队列 fd 连同必要元数据经 unix 套接字交给 consumer,免去"按名打开 + 另行查询配置"。

协议自洽:双方据此对接,无需了解对方的内部实现。§2(句柄交接 wire 协议)与 §3(动态获取
契约)为 **normative**;规范性关键词**必须/禁止/应当/不应/可**对应 RFC 2119 的
MUST / MUST NOT / SHOULD / SHOULD NOT / MAY。consumer 如何在自身配置中建模网络
(YAML/JSON 格式、L3/路由/DNS 等字段)是 consumer 的实现细节,不属于本协议。

参考实现:`connector-ctl vswitch open-port` 与`connector-ctl tapfd get` 子命令 是 provider 实现
([vswitch.md](vswitch.md) §2.8、§2.13);Go 参考库
`github.com/kuasar-sandbox/connector/pkg/tapfd` 覆盖收发两侧;可运行的
consumer 示例见源码树 `examples/tapfd_receiver/`。

## 1. 概述

### 1.1 角色

- **provider**(发送方/sender/helper):打开 tap 队列 fd 并经套接字发出的一方。
- **consumer**(接收方/receiver/VMM):接收 fd 并据元数据配置网卡的一方。
- **runtime**:consumer 侧负责建立套接字、按 §3 exec helper 的编排逻辑。

### 1.2 分层

```
Layer 2  dynamic acquisition contract (normative, §3) — exec model only
         the runtime tells the exec'ed provider helper where the socket
         is, via the TAPFD_SOCKET environment variable
            │
            ▼
Layer 1  fd handoff wire protocol (normative, §2)
         SCM_RIGHTS fd passing + NUL-terminated key=value metadata line
```

直接连接 provider(provider 拨号,或 consumer 连接一个常驻 provider)的 consumer 只需
实现 **Layer 1**;以 exec 子进程获取 fd 的 consumer 再加 **Layer 2**。

## 2. 句柄交接 wire 协议(normative)

### 2.1 传输

- provider 与 consumer 之间**必须**为一个已连接的 `AF_UNIX`、`SOCK_STREAM` 套接字。
- 一次成功交接由**单个** `sendmsg(2)`/`recvmsg(2)` 完成:携带 fd 的 ancillary 数据与
  元数据 payload 在同一条消息中。
- 套接字的建立方向(谁监听、谁拨号、或是否为 `socketpair` 继承)不属于本层,见 §3。

### 2.2 fd 传递

- provider **必须**通过 `SCM_RIGHTS` 携带**至少 1 个** tap 队列 fd,并在 payload 的
  `fd=` 中声明个数。一次交付多个 tap fd 即多队列:consumer 收取全部 N 个。
- 被传递的 tap fd **必须**是对 `/dev/net/tun` 执行
  `TUNSETIFF(IFF_TAP | IFF_NO_PI | IFF_VNET_HDR)` 绑定到目标 tap 设备得到的队列 fd。
- provider **应当**以非阻塞模式(`O_NONBLOCK`)交付该 fd:tap 队列只有在 `TUNSETIFF`
  之后才被内核登记进 poll,使用带运行时轮询的语言(如 Go)的 consumer 依赖此点。
- **可选的 netns fd**:provider **可**在全部 tap fd **之后**再追加 netns fd(个数由
  payload 的 `netns_fd=` 声明,0 或 1),交给需要进入 tap 所在 network namespace 的
  consumer(见 §2.3、§2.5)。netns fd 永远排在 ancillary 的**末尾**,故 ancillary 内
  fd 总数 = `fd` + `netns_fd`。
- 交接成功后,provider **应当**关闭其本地 fd;consumer 此时持有这些引用
  (生命周期见 §5)。

### 2.3 元数据 payload

payload 为单行 ASCII 文本,由空格分隔的 `key=value` 组成,**必须**以单个 `NUL`(`0x00`)
结尾:

```
port=1 mac=02:00:00:00:80:01 ip=169.254.1.1 fd=1\0
```

**帧规则**:

- consumer **必须**扫描第一个 `NUL`,仅解析其之前的字节,并**必须**忽略其后的任何字节。
- token 内以**第一个** `=` 分隔 key 与 value;value 可包含其后的 `=`;不含 `=` 的
  token 为非法。
- payload(含结尾 `NUL`)**不应**超过 **512 字节**;consumer **应当**以 ≥512 字节缓冲区
  执行 `recvmsg`。
- consumer **必须**按 key 解析、**不应**依赖字段顺序。

**字段**:

- **必填** —— `fd`:本条消息 `SCM_RIGHTS` 携带的 **tap 队列 fd** 个数(十进制,≥1)。
  它既满足内核"`SCM_RIGHTS` 须伴随非空数据"的要求,也供 consumer 交叉校验(见 §2.4)。
- **推荐可选** —— provider 需要传达下列信息时**应当**使用这些约定名称,consumer 识别后
  **应当**采用:

  | key | 格式 | 含义 |
  | --- | --- | --- |
  | `mac` | `xx:xx:xx:xx:xx:xx` | provider 为该接口分配的 MAC。provider 可能据此识别该接口的流量,consumer 与之不一致可能导致丢包。 |
  | `ip`  | IPv4 点分四段 | 接口的 L3 地址。 |
  | `port` | 十进制整数 | provider 侧端口/槽位标识,仅供诊断/回查(扩展字段,consumer 可忽略)。参考实现(`pkg/tapfd`)总是把它作为元数据行的**首个** token 发出。 |
  | `netns_fd` | 十进制整数(0 或 1) | 紧跟在 tap fd **之后**追加的 netns fd 个数;缺省/`0` 表示未附带。非 0 时,ancillary 的**最后** `netns_fd` 个 fd 为 tap 设备所在 netns 的引用(见 §2.5)。consumer 据此把 ancillary 切分为前 `fd` 个 tap fd 与后 `netns_fd` 个 netns fd。 |

- **扩展** —— provider **可**加入任何其他 key;consumer **必须**忽略其无法识别的 key。
  `netns_fd` 是一个可选特性:consumer 在需要跨 netns 操作时请求它,provider 按自身实现
  决定是否提供(见 §2.5)。

### 2.4 接收方算法(参考)

1. 以 ≥512 字节的数据缓冲区与可容纳预期 fd 数的 ancillary 缓冲区执行一次 `recvmsg`
   (ancillary 至少应能容纳 8 个 `int`,以兼容多队列 + 末尾 netns fd)。
2. 从所有 `SOL_SOCKET / SCM_RIGHTS` 控制消息中**收集全部** fd——即使预期只有 1 个,
   也要全收以免泄漏。
3. 在数据缓冲区中扫描首个 `NUL`,解析其前的元数据行。
4. 若实际收到的 fd 总数与 `fd` + `netns_fd`(缺省视 `netns_fd=0`)之和不一致,**必须**
   视为错误并关闭全部已收 fd。
5. 按位置切分:前 `fd` 个为 tap 队列 fd,末尾 `netns_fd` 个为 netns fd。
6. 任意一步出错时,**必须**关闭所有已收 fd 后再返回,避免描述符泄漏。

tap fd 是对 tun 队列的内核引用,跨 network namespace 有效;consumer **无需**与 tap
设备处于同一 netns(见 §5)。

### 2.5 netns fd(可选)

`netns_fd` 是一个**可选支持**的特性。当 payload 含 `netns_fd=K`(K≥1,目前上限 1)时,
ancillary 末尾的 K 个 fd 是 tap 设备所在 network namespace 的打开引用(provider 侧
通常来自 `/proc/<pid>/ns/net` 或 `/run/netns/<name>`)。

- **请求与提供**:consumer 在需要跨 netns 对设备做额外操作时**请求**它(如进入 netns
  读取 tap 元数据/抓包/读统计;参考实现的请求方式见 §3.4)。provider 按自身实现决定
  是否**提供**:tap 处于独立 netns 时提供其 netns fd;若 provider 的 tap 没有 netns
  隔离,则无需提供(仍可正常完成 §2 的 tap fd 交接)。
- consumer **可**对收到的 netns fd 执行 `setns(2, CLONE_NEWNET)` 进入该 netns。
- 收发帧本身无需 netns fd(tap fd 跨 netns 可用,§5);netns fd 仅服务于需要**进入**
  该 netns 操作设备本体的 consumer。
- netns fd 同样是一种能力(capability,见 §6):持有它即可进入该网络命名空间,provider
  与 consumer 都应按此对待其传递与持有。
- consumer 不需要 netns fd 时**应当**关闭它以免泄漏。

### 2.6 fd 的 TUN flags

交付的 fd 设置 `IFF_TAP | IFF_NO_PI | IFF_VNET_HDR`:fd 带 virtio-net header——这是
cloud-hypervisor、Firecracker、QEMU 等主流 virtio VMM 对 tap fd 的预期帧格式,免去
consumer 自行改装后端。consumer **应当**按其 virtio-net 版本设置 vnet_hdr 长度
(`TUNSETVNETHDRSZ`,通常为 12 = `virtio_net_hdr_v1`)。

offload(TSO/GSO/checksum)由 consuming VMM 与其 guest 按常规协商,**不**属于本协议;
本协议不就 offload 做任何约定或限制。

## 3. 动态获取契约(normative)

当 consumer 不直接连接 provider,而是以子进程方式 **exec 一个 provider helper** 来获取
fd 时,适用本契约:runtime 负责建立套接字并经 `TAPFD_SOCKET` 告知 helper,由 helper 经
该套接字执行 §2 交接。

### 3.1 runtime(consumer 侧)职责

1. 建立一个已连接的 `AF_UNIX SOCK_STREAM` 套接字(§3.2)。
2. 在 helper 的环境中设置 `TAPFD_SOCKET`(§3.3),然后 exec helper 命令。
3. 等待 helper 经该套接字发出**恰好一条** §2 消息,随后 helper **必须**以退出码 `0`
   退出。
4. **必须**对整个过程施加超时;helper 非零退出或超时**必须**视为失败,此时 runtime
   **不应**启用该网卡。

### 3.2 套接字提供方式(二选一)

- **R1 — 继承的 socketpair fd(推荐)**:runtime `socketpair(AF_UNIX, SOCK_STREAM)`
  建对,将其中一端通过 fd 继承交给 helper、自己读另一端。无文件系统对象、无路径竞争、
  生命周期随进程。
- **R2 — 监听路径**:runtime 在某 unix 套接字路径上监听,由 helper 拨号回连。适合
  helper 与 runtime 非父子关系的场景。

### 3.3 套接字位置的通告:`TAPFD_SOCKET`

runtime **必须**在 helper 的环境变量 `TAPFD_SOCKET` 中告知套接字位置,helper **必须**
读取它并据此发送交接消息:

```
TAPFD_SOCKET=fd=<N>     # R1: inherited fd N of a connected unix socket
TAPFD_SOCKET=<path>     # R2: filesystem path the helper dials
```

值以 `fd=` 前缀时,`<N>` 为 helper 继承到的已连接套接字 fd;否则整个值为一个路径,
helper **必须**拨号连接之。该约定与具体 provider 无关:任意 helper 只要读取
`TAPFD_SOCKET` 并完成 §2,即可被任意 runtime 驱动,exec 命令中**无需**为某个 helper
硬编码套接字参数。

### 3.4 请求 netns fd:`TAPFD_WANT_NETNS`

需要 tap 所在 netns fd(§2.5)的 runtime **可**在 helper 环境中设置 `TAPFD_WANT_NETNS`
为真值(`1`/`true`/`yes`/`on`,大小写不敏感);helper 识别后,若其实现的 tap 处于独立
netns,则**应当**在 tap fd 之后追加该 netns fd 并置 `netns_fd=1`。该变量缺省/为空/为
假值时,helper **禁止**追加 netns fd。runtime 设置它即表示自己会按 §2.4 正确切分末尾的
netns fd。

### 3.5 helper(provider 侧)职责

被 exec 的 helper **必须**:

1. 读取 `TAPFD_SOCKET`(缺失则以非零退出)。
2. 在打开 tap 或写套接字之前,**应当**校验目标接口处于可服务状态;若不可服务,**必须**
   以非零退出且**不**发送任何 fd。
3. 按 §2 经该套接字发送 fd + 元数据;若 `TAPFD_WANT_NETNS` 为真值且其 tap 处于独立
   netns,则按 §3.4 追加 netns fd。
4. 成功后**应当**关闭本地 fd 并以退出码 `0` 退出;任何失败**必须**以非零退出。

若 helper 在一次调用中既分配接口又交接 fd,交接失败时**应当**回滚其分配,避免"已分配但
未交付"的中间态。退出码约定见附录 B。

## 4. 持久 provider socket(normative)

为避免每次交接都 fork/exec helper,provider 可长期监听一个 `AF_UNIX SOCK_STREAM`
套接字。consumer 连接该 socket,发送一行请求,provider 在同一连接上返回一条响应。

请求行:

```text
TAPFD/1 OPEN want_netns=1 VSWITCH=sw0 PORT=3\n
```

- `TAPFD/1` 是协议版本,`OPEN` 是当前唯一操作。
- `want_netns=1` 与 §3.4 语义相同:consumer 请求 provider 追加 tap 所在 netns fd。
- 其余 `key=value` token 是 provider 私有字段。`connector-ctl vswitch serve` 接受
  `switch`/`vswitch`/`VSWITCH` 与 `port`/`PORT`。
- 行最大 512 字节,不得包含 NUL 或内嵌换行。

成功响应在 §2 metadata 前加版本化状态前缀,并与 fd 一起通过 `SCM_RIGHTS` 返回:

```text
TAPFD/1 OK port=3 mac=02:00:00:00:80:01 ip=169.254.3.1 fd=1 netns_fd=1\0
```

consumer **应当**接受该 `TAPFD/1 OK` 前缀;为兼容 exec helper,也可接受裸 §2 metadata。

失败响应不携带 fd:

```text
TAPFD/1 ERR code=PORT_UNAVAILABLE message=port_not_attached\n
```

错误码建议使用 `BAD_REQUEST`、`SWITCH_MISMATCH`、`PORT_INVALID`、
`PORT_UNAVAILABLE`、`PROVIDER_INTERNAL`。收到 `ERR` 时 consumer **不得**启用网卡。

`connector-ctl vswitch serve --tapfd-listen /run/kuasar/connector/sw0/tapfd.sock`
是本模式的参考 provider。它复用 `open-port` 的 slot 校验、tap 打开、metadata 生成与
SCM_RIGHTS 发送路径,仅把"谁拨号谁监听"改为 consumer 拨号 provider。

## 5. 生命周期与幂等

- **设备与 fd 解耦**:tap 设备的生命周期由 provider 独立管理,与交接出去的 fd 解耦。
  被传递的 fd 只是该设备的一个队列引用;consumer 关闭 fd **不会**销毁设备。provider
  **应当**以持久 tap(`TUNSETPERSIST`)承载该设备,使其在 fd 关闭后仍存在。
- **重新获取幂等**:consumer 进程退出会关闭其队列 fd(队列从 tap 解绑),但设备仍在;
  consumer **可**再次向 provider 发起交接,获取一个新的队列 fd。
- **fd 跨 netns**:tap 设备可能位于 provider 的某个 network namespace,但队列 fd 是
  内核引用,consumer **无需**进入该 netns 即可使用。

## 6. 安全考量

- **套接字访问即网络访问授权**:任何能读到该 unix 套接字的进程都会收到 tap 队列 fd。
  runtime **应当**严格限制套接字(如 `0600` 与受限父目录权限);R1(继承 fd)天然不
  暴露文件系统对象,优于 R2。
- **fd 是能力(capability)**:持有该 fd 即可在该接口收发任意 L2 帧。请按"等同于授予
  该接口网络接入"来对待 fd 的传递与持有。
- **隔离/防伪由 provider 保证,而非 consumer**:L2 隔离、源地址防伪等安全属性应由
  provider 的数据面保证(例如在出口改写源 MAC、按受信任的端口标识而非报文自带地址转发、
  代答 ARP 等)。即便 guest 伪造源地址,隔离性仍由 provider 维持;consumer 只需如实
  采用 §2.3 中 provider 给出的 `mac`。

## 6. 扩展方式

本协议无显式版本字段,靠"固定帧 + 扩展 key"演进。帧结构(`SOCK_STREAM` + 单条
`recvmsg` + `SCM_RIGHTS` + NUL 结尾文本)本身不变,扩展分两类:

- **纯文本 key**:provider 增加新的 `key=value`;consumer **必须**忽略其无法识别的
  key(**禁止**因此失败)。无需协商即可加入。
- **会改变 fd 计数的 key**(如 `netns_fd`,§2.5):因为会改变 ancillary 中的 fd 数,
  provider **仅在 consumer 请求时**才发送(参考实现用 §3.4 的 `TAPFD_WANT_NETNS`)。
  consumer 既然请求,就应按 §2.4 的 `fd + netns_fd` 切分;未请求的 consumer 不会收到
  额外 fd。此类 key 缺省值**必须**为"不追加 fd"(如 `netns_fd` 缺省为 0)。

## 7. 交接示例

R2(监听路径)一次握手的时序:

```
consumer (runtime)                       provider helper (exec'ed with TAPFD_SOCKET=/run/vm5.sock)
 │ listen(AF_UNIX, /run/vm5.sock)
 │ exec helper (inject TAPFD_SOCKET) ──▶ │ read TAPFD_SOCKET; check interface is serviceable
 │                                       │ open(/dev/net/tun) + TUNSETIFF(IFF_TAP|IFF_NO_PI|IFF_VNET_HDR)
 │                                       │ payload: port=5 mac=.. ip=169.254.1.5 fd=1\0
 │ recvmsg() ◀────────────────────────── │ sendmsg(payload, SCM_RIGHTS[tapfd]); close(fd); exit 0
 │ parse payload; take fd; mirror mac= onto virtio-net;
 │ hand fd to the VMM backend (CH --net fd=, Firecracker tap fd)
```

接收侧最小实现(Go,使用参考库):

```go
ln, _ := net.Listen("unix", "/run/vm5.sock")
c, _ := ln.Accept()
tapFile, meta, err := tapfd.RecvFd(c.(*net.UnixConn)) // 收 1 个 tap fd + 解析元数据
if err != nil { log.Fatal(err) }
// 若 meta.MAC 非空,必须镜像到 virtio-net;tapFile.Fd() 交给 VMM 的 tap 后端
fmt.Printf("mac=%s ip=%s\n", meta.MAC, meta.InnerIP)
```

若 provider 还会附带 netns fd(§2.5),改用 `RecvFdsWithNetns` 把它取出(`RecvFd`/
`RecvFds` 会丢弃并关闭 netns fd):

```go
tapFiles, netnsFile, meta, err := tapfd.RecvFdsWithNetns(c.(*net.UnixConn))
if err != nil { log.Fatal(err) }
// tapFiles[0] 交给 VMM;netnsFile(可能为 nil)可用于 setns(CLONE_NEWNET)
```

不依赖参考库时,可按 §2.4 直接基于 `recvmsg(2)` + `SCM_RIGHTS` 实现。Go 示例见
源码树 `examples/tapfd_receiver/`;发布包中的 `tap_test.sh` 使用内嵌 Python receiver,
不要求现场构建该示例。

## 8. See Also

- [vswitch.md](vswitch.md) — connector 设计与命令参考;`open-port`(§2.8)与
  `connector-ctl tapfd get`(§2.13)是本协议的 provider 实现,§6.7 记录其实现取舍。
- `pkg/tapfd` — Go 参考库:provider 侧 `OpenTap`/`SendFd`,consumer 侧
  `RecvFd`/`RecvFds`/`RecvFdsWithNetns`,建连 `ConnectUnix`/`UnixConnFromFd`。
- 源码树 `examples/tapfd_receiver/` — 可运行的 consumer 示例。
- unix(7)、cmsg(3) — `SCM_RIGHTS` 文件描述符传递。

## 附录 A:元数据 payload ABNF

```abnf
message     = line NUL *OCTET        ; 接收方扫描首个 NUL,其后字节忽略
line        = pair *( SP pair )
pair        = key "=" value          ; 以首个 "=" 分隔;value 可含其后的 "="
key         = 1*( ALPHA / DIGIT / "_" )
value       = 1*VCHAR-no-SP          ; 可见 ASCII,不含 SP 与 NUL
SP          = %x20
NUL         = %x00
```

## 附录 B:helper 退出码约定

| 码 | 含义 |
| --- | --- |
| `0` | 成功,已交付 fd |
| 非零 | 失败:`TAPFD_SOCKET` 缺失/接口不可服务/打开 tap 失败/`SCM_RIGHTS` 交接失败等。helper 失败时**不得**发送 fd;若为组合操作,应回滚已做的接口分配。 |
