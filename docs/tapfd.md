[English](tapfd.md) | [简体中文](tapfd_zh.md)

# tapfd — TAP device file-descriptor handoff protocol

In some virtualized networking deployments, a **provider** (switch or network backend) creates and manages a network interface (a TAP device), while a **consumer** (VMM or orchestrator, such as Cloud Hypervisor, Firecracker or QEMU) needs access to it to drive virtio-net. This protocol lets the provider perform a **file-descriptor handoff**: it sends the queue descriptors already bound to that TAP, together with the necessary metadata, to the consumer over a Unix socket. This avoids opening an interface by name and querying its configuration separately.

The protocol is self-contained: either side can implement it without knowing the other's internals. Sections 2 (handoff wire protocol), 3 (dynamic acquisition contract) and 4 (persistent provider socket) are **normative**. The requirement words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT** and **MAY** retain their RFC 2119 meanings. How a consumer represents networking in its own configuration (YAML/JSON, L3, routes, DNS and similar fields) is a consumer implementation detail, not part of this protocol.

Reference providers are `connector-ctl vswitch open-port` and `connector-ctl tapfd get` ([open-port](vswitch-operations.md#28-connector-ctl-vswitch-open-port) and [tapfd get](vswitch-operations.md#213-connector-ctl-tapfd-get)). The Go reference library, `github.com/kuasar-sandbox/connector/pkg/tapfd`, implements both sending and receiving. A runnable consumer example is in [`examples/tapfd_receiver/`](../examples/tapfd_receiver/).

<a id="1-概述"></a>
## 1. Overview

<a id="11-角色"></a>
### 1.1 Roles

- **provider** (sender/helper): opens TAP queue descriptors and sends them over the socket.
- **consumer** (receiver/VMM): receives the descriptors and configures its network interface from the metadata.
- **runtime**: consumer-side orchestration that establishes the socket and executes the helper according to section 3.

<a id="12-分层"></a>
### 1.2 Layers

```text
Layer 2  dynamic acquisition contract (normative, section 3) — exec model only
         the runtime tells the exec'ed provider helper where the socket
         is, via the TAPFD_SOCKET environment variable
            |
            v
Layer 1  fd handoff wire protocol (normative, section 2)
         SCM_RIGHTS fd passing + NUL-terminated key=value metadata line
```

Consumers connected directly to a provider (whether the provider connects back or the consumer connects to a persistent provider) need only implement **Layer 1** for descriptor handoff. Consumers acquiring descriptors by executing a child process additionally implement **Layer 2**. The request/status envelope for a persistent provider is defined in section 4.

<a id="2-句柄交接-wire-协议normative"></a>
## 2. Descriptor handoff wire protocol (normative)

<a id="21-传输"></a>
### 2.1 Transport

- The provider and consumer **MUST** communicate through a connected `AF_UNIX`, `SOCK_STREAM` socket.
- A successful handoff uses a **single** `sendmsg(2)`/`recvmsg(2)` exchange: descriptor-bearing ancillary data and the metadata payload are in the same message.
- The direction of socket establishment (which side listens or connects, or whether a `socketpair` is inherited) is outside this layer; see section 3.

<a id="22-fd-传递"></a>
### 2.2 Descriptor transfer

- The provider **MUST** carry **at least one** TAP queue descriptor through `SCM_RIGHTS` and declare its count in the payload's `fd=` field. Multiple TAP descriptors in one handoff represent multiple queues; the consumer receives all N descriptors.
- Each transferred TAP descriptor **MUST** be a queue descriptor obtained by opening `/dev/net/tun` and binding it to the target TAP device with `TUNSETIFF(IFF_TAP | IFF_NO_PI | IFF_VNET_HDR)`.
- The provider **SHOULD** deliver the descriptor in nonblocking mode (`O_NONBLOCK`). A TAP queue is registered with kernel polling only after `TUNSETIFF`; consumers using runtime polling, such as Go, depend on this ordering.
- **Optional network-namespace descriptor:** the provider **MAY** append a netns descriptor **after all TAP descriptors**, with its count declared by `netns_fd=` (0 or 1), for a consumer that needs to enter the TAP's namespace (sections 2.3 and 2.5). Netns descriptors are always at the **end** of the ancillary descriptor list. Thus the total ancillary descriptor count is `fd + netns_fd`.
- After a successful handoff, the provider **SHOULD** close its local descriptors; the consumer now holds these references. See section 5 for lifetime rules.

<a id="23-元数据-payload"></a>
### 2.3 Metadata payload

The payload is one ASCII line of space-separated `key=value` tokens and **MUST** end in a single `NUL` (`0x00`):

```text
port=1 mac=02:00:00:00:80:01 ip=169.254.1.1 fd=1\0
```

**Framing rules:**

- The consumer **MUST** locate the first `NUL`, parse only the bytes before it, and **MUST** ignore bytes after it.
- Split each token at its **first** `=`. A value may contain subsequent `=` characters. A token without `=` is invalid.
- The payload, including the terminating `NUL`, **SHOULD NOT** exceed **512 bytes**. The consumer **SHOULD** use a data buffer of at least 512 bytes for `recvmsg`.
- The consumer **MUST** parse by key and **SHOULD NOT** depend on field order.

**Fields:**

- **Required — `fd`:** the number of **TAP queue descriptors** carried by this message's `SCM_RIGHTS` (decimal, at least 1). This both supplies nonempty data alongside `SCM_RIGHTS` and lets the consumer cross-check descriptor counts (section 2.4).
- **Recommended optional fields:** a provider that needs to communicate the following information **SHOULD** use these names, and a consumer recognizing them **SHOULD** use the values:

  | Key | Format | Meaning |
  | --- | --- | --- |
  | `mac` | `xx:xx:xx:xx:xx:xx` | MAC address assigned by the provider. The provider may identify interface traffic using it; a mismatching consumer configuration may cause packet loss. |
  | `ip` | IPv4 dotted quad | The interface's L3 address. |
  | `port` | Decimal integer | Provider-side port/slot identifier for diagnostics and lookup. This extension field may be ignored by a consumer. The reference implementation (`pkg/tapfd`) always sends it as the **first** metadata token. |
  | `netns_fd` | Decimal integer, 0 or 1 | Number of netns descriptors appended **after** the TAP descriptors. Missing or `0` means none. When nonzero, the **last** `netns_fd` ancillary descriptors reference the TAP device's netns (section 2.5). The consumer splits the list into the first `fd` TAP descriptors and the trailing `netns_fd` netns descriptors. |

- **Extensions:** the provider **MAY** add other keys. The consumer **MUST** ignore unrecognized keys. `netns_fd` is optional: consumers request it when they need cross-namespace operations, and the provider decides whether its implementation supplies it (section 2.5).

<a id="24-接收方算法参考"></a>
### 2.4 Receiver algorithm (reference)

1. Call `recvmsg` once with a data buffer of at least 512 bytes and an ancillary buffer large enough for the expected descriptors. The latter should accommodate at least eight `int` values for multiple queues plus a trailing netns descriptor.
2. **Collect every descriptor** in all `SOL_SOCKET / SCM_RIGHTS` control messages, even when only one is expected, to avoid leaks.
3. Locate the first `NUL` in the data buffer and parse the preceding metadata line.
4. If the actual total descriptor count differs from `fd + netns_fd` (missing `netns_fd` means 0), the consumer **MUST** reject the handoff and close all received descriptors.
5. Split by position: the first `fd` descriptors are TAP queues; the final `netns_fd` descriptors are netns references.
6. On any error, the consumer **MUST** close all received descriptors before returning, to avoid descriptor leaks.

A TAP descriptor is a kernel reference to a TUN queue and remains usable across network namespaces. The consumer does **not** need to reside in the TAP device's netns (section 5).

<a id="25-netns-fd可选"></a>
### 2.5 Optional netns descriptor

`netns_fd` is an **optional** feature. When the payload includes `netns_fd=K` (K at least 1, currently limited to 1), the last K ancillary descriptors are open references to the TAP device's network namespace. Providers typically open `/proc/<pid>/ns/net` or `/run/netns/<name>`.

- **Requesting and providing:** a consumer **requests** this descriptor when it needs additional device operations across namespaces, such as entering the netns to inspect TAP metadata, capture packets or read statistics. Section 3.4 describes the reference request mechanism. The provider decides whether to **supply** it: a TAP in a separate netns can include the namespace descriptor; a TAP without namespace isolation does not need one, and ordinary section 2 handoff can still succeed.
- The consumer **MAY** call `setns(2, CLONE_NEWNET)` on the received netns descriptor to enter that namespace.
- Sending and receiving frames does not require a netns descriptor because TAP descriptors work across namespaces (section 5). The additional descriptor serves consumers that need to **enter** the namespace to operate on the device itself.
- A netns descriptor is also a capability (section 6): it is a reference used to enter the network namespace. Both sides should treat its transfer and possession accordingly.
- A consumer that does not need the netns descriptor **SHOULD** close it to avoid leaks.

<a id="26-fd-的-tun-flags"></a>
### 2.6 TUN flags on transferred descriptors

Transferred descriptors use `IFF_TAP | IFF_NO_PI | IFF_VNET_HDR`. Frames include a virtio-net header, the TAP framing expected by mainstream virtio VMMs such as Cloud Hypervisor, Firecracker and QEMU, so the consumer does not have to adapt the backend. The consumer **SHOULD** set the vnet header length for its virtio-net version (`TUNSETVNETHDRSZ`, usually 12 for `virtio_net_hdr_v1`).

Offload features (TSO/GSO/checksum) are negotiated normally between the consuming VMM and its guest. They are **not** part of this protocol, which imposes no offload convention or restriction.

<a id="3-动态获取契约normative"></a>
## 3. Dynamic acquisition contract (normative)

This contract applies when the consumer does not connect to a provider directly, but **executes a provider helper** as a child process to acquire descriptors. The runtime establishes the socket, communicates its location through `TAPFD_SOCKET`, and the helper performs the section 2 handoff through it.

<a id="31-runtimeconsumer-侧职责"></a>
### 3.1 Runtime responsibilities (consumer side)

1. Establish a connected `AF_UNIX SOCK_STREAM` socket (section 3.2).
2. Set `TAPFD_SOCKET` in the helper's environment (section 3.3), then execute the helper command.
3. Wait for the helper to send **exactly one** section 2 message through that socket. The helper then **MUST** exit with status `0`.
4. The runtime **MUST** impose a timeout on the entire operation. A nonzero helper exit or timeout **MUST** be treated as failure; the runtime **SHOULD NOT** enable the network interface in that case.

<a id="32-套接字提供方式二选一"></a>
### 3.2 Socket provisioning (choose one)

- **R1 — inherited socketpair descriptor (recommended):** the runtime creates a pair with `socketpair(AF_UNIX, SOCK_STREAM)`, passes one end to the helper through descriptor inheritance, and reads the other end. There is no filesystem object or pathname race; lifetime follows the processes.
- **R2 — listening pathname:** the runtime listens at a Unix socket pathname and the helper connects back. This also accommodates deployments where helper and runtime are not parent and child.

<a id="33-套接字位置的通告tapfd_socket"></a>
### 3.3 Advertising the socket: `TAPFD_SOCKET`

The runtime **MUST** advertise the socket in the helper's `TAPFD_SOCKET` environment variable. The helper **MUST** read it and send the handoff through the indicated socket:

```text
TAPFD_SOCKET=fd=<N>     # R1: inherited fd N of a connected unix socket
TAPFD_SOCKET=<path>     # R2: filesystem path the helper dials
```

For the `fd=` prefix, `<N>` is a connected socket descriptor inherited by the helper. Otherwise, the entire value is a pathname that the helper **MUST** connect to. This convention is provider-independent: any helper reading `TAPFD_SOCKET` and implementing section 2 can be driven by any runtime, without hardcoding helper-specific socket arguments into its command.

<a id="34-请求-netns-fdtapfd_want_netns"></a>
### 3.4 Requesting a netns descriptor: `TAPFD_WANT_NETNS`

A runtime requiring the TAP's namespace descriptor (section 2.5) **MAY** set `TAPFD_WANT_NETNS` to a truthy value (`1`/`true`/`yes`/`on`, case-insensitive) in the helper's environment. If the helper recognizes it and its TAP resides in a separate netns, it **SHOULD** append that namespace descriptor after the TAP descriptors and set `netns_fd=1`. When the variable is absent, empty or false, the helper **MUST NOT** append a netns descriptor. Setting the variable means the runtime will correctly split the trailing descriptor as specified in section 2.4.

<a id="35-helperprovider-侧职责"></a>
### 3.5 Helper responsibilities (provider side)

An executed helper **MUST**:

1. Read `TAPFD_SOCKET`, exiting nonzero when it is missing.
2. Before opening the TAP or writing the socket, it **SHOULD** verify that the target interface is serviceable. If it is not, the helper **MUST** exit nonzero and send **no** descriptors.
3. Send descriptors and metadata through the socket according to section 2. If `TAPFD_WANT_NETNS` is truthy and the TAP is in a separate namespace, append the namespace descriptor as described in section 3.4.
4. After success, it **SHOULD** close its local descriptors and exit `0`. Any failure **MUST** produce a nonzero exit status.

If one invocation both allocates an interface and hands off its descriptors, the helper **SHOULD** roll back the allocation on handoff failure, avoiding an allocated-but-undelivered intermediate state. Appendix B lists exit-status conventions.

<a id="4-持久-provider-socketnormative"></a>
## 4. Persistent provider socket (normative)

To avoid forking/executing a helper for every handoff, a provider may keep an `AF_UNIX SOCK_STREAM` listener running. The consumer connects, sends one request line, and receives one response on the same connection.

Request lines:

```text
TAPFD/1 PREPARE VSWITCH=sw0 INNER_IP=169.254.0.21\n
TAPFD/1 PREPARE VSWITCH=sw0 INNER_IP=169.254.0.21 TRANSIT_GATEWAY_IP=10.0.0.2 TRANSIT_GENEVE_VNI=42 TRANSIT_GENEVE_OPTS=0102:02:0000002a,0102:83:1122334455667788\n
TAPFD/1 OPEN want_netns=1 VSWITCH=sw0 PORT=3\n
TAPFD/1 RELEASE VSWITCH=sw0 PORT=3\n
```

- `TAPFD/1` is the protocol version. Operations are `PREPARE`, `OPEN` and `RELEASE`.
- `PREPARE` allocates and configures a port slot that can subsequently be opened with `OPEN`. `connector-ctl vswitch serve` accepts `INNER_IP` and optional `TRANSIT_GATEWAY_IP`, `TRANSIT_GENEVE_VNI`, `TRANSIT_GENEVE_OPTS` and `TRANSIT_MAC`. `transit_geneve_opts` is a comma-separated sequence of `CLASS:TYPE:DATA` items and uses the same parser as CLI `--transit-geneve-opt`. Class, type and data are hexadecimal; data length must be a multiple of four bytes; an empty value means no options. Caller ordering is preserved. Options are used only for connector-to-gateway outbound Geneve encapsulation; they do not appear on the return path or in the TAP FD payload.
- `OPEN` opens the queue descriptors of an allocated port and returns them using `SCM_RIGHTS`. `want_netns=1` has the same meaning as section 3.4: the consumer requests the TAP's netns descriptor.
- `RELEASE` releases an allocated port slot.
- Other `key=value` tokens are provider-specific. `connector-ctl vswitch serve` accepts `switch`/`vswitch`/`VSWITCH` and `port`/`PORT`.
- The line is limited to 512 bytes and must not contain `NUL` or embedded newlines. A canonical string representing up to 64 bytes of opaque Geneve options, including option headers, fits within that limit. Oversized requests explicitly return `BAD_REQUEST`.

A successful `OPEN` response adds a versioned status prefix before the section 2 metadata and returns it together with descriptors through `SCM_RIGHTS`:

```text
TAPFD/1 OK port=3 mac=02:00:00:00:80:01 ip=169.254.3.1 fd=1 netns_fd=1\0
```

Consumers **SHOULD** accept this `TAPFD/1 OK` prefix. They may also accept bare section 2 metadata for compatibility with exec helpers.

Successful `PREPARE`/`RELEASE` responses do not carry descriptors:

```text
TAPFD/1 OK port=3 floating_ip=100.100.96.3 mac=02:00:00:00:80:01 ip=169.254.0.21 mode=tap\n
TAPFD/1 OK port=3 released=1\n
```

Error responses do not carry descriptors:

```text
TAPFD/1 ERR code=PORT_UNAVAILABLE message=port_not_attached\n
```

Recommended error codes are `BAD_REQUEST`, `SWITCH_MISMATCH`, `PORT_INVALID`, `PORT_UNAVAILABLE` and `PROVIDER_INTERNAL`. A consumer receiving `ERR` **MUST NOT** enable the interface.

`connector-ctl vswitch serve --tapfd-listen /run/kuasar/connector/sw0/tapfd.sock` is the reference provider for this mode. It handles `PREPARE`/`OPEN`/`RELEASE` on the same persistent switch handle, avoiding repeated fork/exec and reopening pinned BPF maps on the hot path.

<a id="5-生命周期与幂等"></a>
## 5. Lifetime and idempotency

- **Device and descriptor lifetimes are separate:** a transferred descriptor is one TAP queue reference. The provider **SHOULD** use a persistent TAP (`TUNSETPERSIST`) when it independently manages a device that must survive descriptor closure. Closing consumer descriptors does not remove such a persistent device. For a nonpersistent TAP, including `connector-ctl tapfd get --new`, the device disappears when its last reference closes.
- **Reacquisition:** consumer exit closes its queue descriptors and detaches those queues. If the provider-managed TAP still exists, the consumer **MAY** request another handoff to obtain new queue descriptors. A nonpersistent TAP that has disappeared must be recreated before another handoff; this protocol does not make device recreation or network-resource allocation idempotent.
- **Descriptors work across netns boundaries:** the TAP may be in a provider-owned namespace, but a queue descriptor is a kernel reference. The consumer does **not** need to enter that namespace to use it.

<a id="6-安全考量"></a>
## 6. Security considerations

- **Socket access grants network access:** a process that can receive from this Unix socket receives TAP queue descriptors. The runtime **SHOULD** strictly restrict socket access, for example using `0600` and restricted parent-directory permissions. R1 (inherited descriptors) exposes no filesystem object and is preferable to R2.
- **A descriptor is a capability:** its holder can send and receive arbitrary L2 frames on the interface. Treat transfer and possession as granting network access through that interface.
- **Isolation and anti-spoofing belong to the provider, not the consumer:** the provider's data plane should enforce L2 isolation and source-address protection, for example by rewriting source MACs, forwarding by trusted port identity rather than packet-supplied addresses, and answering ARP. Guest address spoofing must not defeat provider isolation. The consumer should faithfully use the provider's `mac` from section 2.3.

<a id="6-扩展方式"></a>
<a id="7-扩展方式"></a>
## 7. Extensions

The bare metadata frame in section 2 has no explicit version field; it evolves through fixed framing and extension keys. The persistent-provider envelope in section 4 is separately versioned with `TAPFD/1`. The base handoff framing (`SOCK_STREAM`, a single `recvmsg`, `SCM_RIGHTS` and NUL-terminated text) remains unchanged. There are two kinds of extension:

- **Text-only keys:** providers add `key=value` fields; consumers **MUST** ignore unknown keys and **MUST NOT** fail solely because of them. These additions need no negotiation.
- **Keys changing descriptor counts**, such as `netns_fd` (section 2.5): because they change the ancillary descriptor count, providers send the additional descriptors **only when requested by the consumer**. The reference implementation uses `TAPFD_WANT_NETNS` (section 3.4). A requesting consumer must split by `fd + netns_fd` as described in section 2.4; a consumer that did not request the feature receives no extra descriptors. Such keys **MUST** default to appending no descriptors, as with `netns_fd=0`.

<a id="7-交接示例"></a>
<a id="8-交接示例"></a>
## 8. Handoff example

One R2 (listening pathname) handshake:

```text
consumer (runtime)                       provider helper (exec'ed with TAPFD_SOCKET=/run/vm5.sock)
 | listen(AF_UNIX, /run/vm5.sock)
 | exec helper (inject TAPFD_SOCKET) ---> | read TAPFD_SOCKET; check interface is serviceable
 |                                       | open(/dev/net/tun) + TUNSETIFF(IFF_TAP|IFF_NO_PI|IFF_VNET_HDR)
 |                                       | payload: port=5 mac=.. ip=169.254.1.5 fd=1\0
 | recvmsg() <--------------------------- | sendmsg(payload, SCM_RIGHTS[tapfd]); close(fd); exit 0
 | parse payload; take fd; mirror mac= onto virtio-net;
 | hand fd to the VMM backend (CH --net fd=, Firecracker tap fd)
```

Minimal receiving code using the Go reference library:

```go
ln, _ := net.Listen("unix", "/run/vm5.sock")
c, _ := ln.Accept()
tapFile, meta, err := tapfd.RecvFd(c.(*net.UnixConn)) // Receive one TAP fd and parse metadata.
if err != nil { log.Fatal(err) }
// Mirror a nonempty meta.MAC to virtio-net; pass tapFile.Fd() to the VMM TAP backend.
fmt.Printf("mac=%s ip=%s\n", meta.MAC, meta.InnerIP)
```

When the provider also supplies a netns descriptor (section 2.5), use `RecvFdsWithNetns` to obtain it. `RecvFd`/`RecvFds` discard and close that descriptor:

```go
tapFiles, netnsFile, meta, err := tapfd.RecvFdsWithNetns(c.(*net.UnixConn))
if err != nil { log.Fatal(err) }
// Pass tapFiles[0] to the VMM; netnsFile (possibly nil) can be used with setns(CLONE_NEWNET).
```

Without the library, implement section 2.4 directly with `recvmsg(2)` and `SCM_RIGHTS`. The runnable Go example is in [`examples/tapfd_receiver/`](../examples/tapfd_receiver/). The release package's `tap_test.sh` embeds a Python receiver and does not require building that example on site.

<a id="8-see-also"></a>
## 9. See also

- [vSwitch operations](vswitch-operations.md): `open-port` and `connector-ctl tapfd get` implement the provider side. [vSwitch design](vswitch.md#67-tap-descriptor-handoff) records implementation tradeoffs.
- [`pkg/tapfd`](../pkg/tapfd/): Go reference library. Provider: `OpenTap`/`SendFd`; consumer: `RecvFd`/`RecvFds`/`RecvFdsWithNetns`; connection setup: `ConnectUnix`/`UnixConnFromFd`.
- [`examples/tapfd_receiver/`](../examples/tapfd_receiver/): runnable consumer example.
- unix(7), cmsg(3): `SCM_RIGHTS` descriptor passing.

<a id="附录-a元数据-payload-abnf"></a>
## Appendix A: metadata payload ABNF

```abnf
message     = line NUL *OCTET        ; Scan the first NUL; ignore subsequent bytes.
line        = pair *( SP pair )
pair        = key "=" value          ; Split at the first "="; value may contain more.
key         = 1*( ALPHA / DIGIT / "_" )
value       = 1*VCHAR-no-SP          ; Visible ASCII excluding SP and NUL.
SP          = %x20
NUL         = %x00
```

<a id="附录-bhelper-退出码约定"></a>
## Appendix B: helper exit-status convention

| Status | Meaning |
| --- | --- |
| `0` | Success: descriptors delivered. |
| Nonzero | Failure, such as missing `TAPFD_SOCKET`, an unserviceable interface, TAP-open failure or `SCM_RIGHTS` handoff failure. A failing helper **MUST NOT** send descriptors; a combined operation should roll back any interface allocation. |
