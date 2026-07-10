// connector-ctl tapfd get opens a tap device and hands its queue fd to a consumer over
// TAPFD_SOCKET via SCM_RIGHTS — the tapfd handoff protocol.
// It is a complete, standalone provider helper: a VMM orchestrator (or a test)
// sets TAPFD_SOCKET and execs it to obtain a virtio-net-framed tap fd.
//
//	connector-ctl tapfd get <tap>          open an existing tap and hand off its queue fd
//	connector-ctl tapfd get --new [<tap>]  create a tap (auto-named when <tap> is omitted)
//
// The delivered fd carries IFF_TAP|IFF_NO_PI|IFF_VNET_HDR (the framing
// cloud-hypervisor / Firecracker / QEMU expect on a tap fd). Optional
// --host-cidr assigns a host-side IP and brings the tap up (a point-to-point
// peer, handy for connectivity tests); --mac/--ip populate the handoff
// metadata line. Run as root (touches /dev/net/tun and `ip`).
//
// A tap created via --new is NOT persistent: the handed-off fd keeps it alive
// for the consumer; when all references close, the device is removed.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"unsafe"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

// ifReq mirrors struct ifreq (name + flags, padded to the ABI size).
type ifReq struct {
	Name  [16]byte
	Flags uint16
	_     [22]byte
}

var tapfdGetCmd = &cobra.Command{
	Use:                "get [tap]",
	Short:              "Open a tap and hand its queue fd to TAPFD_SOCKET",
	DisableFlagParsing: true,
	Long: `Open an existing tap device, or create one with --new, and hand its
IFF_VNET_HDR queue fd to TAPFD_SOCKET via SCM_RIGHTS.

The optional metadata flags populate the tapfd handoff line consumed by the
VMM side.`,
	RunE: runTapfdGetCmd,
}

func runTapfdGetCmd(cmd *cobra.Command, args []string) error {
	fs := flag.NewFlagSet("tapfd get", flag.ContinueOnError)
	fs.SetOutput(cmd.ErrOrStderr())
	newTap := fs.Bool("new", false, "create <tap> if it does not exist (default: require an existing tap)")
	hostCIDR := fs.String("host-cidr", "", "assign this host-side IP/CIDR and bring <tap> up (point-to-point peer for tests)")
	mac := fs.String("mac", "", "guest MAC to advertise in the handoff metadata")
	ip := fs.String("ip", "", "guest inner IP in the metadata (bare or CIDR)")
	fs.Usage = func() {
		fmt.Fprintf(cmd.ErrOrStderr(), "usage: connector-ctl tapfd get [flags] [<tap>]\n\n"+
			"Opens <tap> and hands its IFF_VNET_HDR queue fd to TAPFD_SOCKET via\n"+
			"SCM_RIGHTS (tapfd handoff protocol). <tap> must already exist unless\n"+
			"--new; with --new and no name, a tap is auto-allocated.\n\nflags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 1 {
		fs.Usage()
		return fmt.Errorf("tapfd get: accepts at most one tap argument")
	}
	tap := fs.Arg(0)
	if tap == "" && !*newTap {
		fs.Usage()
		return fmt.Errorf("tapfd get: <tap> is required (or use --new to auto-create one)")
	}
	return runTapfdGet(tap, *newTap, *hostCIDR, *mac, *ip)
}

func runTapfdGet(tap string, create bool, hostCIDR, mac, ip string) error {
	sockSpec := os.Getenv(tapSocketEnv)
	if sockSpec == "" {
		return fmt.Errorf("%s not set (run me as a tapfd helper)", tapSocketEnv)
	}
	if !create {
		if _, err := os.Stat("/sys/class/net/" + tap); err != nil {
			return fmt.Errorf("tap %q does not exist (pass --new to create it)", tap)
		}
	} else if tap == "" {
		tap = "tap%d" // kernel picks the lowest free number (one-shot, disposable)
	}

	conn, err := dial(sockSpec)
	if err != nil {
		return err
	}
	defer conn.Close()

	// TUNSETIFF attaches a queue, creating the (non-persistent) device if absent
	// (only reachable with --new) and resolving any "%d" template to the real
	// name. The handed-off fd keeps the device alive for the consumer.
	queue, name, err := openTap(tap)
	if err != nil {
		return err
	}
	defer unix.Close(queue)
	fmt.Fprintf(os.Stderr, "connector-ctl tapfd get: handing off tap %s\n", name)

	if err := prepareTap(name, hostCIDR); err != nil {
		return err
	}

	payload := buildPayload(mac, ip)
	if _, _, err := conn.WriteMsgUnix(payload, unix.UnixRights(queue), nil); err != nil {
		return fmt.Errorf("send fd: %w", err)
	}
	return nil
}

// prepareTap makes the tap serviceable before handoff, via raw netlink (no
// external `ip`): it ALWAYS brings the device up — a handed-off tap that is
// administratively down is a silent dead link — and
// additionally assigns a host-side IP when hostCIDR is given (so the host
// kernel can act as a point-to-point peer for connectivity tests). The device
// must already exist (openTap created/attached it). Called before the
// SCM_RIGHTS send, so a failure here aborts with a non-zero exit and no fd is
// handed off.
func prepareTap(tap, hostCIDR string) error {
	ifindex, err := ifindexOf(tap)
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("netlink socket: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("netlink bind: %w", err)
	}

	if err := nlLinkUp(fd, 1, ifindex); err != nil {
		return fmt.Errorf("bring %s up: %w", tap, err)
	}
	if hostCIDR != "" {
		ip, ipnet, err := net.ParseCIDR(hostCIDR)
		if err != nil {
			return fmt.Errorf("parse host-cidr %q: %w", hostCIDR, err)
		}
		prefix, _ := ipnet.Mask.Size()
		if err := nlAddrAdd(fd, 2, ifindex, ip, prefix); err != nil {
			return fmt.Errorf("assign %s to %s: %w", hostCIDR, tap, err)
		}
	}
	return nil
}

// ifindexOf reads an interface index from sysfs (in-process; no netlink dump).
func ifindexOf(name string) (int32, error) {
	b, err := os.ReadFile("/sys/class/net/" + name + "/ifindex")
	if err != nil {
		return 0, fmt.Errorf("ifindex %s: %w", name, err)
	}
	idx, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return 0, fmt.Errorf("ifindex %s: %w", name, err)
	}
	return int32(idx), nil
}

// --- minimal RTNETLINK (link up + addr add) -------------------------------

func nlAlign(n int) int { return (n + 3) &^ 3 }

// nlAttr appends a TLV rtattr (type + value, 4-byte aligned).
func nlAttr(buf []byte, typ uint16, val []byte) []byte {
	l := 4 + len(val)
	a := make([]byte, nlAlign(l))
	binary.LittleEndian.PutUint16(a[0:2], uint16(l))
	binary.LittleEndian.PutUint16(a[2:4], typ)
	copy(a[4:], val)
	return append(buf, a...)
}

// nlSend issues one NLM_F_REQUEST|NLM_F_ACK message and checks the ack.
func nlSend(fd int, msgType, flags uint16, seq uint32, body []byte) error {
	const hdr = unix.SizeofNlMsghdr
	buf := make([]byte, hdr+len(body))
	h := (*unix.NlMsghdr)(unsafe.Pointer(&buf[0]))
	h.Len = uint32(len(buf))
	h.Type = msgType
	h.Flags = unix.NLM_F_REQUEST | unix.NLM_F_ACK | flags
	h.Seq = seq
	copy(buf[hdr:], body)
	if err := unix.Sendto(fd, buf, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("sendto: %w", err)
	}
	rbuf := make([]byte, 4096)
	n, _, err := unix.Recvfrom(fd, rbuf, 0)
	if err != nil {
		return fmt.Errorf("recvfrom: %w", err)
	}
	if n < hdr+4 {
		return fmt.Errorf("short netlink ack (%d bytes)", n)
	}
	rh := (*unix.NlMsghdr)(unsafe.Pointer(&rbuf[0]))
	if rh.Type == unix.NLMSG_ERROR {
		if errno := int32(binary.LittleEndian.Uint32(rbuf[hdr : hdr+4])); errno != 0 {
			return unix.Errno(-errno)
		}
	}
	return nil
}

// nlLinkUp issues RTM_NEWLINK setting IFF_UP on ifindex.
func nlLinkUp(fd int, seq uint32, ifindex int32) error {
	body := make([]byte, unix.SizeofIfInfomsg)
	ifi := (*unix.IfInfomsg)(unsafe.Pointer(&body[0]))
	ifi.Family = unix.AF_UNSPEC
	ifi.Index = ifindex
	ifi.Flags = unix.IFF_UP
	ifi.Change = unix.IFF_UP
	return nlSend(fd, unix.RTM_NEWLINK, 0, seq, body)
}

// nlAddrAdd issues RTM_NEWADDR (REPLACE → idempotent) with IFA_LOCAL+IFA_ADDRESS.
func nlAddrAdd(fd int, seq uint32, ifindex int32, ip net.IP, prefix int) error {
	body := make([]byte, unix.SizeofIfAddrmsg)
	ifa := (*unix.IfAddrmsg)(unsafe.Pointer(&body[0]))
	family := unix.AF_INET
	raw := ip.To4()
	if raw == nil {
		family, raw = unix.AF_INET6, ip.To16()
	}
	ifa.Family = uint8(family)
	ifa.Prefixlen = uint8(prefix)
	ifa.Index = uint32(ifindex)
	ifa.Scope = unix.RT_SCOPE_UNIVERSE
	body = nlAttr(body, unix.IFA_LOCAL, raw)
	body = nlAttr(body, unix.IFA_ADDRESS, raw)
	return nlSend(fd, unix.RTM_NEWADDR, unix.NLM_F_CREATE|unix.NLM_F_REPLACE, seq, body)
}

// openTap attaches a queue fd with the vnet_hdr framing CH expects, creating
// the (non-persistent) device if it doesn't exist yet — TUNSETIFF both creates
// the device and sets IFF_VNET_HDR on this fd. A "%d" in name is resolved by
// the kernel; the actual device name is returned.
func openTap(name string) (int, string, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", fmt.Errorf("open /dev/net/tun: %w", err)
	}
	var req ifReq
	copy(req.Name[:], name)
	req.Flags = unix.IFF_TAP | unix.IFF_NO_PI | unix.IFF_VNET_HDR
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&req))); e != 0 {
		unix.Close(fd)
		return -1, "", fmt.Errorf("TUNSETIFF %s: %w", name, e)
	}
	return fd, cstr(req.Name[:]), nil // kernel wrote back the assigned name
}

// cstr trims a fixed-size NUL-padded C string.
func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func buildPayload(mac, ip string) []byte {
	var b strings.Builder
	if mac != "" {
		fmt.Fprintf(&b, "mac=%s ", mac)
	}
	if ip != "" {
		fmt.Fprintf(&b, "ip=%s ", ip)
	}
	b.WriteString("fd=1\x00") // single-queue v1; NUL terminates the line
	return []byte(b.String())
}

// dial resolves TAPFD_SOCKET: "fd=N" (inherited socket) or
// a filesystem path to connect.
func dial(spec string) (*net.UnixConn, error) {
	if n, ok := strings.CutPrefix(spec, "fd="); ok {
		fd, err := strconv.Atoi(n)
		if err != nil || fd < 0 {
			return nil, fmt.Errorf("invalid %s=%q", tapSocketEnv, spec)
		}
		f := os.NewFile(uintptr(fd), "tapfd-sock")
		c, err := net.FileConn(f)
		_ = f.Close()
		if err != nil {
			return nil, fmt.Errorf("fileconn fd=%d: %w", fd, err)
		}
		return c.(*net.UnixConn), nil
	}
	c, err := net.Dial("unix", spec)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", spec, err)
	}
	return c.(*net.UnixConn), nil
}
