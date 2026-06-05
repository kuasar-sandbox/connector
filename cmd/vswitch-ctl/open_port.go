package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"

	nllink "github.com/kuasar-sandbox/sandbox-vswitch/pkg/netlink"
	"github.com/kuasar-sandbox/sandbox-vswitch/pkg/netns"
	"github.com/kuasar-sandbox/sandbox-vswitch/pkg/tapfd"
	"github.com/kuasar-sandbox/sandbox-vswitch/pkg/vswitch"
)

// netlinkGetMTU is the GetMTU function we call from inside switch-netns;
// pulled into a var so tests could substitute it.
var netlinkGetMTU = nllink.GetMTU

var openPortCmd = &cobra.Command{
	Use:   "open-port <switch_name>",
	Short: "Open a tap port's fd and transfer it via SCM_RIGHTS",
	Long: `Open the persistent tap device backing a tap-mode port slot and send
the file descriptor to a VMM (or other userspace process) over a unix socket
using SCM_RIGHTS. This implements the tapfd handoff protocol.

The port must already be provisioned in tap mode and attached
('vswitch-ctl provision --mode=tap' then 'vswitch-ctl attach').

The destination socket is given by the TAPFD_SOCKET environment variable:
  TAPFD_SOCKET=/path/to/sock   dial this path and send the fd
  TAPFD_SOCKET=fd=N            use an already-inherited unix socket fd (N)

For the path form, the VMM (or its supervisor) must be listening on that
socket as a stream-mode unix server. For the fd form, the orchestrator
typically creates a socketpair, hands one end to the VMM, and passes the
other end to this helper via fd inheritance.

Set TAPFD_WANT_NETNS=1 to also deliver the tap's network namespace fd as a
trailing SCM_RIGHTS fd (advertised via netns_fd=1 in the payload), letting the
receiver enter the tap's netns with setns(2) — useful when the receiver needs
to inspect the device in its namespace.

Example (path):
  # VMM-side: socat UNIX-LISTEN:/run/vm1.sock,fork ...
  TAPFD_SOCKET=/run/vm1.sock vswitch-ctl open-port sw0 --port=3

Example (inherited fd):
  TAPFD_SOCKET=fd=3 vswitch-ctl open-port sw0 --port=3`,
	Args: cobra.ExactArgs(1),
	RunE: runOpenPort,
}

// tapSocketEnv is the environment variable carrying the destination socket for
// the tapfd handoff: "fd=N" (inherited unix socket fd) or
// a filesystem path the helper dials.
const tapSocketEnv = "TAPFD_SOCKET"

// tapNetnsEnv, when set to a truthy value, asks the helper to also deliver the
// tap's network namespace fd as a trailing SCM_RIGHTS fd and advertise it via
// the netns_fd payload key. A consumer requests it
// when it needs to enter the tap's netns (e.g. to read device metadata); a
// consumer that doesn't request it just gets the tap fd.
const tapNetnsEnv = "TAPFD_WANT_NETNS"

// wantNetnsFD reports whether the consumer asked for the tap's netns fd via
// tapNetnsEnv. Truthy = "1"/"true"/"yes"/"on" (case-insensitive); anything
// else (including unset/empty) is false.
func wantNetnsFD() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(tapNetnsEnv))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

var openPortPort int

func init() {
	openPortCmd.Flags().IntVar(&openPortPort, "port", 0, "Port number (1-based) of the tap slot to open (required)")
	_ = openPortCmd.MarkFlagRequired("port")
}

func runOpenPort(cmd *cobra.Command, args []string) error {
	switchName := args[0]
	if openPortPort <= 0 {
		return fmt.Errorf("--port must be a positive integer")
	}

	// Fail fast if the destination socket wasn't provided, before opening the
	// switch or touching any tap/socket.
	socketSpec := os.Getenv(tapSocketEnv)
	if socketSpec == "" {
		return fmt.Errorf("%s environment variable is required (fd=N or socket path)", tapSocketEnv)
	}

	sw, err := vswitchOpen(switchName)
	if err != nil {
		if vswitch.IsNotExist(err) {
			fmt.Printf("Switch %s is not running\n", switchName)
			osExit(3)
			return nil
		}
		return err
	}
	defer sw.Close()

	cfg := sw.Config()
	slotID := uint32(openPortPort - 1)
	if slotID >= cfg.N_ports {
		return fmt.Errorf("port %d out of range (max %d)", openPortPort, cfg.N_ports)
	}

	// Gate checks — fail fast, BEFORE entering switch-netns or opening any tap fd:
	//   (1) port must be tap-mode (open-port is meaningless for veth)
	//   (2) port must be currently attached to a sandbox (innerIP is a real IP,
	//       not Free/Reserved). The "attached is prerequisite" rule means we
	//       don't hand out fds for unconfigured slots; the orchestrator must
	//       attach first to claim the slot.
	slot := sw.MmapSlots().GetSlot(slotID)
	kind := vswitch.SlotPortKind(slot)
	if kind != vswitch.PortKindTap {
		return fmt.Errorf("port %d is %s, not tap (open-port only valid for tap slots)", openPortPort, kind)
	}
	if slot.Ifindex == 0 {
		return fmt.Errorf("port %d: %w (must run 'provision --mode=tap' first)", openPortPort, vswitch.ErrPortNotProvisioned)
	}
	innerIP := sw.MmapSlots().GetInnerIP(slotID)
	if innerIP == vswitch.InnerIPFree || innerIP == vswitch.InnerIPReserved {
		return fmt.Errorf("port %d: %w (run 'attach' before 'open-port')", openPortPort, vswitch.ErrPortNotAttached)
	}

	result, err := openPortAndSend(sw, switchName, slotID, socketSpec, wantNetnsFD())
	if err != nil {
		return err
	}
	return printJSON(result)
}

// OpenPortResult is the return value of openPortAndSend; the caller decides
// whether to print it (standalone open-port does; attach --open-port folds
// the info into its own output).
type OpenPortResult struct {
	Port      uint32 `json:"port"`
	TapDev    string `json:"tap_dev"`
	SentTo    string `json:"sent_to"`
	MAC       string `json:"mac"`
	MTU       uint32 `json:"mtu"`
	InnerIP   string `json:"inner_ip"`
	NetnsSent bool   `json:"netns_sent"`
}

// openPortAndSend is the reusable core used by both 'open-port' and
// 'attach --open-port'. It enters the switch netns, opens a queue fd on the
// persistent tap, then sends that fd over the destination socket via
// SCM_RIGHTS — accompanied by a metadata payload that lets the receiving VMM
// orchestrator configure its virtio-net device without a separate query.
//
// After a successful send, the local fd is closed (the receiver now holds
// the only reference; the persistent tap survives via TUNSETPERSIST).
//
// When withNetnsFD is set, the switch netns fd is appended as the LAST
// SCM_RIGHTS fd and advertised via netns_fd=1, letting the receiver enter the
// tap's namespace with setns(2).
func openPortAndSend(sw vswitch.Interface, switchName string, slotID uint32, socketSpec string, withNetnsFD bool) (*OpenPortResult, error) {
	tapName := fmt.Sprintf("%s-t%d", switchName, slotID+1)
	cfg := sw.Config()
	slot := sw.MmapSlots().GetSlot(slotID)

	switchNsName := sw.Metadata().SwitchNetnsName()
	switchNs, err := netns.GetByName(switchNsName)
	if err != nil {
		return nil, fmt.Errorf("switch netns %s: %w", switchNsName, err)
	}
	defer switchNs.Close()

	// 1) Connect to the destination socket BEFORE entering switch-netns so
	// any connection errors surface early; the connection then accompanies us
	// through the netns switch (the underlying fd is unaffected by netns).
	conn, err := dialTapSocket(socketSpec)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// 2) Open a tap fd inside switch-netns; also read MTU back from the
	// netdev there (single source of truth for what the kernel actually set).
	var tapFile *os.File
	var mtu int
	if err := switchNs.Do(func() error {
		// IFF_VNET_HDR makes the delivered queue fd carry a virtio-net
		// header — the framing every mainstream virtio VMM (cloud-hypervisor,
		// Firecracker, QEMU default) expects on a tap fd. The flag is a
		// property of this attaching TUNSETIFF, not of the persistent device
		// created by provision (verified: the queue's vnet_hdr state follows
		// the open, not the create). Offload features (TSO/GSO/csum) are left
		// to the consuming VMM to negotiate with its guest.
		f, err := tapfd.OpenTap(tapName, unix.IFF_NO_PI|unix.IFF_VNET_HDR)
		if err != nil {
			return err
		}
		tapFile = f
		mtu, err = netlinkGetMTU(tapName)
		return err
	}); err != nil {
		return nil, fmt.Errorf("open tap %s: %w", tapName, err)
	}
	defer tapFile.Close()

	// 3) Build the metadata payload and send fd(s) + payload atomically.
	portMAC := vswitch.GetPortMAC(cfg.SwitchMac[:], cfg.PortMac[:], slotID)
	meta := &tapfd.PortMetadata{
		Port:    slotID + 1,
		MAC:     portMAC.String(),
		MTU:     uint32(mtu),
		InnerIP: vswitch.Uint32ToIP(slot.InnerIp).String(),
		FDCount: 1,
	}
	// The tap fd goes first; the netns fd (when requested) rides last so a
	// receiver splits the ancillary by fd / netns_fd counts. switchNs.Handle()
	// is the open netns fd, valid to send while switchNs stays open (closed by
	// the deferred Close after the send completes).
	fds := []uintptr{tapFile.Fd()}
	if withNetnsFD {
		meta.NetnsFDCount = 1
		fds = append(fds, uintptr(switchNs.Handle()))
	}
	payload, err := meta.Marshal()
	if err != nil {
		return nil, fmt.Errorf("build metadata payload: %w", err)
	}
	if err := tapfd.SendFd(conn, payload, fds...); err != nil {
		return nil, fmt.Errorf("transfer tap fd: %w", err)
	}

	return &OpenPortResult{
		Port:      slotID + 1,
		TapDev:    tapName,
		SentTo:    socketSpec,
		MAC:       meta.MAC,
		MTU:       meta.MTU,
		InnerIP:   meta.InnerIP,
		NetnsSent: withNetnsFD,
	}, nil
}

// dialTapSocket parses a TAPFD_SOCKET value ("path" or "fd=N") and returns a
// ready-to-write *net.UnixConn.
func dialTapSocket(spec string) (*net.UnixConn, error) {
	if nStr, ok := strings.CutPrefix(spec, "fd="); ok {
		n, err := strconv.Atoi(nStr)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid %s fd= value %q", tapSocketEnv, nStr)
		}
		return tapfd.UnixConnFromFd(n)
	}
	return tapfd.ConnectUnix(spec)
}
