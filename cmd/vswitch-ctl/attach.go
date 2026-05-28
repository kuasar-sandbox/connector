package main

import (
	"fmt"
	"net"
	"os"

	"github.com/spf13/cobra"

	"github.com/kuasar-sandbox/sandbox-vswitch/pkg/vswitch"
)

var attachCmd = &cobra.Command{
	Use:   "attach <switch_name>",
	Short: "Attach a sandbox to a switch port",
	Long: `Attach a sandbox to a switch port, allocating a slot and configuring
the necessary networking parameters.

If --to-netns is specified, the port device will be moved from the ports
namespace to the target sandbox namespace. If omitted, the port device
remains in the ports namespace.

Example:
  vswitch-ctl attach sw1 \
    --to-netns=sandbox1 \
    --inner-ip=169.254.1.1 \
    --transit-gateway-ip=10.0.0.1 \
    --transit-geneve-vni=100`,
	Args: cobra.ExactArgs(1),
	RunE: runAttach,
}

var (
	attachPort             int
	attachToNetNS          string
	attachInnerIP          string
	attachTransitGatewayIP string
	attachTransitGeneveVNI uint32
	attachTransitMACAddr   string
	attachSkipDevice       bool
	attachOpenPort         bool
)

func init() {
	attachCmd.Flags().IntVar(&attachPort, "port", 0, "Port number (0 for auto-allocate)")
	attachCmd.Flags().StringVar(&attachToNetNS, "to-netns", "", "Target network namespace to move port device into (veth mode only)")
	attachCmd.Flags().StringVar(&attachInnerIP, "inner-ip", "", "Sandbox internal IP (required)")
	attachCmd.Flags().StringVar(&attachTransitGatewayIP, "transit-gateway-ip", "", "GENEVE gateway IP")
	attachCmd.Flags().Uint32Var(&attachTransitGeneveVNI, "transit-geneve-vni", 0, "GENEVE VNI")
	attachCmd.Flags().StringVar(&attachTransitMACAddr, "transit-mac-addr", "", "Transit destination MAC address (default: broadcast)")
	attachCmd.Flags().BoolVar(&attachSkipDevice, "skip-device", false, "Skip port device movement (pure BPF slot operation, veth only)")
	attachCmd.Flags().BoolVar(&attachOpenPort, "open-port", false, "Tap mode only: after slot allocation, send the tap fd via SCM_RIGHTS to $TAPFD_SOCKET (combines attach + open-port)")
}

func runAttach(cmd *cobra.Command, args []string) error {
	switchName := args[0]

	if attachInnerIP == "" {
		return fmt.Errorf("--inner-ip is required")
	}

	// Parse inner IP
	innerIP := net.ParseIP(attachInnerIP)
	if innerIP == nil {
		return fmt.Errorf("invalid inner-ip: %s", attachInnerIP)
	}

	// --open-port needs a destination socket; validate it before allocating a
	// slot so a missing TAPFD_SOCKET fails fast with nothing to roll back.
	var tapSocketSpec string
	if attachOpenPort {
		tapSocketSpec = os.Getenv(tapSocketEnv)
		if tapSocketSpec == "" {
			return fmt.Errorf("--open-port requires the %s environment variable (fd=N or socket path)", tapSocketEnv)
		}
	}

	opts := vswitch.AttachOptions{
		Port:             attachPort,
		ToNetNS:          attachToNetNS,
		InnerIP:          innerIP,
		TransitGeneveVNI: attachTransitGeneveVNI,
		SkipDevice:       attachSkipDevice,
	}

	// Parse transit gateway IP if provided
	if attachTransitGatewayIP != "" {
		opts.TransitGatewayIP = net.ParseIP(attachTransitGatewayIP)
		if opts.TransitGatewayIP == nil {
			return fmt.Errorf("invalid transit-gateway-ip: %s", attachTransitGatewayIP)
		}
	}

	// Parse transit MAC if provided
	if attachTransitMACAddr != "" {
		mac, err := net.ParseMAC(attachTransitMACAddr)
		if err != nil {
			return fmt.Errorf("invalid transit-mac-addr: %w", err)
		}
		opts.TransitMAC = mac
	}

	output, err := vswitchAttach(switchName, opts)
	if err != nil {
		return err
	}

	// --open-port: combine attach + open-port to save a fork/exec roundtrip
	// when spinning up a sandbox. Only valid on tap slots; the attach core
	// has already verified the slot is provisioned.
	if attachOpenPort {
		if output.Mode != "tap" {
			// Roll back the slot allocation so the caller can retry cleanly.
			_ = vswitchDetach(switchName, vswitch.DetachOptions{
				Port:       int(output.Port),
				SkipDevice: true,
			})
			return fmt.Errorf("--open-port is only valid for tap-mode slots (port %d is %s)", output.Port, output.Mode)
		}
		fdInfo, err := attachSendTapFd(switchName, output, tapSocketSpec, wantNetnsFD())
		if err != nil {
			// SCM_RIGHTS failed — undo the slot allocation so the caller's
			// retry sees a clean state. The tap device stays (it was created
			// by provision, not by us).
			_ = vswitchDetach(switchName, vswitch.DetachOptions{
				Port:       int(output.Port),
				SkipDevice: true,
			})
			return fmt.Errorf("attach succeeded but tap fd transfer failed: %w", err)
		}
		// Fold the open-port result into the attach output so callers get a
		// single JSON document describing the combined operation.
		output.TapSentTo = fdInfo.SentTo
		output.TapNetnsSent = fdInfo.NetnsSent
	}

	return printJSON(output)
}

// attachSendTapFd opens the freshly-attached tap port and sends its fd to the
// destination socket. Lives in attach.go (not open_port.go) so the rollback
// path stays close to the CAS code it reverses.
func attachSendTapFd(switchName string, out *vswitch.AttachOutput, socketSpec string, withNetnsFD bool) (*OpenPortResult, error) {
	sw, err := vswitchOpen(switchName)
	if err != nil {
		return nil, err
	}
	defer sw.Close()
	slotID := out.Port - 1
	return openPortAndSend(sw, switchName, slotID, socketSpec, withNetnsFD)
}
