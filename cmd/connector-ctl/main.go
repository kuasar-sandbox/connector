package main

import (
	"fmt"
	"os"

	"github.com/kuasar-sandbox/connector/internal/version"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "connector-ctl",
	Short: "Sandbox network connector control tool",
	Long: `connector-ctl manages sandbox network connector components.
Use connector-ctl --version to identify this build.

Components: the vswitch data path, tapfd handoff provider and Geneve Egress gateway.
The vSwitch provides:
- Supports up to 4096 sandbox ports
- Complete isolation between sandboxes
- High-performance packet forwarding via eBPF
- Support for management plane (sandbox support network)
- GENEVE tunnel encapsulation for external network access
- Configuration persists after process exits (eBPF programs continue running)
Egress adds local/remote Area policy, per-session Pool quotas and native NAT;
its separately built VPP dataplane runs under 'egress serve'.`,
}

var vswitchCmd = &cobra.Command{
	Use:   "vswitch",
	Short: "Manage the eBPF virtual switch",
}

var tapfdCmd = &cobra.Command{
	Use:   "tapfd",
	Short: "Tap file-descriptor handoff helpers",
}

func init() {
	vswitchCmd.AddCommand(startCmd)
	vswitchCmd.AddCommand(stopCmd)
	vswitchCmd.AddCommand(attachCmd)
	vswitchCmd.AddCommand(setPortUpCmd)
	vswitchCmd.AddCommand(reserveCmd)
	vswitchCmd.AddCommand(detachCmd)
	vswitchCmd.AddCommand(statusCmd)
	vswitchCmd.AddCommand(statsCmd)
	vswitchCmd.AddCommand(showCmd)
	vswitchCmd.AddCommand(openPortCmd)
	vswitchCmd.AddCommand(dhcpCmd)
	vswitchCmd.AddCommand(serveCmd)
	vswitchCmd.AddCommand(provisionCmd)

	tapfdCmd.AddCommand(tapfdGetCmd)

	rootCmd.AddCommand(vswitchCmd)
	rootCmd.AddCommand(tapfdCmd)
}

func main() {
	if version.PrintIfRequested("connector-ctl") {
		return
	}
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
