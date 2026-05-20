package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/fullof-work/sandbox-vswitch/pkg/vswitch"
)

var detachCmd = &cobra.Command{
	Use:   "detach <switch_name>",
	Short: "Detach a sandbox from a switch port",
	Long: `Detach a sandbox from a switch port, releasing the slot for reuse.

If --from-netns is specified, the port device will be moved back from the
sandbox namespace to the ports namespace. If omitted, the command verifies
the port device is already in the ports namespace before resetting the slot.

Example:
  vswitch-ctl detach sw1 --port=3 --from-netns=sandbox1`,
	Args: cobra.ExactArgs(1),
	RunE: runDetach,
}

var (
	detachPort       int
	detachFromNetNS  string
	detachSkipDevice bool
)

func init() {
	detachCmd.Flags().IntVar(&detachPort, "port", 0, "Port number to detach (required)")
	detachCmd.Flags().StringVar(&detachFromNetNS, "from-netns", "", "Namespace where the port device currently resides (required)")
	detachCmd.Flags().BoolVar(&detachSkipDevice, "skip-device", false, "Skip port device movement (pure BPF slot operation)")
	detachCmd.MarkFlagRequired("port")
}

func runDetach(cmd *cobra.Command, args []string) error {
	switchName := args[0]

	opts := vswitch.DetachOptions{
		Port:       detachPort,
		FromNetNS:  detachFromNetNS,
		SkipDevice: detachSkipDevice,
	}
	if err := vswitchDetach(switchName, opts); err != nil {
		return err
	}

	fmt.Printf("Port %d detached from switch %s\n", detachPort, switchName)
	return nil
}
