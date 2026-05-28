package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/kuasar-sandbox/sandbox-vswitch/pkg/vswitch"
)

var reserveCmd = &cobra.Command{
	Use:   "reserve <switch_name>",
	Short: "Reserve a switch port",
	Long: `Reserve a switch port slot, preventing it from being auto-allocated.

Use --force to force-reserve any port (even allocated ones).

Example:
  vswitch-ctl reserve sw0 --port=42
  vswitch-ctl reserve sw0 --port=42 --force`,
	Args: cobra.ExactArgs(1),
	RunE: runReserve,
}

var (
	reservePort  int
	reserveForce bool
)

func init() {
	reserveCmd.Flags().IntVar(&reservePort, "port", 0, "Port number to reserve (required)")
	reserveCmd.Flags().BoolVar(&reserveForce, "force", false, "Force-reserve any port (even allocated ones)")
}

func runReserve(cmd *cobra.Command, args []string) error {
	if reservePort <= 0 {
		return fmt.Errorf("--port is required")
	}
	output, err := vswitchReserve(args[0], vswitch.ReserveOptions{
		Port:  reservePort,
		Force: reserveForce,
	})
	if err != nil {
		return err
	}
	return printJSON(output)
}
