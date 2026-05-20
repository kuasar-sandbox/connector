package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/fullof-work/sandbox-vswitch/pkg/vswitch"
)

var provisionCmd = &cobra.Command{
	Use:   "provision <switch_name>",
	Short: "Provision port devices for reserved slots",
	Long: `Create veth devices and attach TC programs for Reserved port slots.

Each Reserved slot transitions to Free after provisioning, making the port
available for attach operations.

Use --count to provision a limited number of ports, or --port to provision
a specific port (useful for port repair after veth device loss).

Port repair workflow:
  # Port 42's veth was deleted abnormally
  vswitch-ctl attach sw0 --force-reserve --port=42  # Isolate port
  vswitch-ctl provision sw0 --port=42               # Rebuild veth + TC

Example:
  vswitch-ctl provision sw0            # Provision all Reserved ports
  vswitch-ctl provision sw0 --count=10 # Provision up to 10 ports
  vswitch-ctl provision sw0 --port=42  # Provision specific port`,
	Args: cobra.ExactArgs(1),
	RunE: runProvision,
}

var (
	provisionCount int
	provisionPort  int
	provisionMode  string
)

func init() {
	provisionCmd.Flags().IntVar(&provisionCount, "count", 0, "Maximum number of ports to provision (0 = all)")
	provisionCmd.Flags().IntVar(&provisionPort, "port", 0, "Specific port number to provision")
	provisionCmd.Flags().StringVar(&provisionMode, "mode", "veth", `Port kind: "veth" (default) or "tap". For tap, the device stays in switch-netns and a fd is later transferred via 'open-port'.`)
}

func runProvision(cmd *cobra.Command, args []string) error {
	switchName := args[0]

	if provisionCount > 0 && provisionPort > 0 {
		return fmt.Errorf("--count and --port are mutually exclusive")
	}

	mode, err := vswitch.ParsePortKind(provisionMode)
	if err != nil {
		return fmt.Errorf("invalid --mode: %w", err)
	}

	opts := vswitch.ProvisionOptions{
		Count: provisionCount,
		Port:  provisionPort,
		Mode:  mode,
	}

	output, err := vswitchProvisionPorts(switchName, opts)
	if err != nil {
		return err
	}

	return printJSON(output)
}
