package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/kuasar-sandbox/sandbox-vswitch/pkg/vswitch"
)

var statsCmd = &cobra.Command{
	Use:   "stats <switch_name>",
	Short: "Show per-port traffic statistics",
	Long: `Show per-port traffic statistics for a switch.

Statistics are split into management plane and transit (GENEVE) traffic.
Use --port to query specific ports (repeatable). If omitted, all allocated
ports are shown.

Example:
  vswitch-ctl stats sw1
  vswitch-ctl stats sw1 --port=1 --port=3`,
	Args: cobra.ExactArgs(1),
	RunE: runStats,
}

var statsPorts []int

func init() {
	statsCmd.Flags().IntSliceVar(&statsPorts, "port", nil, "Port number(s) to query (repeatable, default: all allocated)")
}

func runStats(cmd *cobra.Command, args []string) error {
	switchName := args[0]

	output, err := vswitchStats(switchName, statsPorts)
	if err != nil {
		if vswitch.IsNotExist(err) {
			fmt.Printf("Switch %s is not running\n", switchName)
			osExit(3)
			return nil // unreachable, but allows testing
		}
		return err
	}

	return printJSON(output)
}
