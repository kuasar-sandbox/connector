package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/kuasar-sandbox/sandbox-vswitch/pkg/vswitch"
)

var statusReadyOnly bool

var statusCmd = &cobra.Command{
	Use:   "status <switch_name>",
	Short: "Show switch status",
	Long: `Show the current status of a virtual switch, including:
- Switch state (running/stopped)
- Total number of ports
- Ports in use
- Available ports
- Health conditions (Kubernetes-style)

Flags:
  --ready    Only check Ready status for scripting
             Ready=True  → exit code 0
             Ready=False → exit code 4

Exit codes:
  0  Success (--ready mode: Ready=True)
  1  General error
  3  Switch does not exist
  4  Switch exists but Ready=False (--ready mode)

Example:
  vswitch-ctl status sw1
  vswitch-ctl status sw1 --ready`,
	Args: cobra.ExactArgs(1),
	RunE: runStatus,
}

func init() {
	statusCmd.Flags().BoolVar(&statusReadyOnly, "ready", false, "Only check Ready status, for scripting")
}

func runStatus(cmd *cobra.Command, args []string) error {
	switchName := args[0]

	output, err := vswitchStatus(switchName)
	if err != nil {
		if vswitch.IsNotExist(err) {
			fmt.Printf("Switch %s is not running\n", switchName)
			osExit(3)
			return nil // unreachable, but allows testing
		}
		return err
	}

	if statusReadyOnly {
		// --ready mode: simplified output for scripting
		if output.IsReady() {
			fmt.Println("Ready")
			return nil
		}
		reasons := output.GetNotReadyReasons()
		if reasons != "" {
			fmt.Printf("NotReady: %s\n", reasons)
		} else {
			fmt.Println("NotReady")
		}
		osExit(4)
		return nil // unreachable, but allows testing
	}

	return printJSON(output)
}
