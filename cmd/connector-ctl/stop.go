package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/kuasar-sandbox/connector/pkg/vswitch"
)

var stopCmd = &cobra.Command{
	Use:   "stop <switch_name>",
	Short: "Stop and clean up a virtual switch",
	Long: `Stop a running virtual switch and clean up all resources.

This will:
- Move transit device back to the caller's network namespace
- Delete all management veth pairs (<sw>-mX)
- Delete all port veth pairs (<sw>-nX / <sw>-pX)
- Unpin BPF maps from /sys/fs/bpf/<switch_name>/
- The eBPF programs will be automatically unloaded when no longer referenced

By default, stop refuses to proceed if any ports are in use (Allocated).
Free ports will be reserved to block new attaches. Drain active ports and
retry, or use --force to override.

Use --force to force-stop including in-use ports (two-round cleanup).
Use --force-clean to clean up a corrupted switch (e.g. after binary upgrade
with incompatible metadata format). Force-clean only unpins BPF maps/programs
without attempting veth cleanup or transit device restoration.

Example:
  connector-ctl vswitch stop sw1
  connector-ctl vswitch stop sw1 --force
  connector-ctl vswitch stop sw1 --force-clean`,
	Args: cobra.ExactArgs(1),
	RunE: runStop,
}

var (
	stopForce      bool
	stopForceClean bool
)

func init() {
	stopCmd.Flags().BoolVar(&stopForce, "force", false, "Force stop: release all ports including in-use ones (two-round cleanup)")
	stopCmd.Flags().BoolVar(&stopForceClean, "force-clean", false, "Force-clean corrupted switch (unpin only, skip device cleanup)")
}

func runStop(cmd *cobra.Command, args []string) error {
	switchName := args[0]

	err := vswitchStop(switchName, vswitch.StopOptions{Force: stopForce})
	if err == nil {
		fmt.Printf("Switch %s stopped\n", switchName)
		return nil
	}

	if vswitch.IsPortsInUse(err) {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		fmt.Fprintf(os.Stderr, "Free ports have been reserved (no new attach allowed).\n")
		fmt.Fprintf(os.Stderr, "Drain active ports and retry, or use --force to override.\n")
		osExit(4)
		return nil
	}

	if vswitch.IsNotExist(err) {
		fmt.Printf("Switch %s is not running\n", switchName)
		osExit(3)
		return nil // unreachable, but allows testing
	}

	if vswitch.IsSwitchCorrupted(err) && stopForceClean {
		fmt.Fprintf(os.Stderr, "[warn] %v\n", err)
		fmt.Fprintf(os.Stderr, "[warn] force-cleaning pinned data for %s\n", switchName)
		if err := vswitchForceCleanup(switchName); err != nil {
			return fmt.Errorf("force cleanup failed: %w", err)
		}
		fmt.Printf("Switch %s force-cleaned\n", switchName)
		return nil
	}

	return err
}
