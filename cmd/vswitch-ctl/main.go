package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "vswitch-ctl",
	Short: "High-performance eBPF virtual switch for sandbox containers",
	Long: `vswitch-ctl is a CLI tool for configuring a high-performance eBPF virtual switch
that supports network access for up to ~4K sandbox containers (microVMs).

Features:
- Supports up to 4096 sandbox ports
- Complete isolation between sandboxes
- High-performance packet forwarding via eBPF
- Support for management plane (sandbox support network)
- GENEVE tunnel encapsulation for external network access
- Configuration persists after process exits (eBPF programs continue running)`,
}

func init() {
	rootCmd.AddCommand(startCmd)
	rootCmd.AddCommand(stopCmd)
	rootCmd.AddCommand(attachCmd)
	rootCmd.AddCommand(reserveCmd)
	rootCmd.AddCommand(detachCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(statsCmd)
	rootCmd.AddCommand(showCmd)
	rootCmd.AddCommand(openPortCmd)
	rootCmd.AddCommand(dhcpCmd)
	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(provisionCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
