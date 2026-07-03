package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/kuasar-sandbox/connector/pkg/dhcp"
)

var dhcpCmd = &cobra.Command{
	Use:   "dhcp",
	Short: "DHCP client operations",
	Long:  `DHCP client operations for network configuration.`,
}

var dhcpRequestCmd = &cobra.Command{
	Use:   "request",
	Short: "Perform DHCP request on an interface",
	Long: `Perform a DHCP DORA (Discover, Offer, Request, Acknowledge) handshake
on the specified network interface and print the acquired lease as JSON.

Example:
  connector-ctl vswitch dhcp request --dev=eth1
  connector-ctl vswitch dhcp request --dev=eth1 --timeout=10s --retries=5`,
	RunE: runDHCPRequest,
}

var (
	dhcpDev     string
	dhcpTimeout time.Duration
	dhcpRetries int
)

func init() {
	dhcpCmd.AddCommand(dhcpRequestCmd)

	dhcpRequestCmd.Flags().StringVar(&dhcpDev, "dev", "", "Network interface (required)")
	dhcpRequestCmd.Flags().DurationVar(&dhcpTimeout, "timeout", 5*time.Second, "Timeout for each DHCP attempt")
	dhcpRequestCmd.Flags().IntVar(&dhcpRetries, "retries", 3, "Number of retry attempts")

	_ = dhcpRequestCmd.MarkFlagRequired("dev")
}

func runDHCPRequest(cmd *cobra.Command, args []string) error {
	// Set up signal handling for graceful cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	opts := dhcp.RequestOptions{
		Interface: dhcpDev,
		Timeout:   dhcpTimeout,
		Retries:   dhcpRetries,
	}

	lease, err := dhcpRequest(ctx, opts)
	if err != nil {
		return fmt.Errorf("DHCP request failed: %w", err)
	}

	output := lease.ToOutput(dhcpDev)
	jsonBytes, err := json.MarshalIndent(output, "", "    ")
	if err != nil {
		return fmt.Errorf("failed to marshal output: %w", err)
	}

	fmt.Println(string(jsonBytes))
	return nil
}
