package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/fullof-work/sandbox-vswitch/pkg/dhcp"
)

var dhcpServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start a DHCP server",
	Long: `Start a simple DHCP server for testing purposes.

Example:
  vswitch-ctl dhcp serve \
      --dev=veth0 \
      --server-ip=10.0.0.1 \
      --pool=10.0.0.100-10.0.0.200 \
      --gateway=10.0.0.1 \
      --lease-time=1h`,
	RunE: runDHCPServe,
}

var (
	dhcpServeDev      string
	dhcpServeServerIP string
	dhcpServePool     string
	dhcpServeGateway  string
	dhcpServeDNS      string
	dhcpServeLease    time.Duration
)

func init() {
	dhcpCmd.AddCommand(dhcpServeCmd)

	dhcpServeCmd.Flags().StringVar(&dhcpServeDev, "dev", "", "Network interface to listen on (required)")
	dhcpServeCmd.Flags().StringVar(&dhcpServeServerIP, "server-ip", "", "Server IP address (required)")
	dhcpServeCmd.Flags().StringVar(&dhcpServePool, "pool", "", "IP address pool range, e.g., 10.0.0.100-10.0.0.200 (required)")
	dhcpServeCmd.Flags().StringVar(&dhcpServeGateway, "gateway", "", "Default gateway (defaults to server-ip)")
	dhcpServeCmd.Flags().StringVar(&dhcpServeDNS, "dns", "", "DNS servers, comma-separated")
	dhcpServeCmd.Flags().DurationVar(&dhcpServeLease, "lease-time", time.Hour, "Lease duration")

	_ = dhcpServeCmd.MarkFlagRequired("dev")
	_ = dhcpServeCmd.MarkFlagRequired("server-ip")
	_ = dhcpServeCmd.MarkFlagRequired("pool")
}

func runDHCPServe(cmd *cobra.Command, args []string) error {
	// Parse server IP
	serverIP := net.ParseIP(dhcpServeServerIP)
	if serverIP == nil {
		return fmt.Errorf("invalid server IP: %s", dhcpServeServerIP)
	}
	serverIP = serverIP.To4()
	if serverIP == nil {
		return fmt.Errorf("server IP must be IPv4: %s", dhcpServeServerIP)
	}

	// Parse pool range
	poolStart, poolEnd, err := parsePoolRange(dhcpServePool)
	if err != nil {
		return fmt.Errorf("invalid pool range: %w", err)
	}

	// Parse gateway (optional)
	var gateway net.IP
	if dhcpServeGateway != "" {
		gateway = net.ParseIP(dhcpServeGateway)
		if gateway == nil {
			return fmt.Errorf("invalid gateway: %s", dhcpServeGateway)
		}
		gateway = gateway.To4()
		if gateway == nil {
			return fmt.Errorf("gateway must be IPv4: %s", dhcpServeGateway)
		}
	}

	// Parse DNS servers (optional)
	var dnsServers []net.IP
	if dhcpServeDNS != "" {
		parts := strings.Split(dhcpServeDNS, ",")
		for _, p := range parts {
			dns := net.ParseIP(strings.TrimSpace(p))
			if dns == nil {
				return fmt.Errorf("invalid DNS server: %s", p)
			}
			dnsServers = append(dnsServers, dns)
		}
	}

	// Derive netmask from server IP (assume /24 for simplicity)
	netmask := net.CIDRMask(24, 32)

	cfg := dhcp.ServerConfig{
		Interface: dhcpServeDev,
		ServerIP:  serverIP,
		PoolStart: poolStart,
		PoolEnd:   poolEnd,
		Netmask:   netmask,
		Gateway:   gateway,
		DNS:       dnsServers,
		LeaseTime: dhcpServeLease,
	}

	server, err := dhcpNewServer(cfg)
	if err != nil {
		return fmt.Errorf("failed to create DHCP server: %w", err)
	}

	// Set up signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nShutting down DHCP server...")
		cancel()
	}()

	fmt.Printf("Starting DHCP server on %s\n", dhcpServeDev)
	fmt.Printf("  Server IP: %s\n", serverIP)
	fmt.Printf("  Pool: %s - %s\n", poolStart, poolEnd)
	fmt.Printf("  Gateway: %s\n", cfg.Gateway)
	fmt.Printf("  Lease time: %s\n", dhcpServeLease)
	if len(dnsServers) > 0 {
		fmt.Printf("  DNS: %v\n", dnsServers)
	}

	if err := server.Serve(ctx); err != nil {
		// Ignore error if context was cancelled
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("DHCP server error: %w", err)
	}

	return nil
}

func parsePoolRange(pool string) (net.IP, net.IP, error) {
	parts := strings.Split(pool, "-")
	if len(parts) != 2 {
		return nil, nil, fmt.Errorf("pool must be in format START-END, got: %s", pool)
	}

	start := net.ParseIP(strings.TrimSpace(parts[0]))
	if start == nil {
		return nil, nil, fmt.Errorf("invalid pool start IP: %s", parts[0])
	}
	start = start.To4()
	if start == nil {
		return nil, nil, fmt.Errorf("pool start must be IPv4: %s", parts[0])
	}

	end := net.ParseIP(strings.TrimSpace(parts[1]))
	if end == nil {
		return nil, nil, fmt.Errorf("invalid pool end IP: %s", parts[1])
	}
	end = end.To4()
	if end == nil {
		return nil, nil, fmt.Errorf("pool end must be IPv4: %s", parts[1])
	}

	return start, end, nil
}
