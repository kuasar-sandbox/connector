// Package dhcp provides a simple DHCP client for acquiring network configuration.
package dhcp

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/nclient4"
)

// dhcpClient defines the DHCP client interface (for testing mock).
type dhcpClient interface {
	Request(ctx context.Context, modifiers ...dhcpv4.Modifier) (*nclient4.Lease, error)
	Close() error
}

// newClient is a function variable for creating DHCP clients. Can be replaced in tests.
var newClient = func(ifname string, opts ...nclient4.ClientOpt) (dhcpClient, error) {
	return nclient4.New(ifname, opts...)
}

// Lease represents a DHCP lease.
type Lease struct {
	IP         net.IP        // Assigned IP address
	Netmask    net.IPMask    // Network mask
	PrefixLen  int           // Prefix length (e.g., 24 for /24)
	Gateway    net.IP        // Default gateway
	DNSServers []net.IP      // DNS servers
	LeaseTime  time.Duration // Lease duration
	ServerID   net.IP        // DHCP server identifier
	AcquiredAt time.Time     // When the lease was acquired
}

// LeaseOutput is the JSON output format for a lease.
type LeaseOutput struct {
	Interface        string   `json:"interface"`
	IP               string   `json:"ip"`
	Netmask          string   `json:"netmask"`
	PrefixLen        int      `json:"prefix_len"`
	CIDR             string   `json:"cidr"`
	Gateway          string   `json:"gateway,omitempty"`
	DNSServers       []string `json:"dns_servers,omitempty"`
	LeaseTimeSeconds int64    `json:"lease_time_seconds"`
	ServerID         string   `json:"server_id,omitempty"`
}

// RequestOptions configures the DHCP request.
type RequestOptions struct {
	Interface string        // Network interface name
	Timeout   time.Duration // Timeout for each attempt
	Retries   int           // Number of retry attempts
}

// DefaultOptions returns default request options.
func DefaultOptions() RequestOptions {
	return RequestOptions{
		Timeout: 5 * time.Second,
		Retries: 3,
	}
}

// Request performs a DHCP DORA handshake and returns the acquired lease.
func Request(ctx context.Context, opts RequestOptions) (*Lease, error) {
	if opts.Interface == "" {
		return nil, fmt.Errorf("interface name is required")
	}
	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Second
	}
	if opts.Retries == 0 {
		opts.Retries = 3
	}

	iface, err := net.InterfaceByName(opts.Interface)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface %s: %w", opts.Interface, err)
	}

	var lastErr error
	for attempt := 0; attempt <= opts.Retries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Second): // Brief delay between retries
			}
		}

		lease, err := doRequest(ctx, iface, opts.Timeout)
		if err == nil {
			return lease, nil
		}
		lastErr = err

		// Check if context was cancelled
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}

	return nil, fmt.Errorf("DHCP request failed after %d attempts: %w", opts.Retries+1, lastErr)
}

func doRequest(ctx context.Context, iface *net.Interface, timeout time.Duration) (*Lease, error) {
	// Create a context with timeout for this attempt
	attemptCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Create DHCP client using the function variable (allows mocking in tests)
	client, err := newClient(iface.Name, nclient4.WithTimeout(timeout))
	if err != nil {
		return nil, fmt.Errorf("failed to create DHCP client on %s: %w", iface.Name, err)
	}
	defer client.Close()

	// Perform DORA handshake
	lease, err := client.Request(attemptCtx)
	if err != nil {
		return nil, fmt.Errorf("DHCP request failed: %w", err)
	}

	return parseLease(lease.ACK)
}

func parseLease(ack *dhcpv4.DHCPv4) (*Lease, error) {
	if ack == nil {
		return nil, fmt.Errorf("no DHCP ACK received")
	}

	lease := &Lease{
		IP:         ack.YourIPAddr,
		AcquiredAt: time.Now(),
	}

	// Get subnet mask
	if mask := ack.SubnetMask(); mask != nil {
		lease.Netmask = mask
		ones, _ := mask.Size()
		lease.PrefixLen = ones
	} else {
		// Default to /24 if no mask provided
		lease.Netmask = net.CIDRMask(24, 32)
		lease.PrefixLen = 24
	}

	// Get gateway (router option)
	routers := ack.Router()
	if len(routers) > 0 {
		lease.Gateway = routers[0]
	}

	// Get DNS servers
	dnsServers := ack.DNS()
	if len(dnsServers) > 0 {
		lease.DNSServers = dnsServers
	}

	// Get lease time
	if leaseTime := ack.IPAddressLeaseTime(0); leaseTime > 0 {
		lease.LeaseTime = leaseTime
	}

	// Get server identifier
	if serverID := ack.ServerIdentifier(); serverID != nil {
		lease.ServerID = serverID
	}

	return lease, nil
}

// ToOutput converts a Lease to its JSON output format.
func (l *Lease) ToOutput(ifaceName string) *LeaseOutput {
	out := &LeaseOutput{
		Interface:        ifaceName,
		IP:               l.IP.String(),
		Netmask:          net.IP(l.Netmask).String(),
		PrefixLen:        l.PrefixLen,
		CIDR:             fmt.Sprintf("%s/%d", l.IP.String(), l.PrefixLen),
		LeaseTimeSeconds: int64(l.LeaseTime.Seconds()),
	}

	if l.Gateway != nil {
		out.Gateway = l.Gateway.String()
	}

	if len(l.DNSServers) > 0 {
		out.DNSServers = make([]string, len(l.DNSServers))
		for i, dns := range l.DNSServers {
			out.DNSServers[i] = dns.String()
		}
	}

	if l.ServerID != nil {
		out.ServerID = l.ServerID.String()
	}

	return out
}

// ToTransitConfig converts a Lease to transit device configuration.
// Returns the IP/mask as *net.IPNet, the gateway as net.IP, and a boolean
// indicating if the gateway was inferred (true) or from DHCP (false).
// If the lease has no gateway, it calculates the first IP of the subnet as gateway.
func (l *Lease) ToTransitConfig() (*net.IPNet, net.IP, bool) {
	ipnet := &net.IPNet{
		IP:   l.IP,
		Mask: l.Netmask,
	}

	gateway := l.Gateway
	gatewayInferred := false

	if gateway == nil {
		// Calculate first IP of subnet as gateway
		// e.g., for 192.168.1.100/24, subnet is 192.168.1.0, first IP is 192.168.1.1
		networkIP := l.IP.Mask(l.Netmask)
		gateway = make(net.IP, len(networkIP))
		copy(gateway, networkIP)
		gateway[len(gateway)-1]++ // First usable IP
		gatewayInferred = true
	}

	return ipnet, gateway, gatewayInferred
}
