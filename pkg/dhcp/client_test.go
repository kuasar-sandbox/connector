package dhcp

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/nclient4"
)

func TestLeaseToOutput(t *testing.T) {
	lease := &Lease{
		IP:         net.ParseIP("192.168.1.100"),
		Netmask:    net.CIDRMask(24, 32),
		PrefixLen:  24,
		Gateway:    net.ParseIP("192.168.1.1"),
		DNSServers: []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("8.8.4.4")},
		LeaseTime:  24 * time.Hour,
		ServerID:   net.ParseIP("192.168.1.1"),
		AcquiredAt: time.Now(),
	}

	out := lease.ToOutput("eth1")

	if out.Interface != "eth1" {
		t.Errorf("Interface = %q, want %q", out.Interface, "eth1")
	}
	if out.IP != "192.168.1.100" {
		t.Errorf("IP = %q, want %q", out.IP, "192.168.1.100")
	}
	if out.Netmask != "255.255.255.0" {
		t.Errorf("Netmask = %q, want %q", out.Netmask, "255.255.255.0")
	}
	if out.PrefixLen != 24 {
		t.Errorf("PrefixLen = %d, want %d", out.PrefixLen, 24)
	}
	if out.CIDR != "192.168.1.100/24" {
		t.Errorf("CIDR = %q, want %q", out.CIDR, "192.168.1.100/24")
	}
	if out.Gateway != "192.168.1.1" {
		t.Errorf("Gateway = %q, want %q", out.Gateway, "192.168.1.1")
	}
	if len(out.DNSServers) != 2 {
		t.Errorf("DNSServers count = %d, want %d", len(out.DNSServers), 2)
	}
	if out.LeaseTimeSeconds != 86400 {
		t.Errorf("LeaseTimeSeconds = %d, want %d", out.LeaseTimeSeconds, 86400)
	}
	if out.ServerID != "192.168.1.1" {
		t.Errorf("ServerID = %q, want %q", out.ServerID, "192.168.1.1")
	}
}

func TestLeaseToOutputMinimal(t *testing.T) {
	lease := &Lease{
		IP:        net.ParseIP("10.0.0.50"),
		Netmask:   net.CIDRMask(16, 32),
		PrefixLen: 16,
		LeaseTime: time.Hour,
	}

	out := lease.ToOutput("enp0s3")

	if out.Interface != "enp0s3" {
		t.Errorf("Interface = %q, want %q", out.Interface, "enp0s3")
	}
	if out.IP != "10.0.0.50" {
		t.Errorf("IP = %q, want %q", out.IP, "10.0.0.50")
	}
	if out.CIDR != "10.0.0.50/16" {
		t.Errorf("CIDR = %q, want %q", out.CIDR, "10.0.0.50/16")
	}
	if out.Gateway != "" {
		t.Errorf("Gateway = %q, want empty", out.Gateway)
	}
	if len(out.DNSServers) != 0 {
		t.Errorf("DNSServers = %v, want nil/empty", out.DNSServers)
	}
	if out.ServerID != "" {
		t.Errorf("ServerID = %q, want empty", out.ServerID)
	}
}

func TestLeaseToTransitConfig(t *testing.T) {
	lease := &Lease{
		IP:        net.ParseIP("192.168.1.100"),
		Netmask:   net.CIDRMask(24, 32),
		PrefixLen: 24,
		Gateway:   net.ParseIP("192.168.1.1"),
	}

	ipnet, gw, inferred := lease.ToTransitConfig()

	if ipnet.IP.String() != "192.168.1.100" {
		t.Errorf("IP = %s, want %s", ipnet.IP, "192.168.1.100")
	}

	ones, bits := ipnet.Mask.Size()
	if ones != 24 || bits != 32 {
		t.Errorf("Mask = /%d (bits=%d), want /24 (bits=32)", ones, bits)
	}

	if gw.String() != "192.168.1.1" {
		t.Errorf("Gateway = %s, want %s", gw, "192.168.1.1")
	}

	if inferred {
		t.Error("gatewayInferred = true, want false when gateway is present")
	}
}

func TestLeaseToTransitConfigNoGateway(t *testing.T) {
	lease := &Lease{
		IP:        net.ParseIP("192.168.1.100"),
		Netmask:   net.CIDRMask(24, 32),
		PrefixLen: 24,
		// Gateway is nil
	}

	ipnet, gw, inferred := lease.ToTransitConfig()

	if ipnet.IP.String() != "192.168.1.100" {
		t.Errorf("IP = %s, want %s", ipnet.IP, "192.168.1.100")
	}

	// Expected: first IP of 192.168.1.0/24 is 192.168.1.1
	if gw.String() != "192.168.1.1" {
		t.Errorf("Gateway = %s, want %s (first IP of subnet)", gw, "192.168.1.1")
	}

	if !inferred {
		t.Error("gatewayInferred = false, want true when gateway was calculated")
	}
}

func TestLeaseToTransitConfigNoGatewayDifferentSubnet(t *testing.T) {
	lease := &Lease{
		IP:        net.ParseIP("10.0.5.50"),
		Netmask:   net.CIDRMask(16, 32),
		PrefixLen: 16,
		// Gateway is nil
	}

	_, gw, inferred := lease.ToTransitConfig()

	// Expected: first IP of 10.0.0.0/16 is 10.0.0.1
	if gw.String() != "10.0.0.1" {
		t.Errorf("Gateway = %s, want %s (first IP of subnet)", gw, "10.0.0.1")
	}

	if !inferred {
		t.Error("gatewayInferred = false, want true when gateway was calculated")
	}
}

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()

	if opts.Timeout != 5*time.Second {
		t.Errorf("Timeout = %v, want %v", opts.Timeout, 5*time.Second)
	}
	if opts.Retries != 3 {
		t.Errorf("Retries = %d, want %d", opts.Retries, 3)
	}
}

func TestNewClientErr(t *testing.T) {
	if _, err := newClient("na", func(c *nclient4.Client) error { return fmt.Errorf("mock error") }); err == nil {
		t.Error("expected error from newClient, got nil")
	}
}

// --- Lease struct tests ---

func TestLeaseStructFields(t *testing.T) {
	now := time.Now()
	lease := &Lease{
		IP:         net.ParseIP("10.0.0.100"),
		Netmask:    net.CIDRMask(24, 32),
		PrefixLen:  24,
		Gateway:    net.ParseIP("10.0.0.1"),
		DNSServers: []net.IP{net.ParseIP("8.8.8.8")},
		LeaseTime:  time.Hour,
		ServerID:   net.ParseIP("10.0.0.1"),
		AcquiredAt: now,
	}

	if !lease.IP.Equal(net.ParseIP("10.0.0.100")) {
		t.Errorf("IP = %s", lease.IP)
	}
	if lease.PrefixLen != 24 {
		t.Errorf("PrefixLen = %d", lease.PrefixLen)
	}
	if !lease.Gateway.Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("Gateway = %s", lease.Gateway)
	}
	if len(lease.DNSServers) != 1 {
		t.Errorf("DNSServers len = %d", len(lease.DNSServers))
	}
	if lease.LeaseTime != time.Hour {
		t.Errorf("LeaseTime = %v", lease.LeaseTime)
	}
	if !lease.AcquiredAt.Equal(now) {
		t.Errorf("AcquiredAt mismatch")
	}
}

// --- LeaseOutput struct tests ---

func TestLeaseOutputFields(t *testing.T) {
	out := &LeaseOutput{
		Interface:        "eth0",
		IP:               "10.0.0.100",
		Netmask:          "255.255.255.0",
		PrefixLen:        24,
		CIDR:             "10.0.0.100/24",
		Gateway:          "10.0.0.1",
		DNSServers:       []string{"8.8.8.8", "8.8.4.4"},
		LeaseTimeSeconds: 3600,
		ServerID:         "10.0.0.1",
	}

	if out.Interface != "eth0" {
		t.Errorf("Interface = %s", out.Interface)
	}
	if out.CIDR != "10.0.0.100/24" {
		t.Errorf("CIDR = %s", out.CIDR)
	}
	if len(out.DNSServers) != 2 {
		t.Errorf("DNSServers len = %d", len(out.DNSServers))
	}
}

// --- RequestOptions tests ---

func TestRequestOptionsDefaults(t *testing.T) {
	opts := RequestOptions{}
	if opts.Timeout != 0 {
		t.Errorf("default Timeout = %v, want 0", opts.Timeout)
	}
	if opts.Retries != 0 {
		t.Errorf("default Retries = %d, want 0", opts.Retries)
	}
}

func TestRequestOptionsCustom(t *testing.T) {
	opts := RequestOptions{
		Interface: "eth1",
		Timeout:   10 * time.Second,
		Retries:   5,
	}

	if opts.Interface != "eth1" {
		t.Errorf("Interface = %s", opts.Interface)
	}
	if opts.Timeout != 10*time.Second {
		t.Errorf("Timeout = %v", opts.Timeout)
	}
	if opts.Retries != 5 {
		t.Errorf("Retries = %d", opts.Retries)
	}
}

// --- ToTransitConfig edge cases ---

func TestLeaseToTransitConfigSlash32(t *testing.T) {
	lease := &Lease{
		IP:        net.ParseIP("10.0.0.100"),
		Netmask:   net.CIDRMask(32, 32),
		PrefixLen: 32,
		// No gateway - will be inferred
	}

	ipnet, gw, inferred := lease.ToTransitConfig()

	ones, _ := ipnet.Mask.Size()
	if ones != 32 {
		t.Errorf("Mask = /%d, want /32", ones)
	}

	// For /32, network IP = host IP, so gateway = IP + 1
	if gw.String() != "10.0.0.101" {
		t.Errorf("Gateway = %s, want 10.0.0.101 (inferred from /32)", gw)
	}

	if !inferred {
		t.Error("gateway should be inferred")
	}
}

func TestLeaseToTransitConfigSlash8(t *testing.T) {
	lease := &Lease{
		IP:        net.ParseIP("10.99.88.77"),
		Netmask:   net.CIDRMask(8, 32),
		PrefixLen: 8,
	}

	_, gw, inferred := lease.ToTransitConfig()

	// For 10.99.88.77/8, network = 10.0.0.0, first IP = 10.0.0.1
	if gw.String() != "10.0.0.1" {
		t.Errorf("Gateway = %s, want 10.0.0.1 (first IP of /8)", gw)
	}

	if !inferred {
		t.Error("gateway should be inferred")
	}
}

// --- parseLease tests ---

func TestParseLease(t *testing.T) {
	tests := []struct {
		name       string
		ack        *dhcpv4.DHCPv4
		wantErr    bool
		checkLease func(*testing.T, *Lease)
	}{
		{
			name:    "nil ACK",
			ack:     nil,
			wantErr: true,
		},
		{
			name: "full ACK with all options",
			ack: func() *dhcpv4.DHCPv4 {
				ack, _ := dhcpv4.New()
				ack.YourIPAddr = net.ParseIP("192.168.1.100")
				ack.UpdateOption(dhcpv4.OptSubnetMask(net.CIDRMask(24, 32)))
				ack.UpdateOption(dhcpv4.OptRouter(net.ParseIP("192.168.1.1")))
				ack.UpdateOption(dhcpv4.OptDNS(net.ParseIP("8.8.8.8"), net.ParseIP("8.8.4.4")))
				ack.UpdateOption(dhcpv4.OptIPAddressLeaseTime(3600 * time.Second))
				ack.UpdateOption(dhcpv4.OptServerIdentifier(net.ParseIP("192.168.1.1")))
				return ack
			}(),
			wantErr: false,
			checkLease: func(t *testing.T, l *Lease) {
				if !l.IP.Equal(net.ParseIP("192.168.1.100")) {
					t.Errorf("IP = %s", l.IP)
				}
				if l.PrefixLen != 24 {
					t.Errorf("PrefixLen = %d", l.PrefixLen)
				}
				if !l.Gateway.Equal(net.ParseIP("192.168.1.1")) {
					t.Errorf("Gateway = %s", l.Gateway)
				}
				if len(l.DNSServers) != 2 {
					t.Errorf("DNSServers count = %d", len(l.DNSServers))
				}
				if l.LeaseTime != 3600*time.Second {
					t.Errorf("LeaseTime = %v", l.LeaseTime)
				}
				if !l.ServerID.Equal(net.ParseIP("192.168.1.1")) {
					t.Errorf("ServerID = %s", l.ServerID)
				}
			},
		},
		{
			name: "ACK without subnet mask (default /24)",
			ack: func() *dhcpv4.DHCPv4 {
				ack, _ := dhcpv4.New()
				ack.YourIPAddr = net.ParseIP("10.0.0.50")
				return ack
			}(),
			wantErr: false,
			checkLease: func(t *testing.T, l *Lease) {
				if l.PrefixLen != 24 {
					t.Errorf("PrefixLen = %d, want 24 (default)", l.PrefixLen)
				}
			},
		},
		{
			name: "ACK without optional fields",
			ack: func() *dhcpv4.DHCPv4 {
				ack, _ := dhcpv4.New()
				ack.YourIPAddr = net.ParseIP("10.0.0.50")
				ack.UpdateOption(dhcpv4.OptSubnetMask(net.CIDRMask(16, 32)))
				return ack
			}(),
			wantErr: false,
			checkLease: func(t *testing.T, l *Lease) {
				if l.PrefixLen != 16 {
					t.Errorf("PrefixLen = %d, want 16", l.PrefixLen)
				}
				if l.Gateway != nil {
					t.Errorf("Gateway should be nil")
				}
				if len(l.DNSServers) != 0 {
					t.Errorf("DNSServers should be empty")
				}
				if l.ServerID != nil {
					t.Errorf("ServerID should be nil")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lease, err := parseLease(tt.ack)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.checkLease != nil {
				tt.checkLease(t, lease)
			}
		})
	}
}

// --- mockDHCPClient for testing ---

type mockDHCPClient struct {
	requestFunc func(ctx context.Context, modifiers ...dhcpv4.Modifier) (*nclient4.Lease, error)
	closed      bool
}

func (m *mockDHCPClient) Request(ctx context.Context, modifiers ...dhcpv4.Modifier) (*nclient4.Lease, error) {
	if m.requestFunc != nil {
		return m.requestFunc(ctx, modifiers...)
	}
	return nil, fmt.Errorf("mock not configured")
}

func (m *mockDHCPClient) Close() error {
	m.closed = true
	return nil
}

// --- doRequest tests ---

func TestDoRequest(t *testing.T) {
	// Save original newClient and restore after test
	origNewClient := newClient
	defer func() { newClient = origNewClient }()

	t.Run("successful request", func(t *testing.T) {
		newClient = func(ifname string, opts ...nclient4.ClientOpt) (dhcpClient, error) {
			return &mockDHCPClient{
				requestFunc: func(ctx context.Context, modifiers ...dhcpv4.Modifier) (*nclient4.Lease, error) {
					ack, _ := dhcpv4.New()
					ack.YourIPAddr = net.ParseIP("192.168.1.100")
					ack.UpdateOption(dhcpv4.OptSubnetMask(net.CIDRMask(24, 32)))
					ack.UpdateOption(dhcpv4.OptRouter(net.ParseIP("192.168.1.1")))
					return &nclient4.Lease{ACK: ack}, nil
				},
			}, nil
		}

		iface := &net.Interface{Name: "mock0"}
		lease, err := doRequest(context.Background(), iface, time.Second)
		if err != nil {
			t.Fatalf("doRequest: %v", err)
		}
		if !lease.IP.Equal(net.ParseIP("192.168.1.100")) {
			t.Errorf("IP = %s", lease.IP)
		}
	})

	t.Run("client creation failure", func(t *testing.T) {
		newClient = func(ifname string, opts ...nclient4.ClientOpt) (dhcpClient, error) {
			return nil, fmt.Errorf("mock error: interface not found")
		}

		iface := &net.Interface{Name: "mock0"}
		_, err := doRequest(context.Background(), iface, time.Second)
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "failed to create DHCP client") {
			t.Errorf("error = %v", err)
		}
	})

	t.Run("request failure", func(t *testing.T) {
		newClient = func(ifname string, opts ...nclient4.ClientOpt) (dhcpClient, error) {
			return &mockDHCPClient{
				requestFunc: func(ctx context.Context, modifiers ...dhcpv4.Modifier) (*nclient4.Lease, error) {
					return nil, fmt.Errorf("mock error: no response")
				},
			}, nil
		}

		iface := &net.Interface{Name: "mock0"}
		_, err := doRequest(context.Background(), iface, time.Second)
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "DHCP request failed") {
			t.Errorf("error = %v", err)
		}
	})

	t.Run("context timeout", func(t *testing.T) {
		newClient = func(ifname string, opts ...nclient4.ClientOpt) (dhcpClient, error) {
			return &mockDHCPClient{
				requestFunc: func(ctx context.Context, modifiers ...dhcpv4.Modifier) (*nclient4.Lease, error) {
					<-ctx.Done()
					return nil, ctx.Err()
				},
			}, nil
		}

		iface := &net.Interface{Name: "mock0"}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		_, err := doRequest(ctx, iface, 100*time.Millisecond)
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

// --- Request tests ---

func TestRequest(t *testing.T) {
	// Save original newClient and restore after test
	origNewClient := newClient
	defer func() { newClient = origNewClient }()

	t.Run("empty interface error", func(t *testing.T) {
		_, err := Request(context.Background(), RequestOptions{})
		if err == nil || !strings.Contains(err.Error(), "interface name is required") {
			t.Errorf("expected interface required error, got %v", err)
		}
	})

	t.Run("nonexistent interface error", func(t *testing.T) {
		_, err := Request(context.Background(), RequestOptions{Interface: "nonexistent12345"})
		if err == nil {
			t.Error("expected error for nonexistent interface")
		}
	})

	t.Run("successful request with lo interface", func(t *testing.T) {
		newClient = func(ifname string, opts ...nclient4.ClientOpt) (dhcpClient, error) {
			return &mockDHCPClient{
				requestFunc: func(ctx context.Context, modifiers ...dhcpv4.Modifier) (*nclient4.Lease, error) {
					ack, _ := dhcpv4.New()
					ack.YourIPAddr = net.ParseIP("10.0.0.100")
					ack.UpdateOption(dhcpv4.OptSubnetMask(net.CIDRMask(24, 32)))
					return &nclient4.Lease{ACK: ack}, nil
				},
			}, nil
		}

		lease, err := Request(context.Background(), RequestOptions{
			Interface: "lo",
			Timeout:   time.Second,
			Retries:   0,
		})
		if err != nil {
			t.Fatalf("Request: %v", err)
		}
		if !lease.IP.Equal(net.ParseIP("10.0.0.100")) {
			t.Errorf("IP = %s", lease.IP)
		}
	})

	t.Run("retry on failure then succeed", func(t *testing.T) {
		attempts := 0
		newClient = func(ifname string, opts ...nclient4.ClientOpt) (dhcpClient, error) {
			return &mockDHCPClient{
				requestFunc: func(ctx context.Context, modifiers ...dhcpv4.Modifier) (*nclient4.Lease, error) {
					attempts++
					if attempts < 2 {
						return nil, fmt.Errorf("temporary failure")
					}
					ack, _ := dhcpv4.New()
					ack.YourIPAddr = net.ParseIP("10.0.0.100")
					return &nclient4.Lease{ACK: ack}, nil
				},
			}, nil
		}

		lease, err := Request(context.Background(), RequestOptions{
			Interface: "lo",
			Timeout:   100 * time.Millisecond,
			Retries:   2,
		})
		if err != nil {
			t.Fatalf("Request: %v", err)
		}
		if attempts != 2 {
			t.Errorf("attempts = %d, want 2", attempts)
		}
		_ = lease
	})

	t.Run("all retries fail", func(t *testing.T) {
		newClient = func(ifname string, opts ...nclient4.ClientOpt) (dhcpClient, error) {
			return &mockDHCPClient{
				requestFunc: func(ctx context.Context, modifiers ...dhcpv4.Modifier) (*nclient4.Lease, error) {
					return nil, fmt.Errorf("permanent failure")
				},
			}, nil
		}

		_, err := Request(context.Background(), RequestOptions{
			Interface: "lo",
			Timeout:   100 * time.Millisecond,
			Retries:   1,
		})
		if err == nil {
			t.Fatal("expected error after all retries")
		}
		if !strings.Contains(err.Error(), "failed after 2 attempts") {
			t.Errorf("error = %v", err)
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		newClient = func(ifname string, opts ...nclient4.ClientOpt) (dhcpClient, error) {
			return &mockDHCPClient{
				requestFunc: func(ctx context.Context, modifiers ...dhcpv4.Modifier) (*nclient4.Lease, error) {
					return nil, fmt.Errorf("failure")
				},
			}, nil
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		_, err := Request(ctx, RequestOptions{
			Interface: "lo",
			Timeout:   time.Second,
			Retries:   5,
		})
		if err != context.Canceled {
			t.Errorf("expected context.Canceled, got %v", err)
		}
	})
}
