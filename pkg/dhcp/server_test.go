package dhcp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

func TestNewIPPool(t *testing.T) {
	tests := []struct {
		name      string
		start     net.IP
		end       net.IP
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid range",
			start:   net.ParseIP("10.0.0.100"),
			end:     net.ParseIP("10.0.0.200"),
			wantErr: false,
		},
		{
			name:    "single IP range",
			start:   net.ParseIP("10.0.0.100"),
			end:     net.ParseIP("10.0.0.100"),
			wantErr: false,
		},
		{
			name:      "start greater than end",
			start:     net.ParseIP("10.0.0.200"),
			end:       net.ParseIP("10.0.0.100"),
			wantErr:   true,
			errSubstr: "greater than end",
		},
		{
			name:      "nil start",
			start:     nil,
			end:       net.ParseIP("10.0.0.100"),
			wantErr:   true,
			errSubstr: "invalid IP range",
		},
		{
			name:      "nil end",
			start:     net.ParseIP("10.0.0.100"),
			end:       nil,
			wantErr:   true,
			errSubstr: "invalid IP range",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool, err := newIPPool(tt.start, tt.end)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errSubstr != "" && !containsSubstr(err.Error(), tt.errSubstr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if pool == nil {
				t.Fatal("expected pool, got nil")
			}
		})
	}
}

func TestIPPoolAllocate(t *testing.T) {
	pool, err := newIPPool(net.ParseIP("10.0.0.100"), net.ParseIP("10.0.0.102"))
	if err != nil {
		t.Fatalf("failed to create pool: %v", err)
	}

	mac1, _ := net.ParseMAC("00:11:22:33:44:55")
	mac2, _ := net.ParseMAC("00:11:22:33:44:66")
	mac3, _ := net.ParseMAC("00:11:22:33:44:77")
	mac4, _ := net.ParseMAC("00:11:22:33:44:88")

	// First allocation
	ip1, err := pool.Allocate(mac1)
	if err != nil {
		t.Fatalf("Allocate mac1: %v", err)
	}
	if ip1.String() != "10.0.0.100" {
		t.Errorf("ip1 = %s, want 10.0.0.100", ip1)
	}

	// Same MAC should return same IP
	ip1Again, err := pool.Allocate(mac1)
	if err != nil {
		t.Fatalf("Allocate mac1 again: %v", err)
	}
	if !ip1Again.Equal(ip1) {
		t.Errorf("ip1Again = %s, want %s", ip1Again, ip1)
	}

	// Second MAC gets next IP
	ip2, err := pool.Allocate(mac2)
	if err != nil {
		t.Fatalf("Allocate mac2: %v", err)
	}
	if ip2.String() != "10.0.0.101" {
		t.Errorf("ip2 = %s, want 10.0.0.101", ip2)
	}

	// Third MAC gets last IP in pool
	ip3, err := pool.Allocate(mac3)
	if err != nil {
		t.Fatalf("Allocate mac3: %v", err)
	}
	if ip3.String() != "10.0.0.102" {
		t.Errorf("ip3 = %s, want 10.0.0.102", ip3)
	}

	// Fourth MAC should fail (pool exhausted)
	_, err = pool.Allocate(mac4)
	if err == nil {
		t.Fatal("expected error for exhausted pool")
	}
	if !containsSubstr(err.Error(), "exhausted") {
		t.Errorf("error %q does not contain 'exhausted'", err.Error())
	}

	// Existing MAC should still work
	ip2Again, err := pool.Allocate(mac2)
	if err != nil {
		t.Fatalf("Allocate mac2 after exhaustion: %v", err)
	}
	if !ip2Again.Equal(ip2) {
		t.Errorf("ip2Again = %s, want %s", ip2Again, ip2)
	}
}

func TestNewServer(t *testing.T) {
	tests := []struct {
		name      string
		cfg       ServerConfig
		wantErr   bool
		errSubstr string
	}{
		{
			name: "valid config",
			cfg: ServerConfig{
				Interface: "eth0",
				ServerIP:  net.ParseIP("10.0.0.1"),
				PoolStart: net.ParseIP("10.0.0.100"),
				PoolEnd:   net.ParseIP("10.0.0.200"),
			},
			wantErr: false,
		},
		{
			name: "with all options",
			cfg: ServerConfig{
				Interface: "eth0",
				ServerIP:  net.ParseIP("10.0.0.1"),
				PoolStart: net.ParseIP("10.0.0.100"),
				PoolEnd:   net.ParseIP("10.0.0.200"),
				Netmask:   net.CIDRMask(24, 32),
				Gateway:   net.ParseIP("10.0.0.1"),
				DNS:       []net.IP{net.ParseIP("8.8.8.8")},
				LeaseTime: 2 * time.Hour,
			},
			wantErr: false,
		},
		{
			name: "missing interface",
			cfg: ServerConfig{
				ServerIP:  net.ParseIP("10.0.0.1"),
				PoolStart: net.ParseIP("10.0.0.100"),
				PoolEnd:   net.ParseIP("10.0.0.200"),
			},
			wantErr:   true,
			errSubstr: "interface is required",
		},
		{
			name: "missing server IP",
			cfg: ServerConfig{
				Interface: "eth0",
				PoolStart: net.ParseIP("10.0.0.100"),
				PoolEnd:   net.ParseIP("10.0.0.200"),
			},
			wantErr:   true,
			errSubstr: "server IP is required",
		},
		{
			name: "missing pool start",
			cfg: ServerConfig{
				Interface: "eth0",
				ServerIP:  net.ParseIP("10.0.0.1"),
				PoolEnd:   net.ParseIP("10.0.0.200"),
			},
			wantErr:   true,
			errSubstr: "IP pool range is required",
		},
		{
			name: "missing pool end",
			cfg: ServerConfig{
				Interface: "eth0",
				ServerIP:  net.ParseIP("10.0.0.1"),
				PoolStart: net.ParseIP("10.0.0.100"),
			},
			wantErr:   true,
			errSubstr: "IP pool range is required",
		},
		{
			name: "invalid pool range",
			cfg: ServerConfig{
				Interface: "eth0",
				ServerIP:  net.ParseIP("10.0.0.1"),
				PoolStart: net.ParseIP("10.0.0.200"),
				PoolEnd:   net.ParseIP("10.0.0.100"),
			},
			wantErr:   true,
			errSubstr: "failed to create IP pool",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, err := NewServer(tt.cfg)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errSubstr != "" && !containsSubstr(err.Error(), tt.errSubstr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if srv == nil {
				t.Fatal("expected server, got nil")
			}
		})
	}
}

func TestServerConfigDefaults(t *testing.T) {
	cfg := ServerConfig{
		Interface: "eth0",
		ServerIP:  net.ParseIP("10.0.0.1"),
		PoolStart: net.ParseIP("10.0.0.100"),
		PoolEnd:   net.ParseIP("10.0.0.200"),
		// Netmask, Gateway, LeaseTime are not set - should use defaults
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	// Check that defaults were applied
	if srv.cfg.Netmask == nil {
		t.Error("Netmask should have default value")
	}
	ones, bits := srv.cfg.Netmask.Size()
	if ones != 24 || bits != 32 {
		t.Errorf("Netmask = /%d, want /24", ones)
	}

	if srv.cfg.Gateway == nil {
		t.Error("Gateway should default to ServerIP")
	}
	if !srv.cfg.Gateway.Equal(cfg.ServerIP) {
		t.Errorf("Gateway = %s, want %s", srv.cfg.Gateway, cfg.ServerIP)
	}

	if srv.cfg.LeaseTime != time.Hour {
		t.Errorf("LeaseTime = %v, want %v", srv.cfg.LeaseTime, time.Hour)
	}
}

func TestIP4ToUint32(t *testing.T) {
	tests := []struct {
		ip   net.IP
		want uint32
	}{
		{net.ParseIP("0.0.0.0").To4(), 0},
		{net.ParseIP("0.0.0.1").To4(), 1},
		{net.ParseIP("0.0.1.0").To4(), 256},
		{net.ParseIP("10.0.0.100").To4(), 0x0a000064},
		{net.ParseIP("255.255.255.255").To4(), 0xffffffff},
		{nil, 0},
	}

	for _, tt := range tests {
		got := ip4ToUint32(tt.ip)
		if got != tt.want {
			t.Errorf("ip4ToUint32(%v) = %d, want %d", tt.ip, got, tt.want)
		}
	}
}

func TestUint32ToIP4(t *testing.T) {
	tests := []struct {
		n    uint32
		want string
	}{
		{0, "0.0.0.0"},
		{1, "0.0.0.1"},
		{256, "0.0.1.0"},
		{0x0a000064, "10.0.0.100"},
		{0xffffffff, "255.255.255.255"},
	}

	for _, tt := range tests {
		got := uint32ToIP4(tt.n)
		if got.String() != tt.want {
			t.Errorf("uint32ToIP4(%d) = %s, want %s", tt.n, got, tt.want)
		}
	}
}

func containsSubstr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstr(s, substr)))
}

func findSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// --- ipPool tests ---

func TestIPPoolAllocateSingleIP(t *testing.T) {
	// Pool with single IP (start == end)
	pool, err := newIPPool(net.ParseIP("10.0.0.100"), net.ParseIP("10.0.0.100"))
	if err != nil {
		t.Fatalf("newIPPool: %v", err)
	}

	mac1, _ := net.ParseMAC("00:11:22:33:44:55")
	mac2, _ := net.ParseMAC("00:11:22:33:44:66")

	// First allocation should succeed
	ip1, err := pool.Allocate(mac1)
	if err != nil {
		t.Fatalf("Allocate mac1: %v", err)
	}
	if ip1.String() != "10.0.0.100" {
		t.Errorf("ip1 = %s, want 10.0.0.100", ip1)
	}

	// Second allocation should fail (pool exhausted)
	_, err = pool.Allocate(mac2)
	if err == nil {
		t.Fatal("expected error for exhausted pool")
	}
}

func TestIPPoolSameMACMultipleCalls(t *testing.T) {
	pool, err := newIPPool(net.ParseIP("10.0.0.100"), net.ParseIP("10.0.0.110"))
	if err != nil {
		t.Fatalf("newIPPool: %v", err)
	}

	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	// Allocate same MAC multiple times - should return same IP
	ip1, _ := pool.Allocate(mac)
	ip2, _ := pool.Allocate(mac)
	ip3, _ := pool.Allocate(mac)

	if !ip1.Equal(ip2) || !ip2.Equal(ip3) {
		t.Errorf("same MAC should return same IP: %s, %s, %s", ip1, ip2, ip3)
	}
}

// --- ServerConfig defaults ---

func TestServerConfigDefaultValues(t *testing.T) {
	cfg := ServerConfig{
		Interface: "eth0",
		ServerIP:  net.ParseIP("10.0.0.1"),
		PoolStart: net.ParseIP("10.0.0.100"),
		PoolEnd:   net.ParseIP("10.0.0.200"),
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	// Check defaults were applied
	if server.cfg.Netmask == nil {
		t.Error("Netmask should have default")
	}
	if server.cfg.Gateway == nil {
		t.Error("Gateway should default to ServerIP")
	}
	if !server.cfg.Gateway.Equal(cfg.ServerIP) {
		t.Errorf("Gateway = %s, want %s", server.cfg.Gateway, cfg.ServerIP)
	}
	if server.cfg.LeaseTime != time.Hour {
		t.Errorf("LeaseTime = %v, want 1h", server.cfg.LeaseTime)
	}
}

// --- Server Close tests ---

func TestServerCloseBeforeServe(t *testing.T) {
	cfg := ServerConfig{
		Interface: "eth0",
		ServerIP:  net.ParseIP("10.0.0.1"),
		PoolStart: net.ParseIP("10.0.0.100"),
		PoolEnd:   net.ParseIP("10.0.0.200"),
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	// Close without starting Serve should not panic
	err = server.Close()
	if err != nil {
		t.Errorf("Close before Serve: %v", err)
	}

	// Double close should be safe
	err = server.Close()
	if err != nil {
		t.Errorf("Double Close: %v", err)
	}
}

// --- IP conversion roundtrip ---

func TestIP4Roundtrip(t *testing.T) {
	ips := []string{"0.0.0.0", "10.0.0.1", "192.168.1.100", "255.255.255.255"}
	for _, s := range ips {
		ip := net.ParseIP(s).To4()
		n := ip4ToUint32(ip)
		back := uint32ToIP4(n)
		if !ip.Equal(back) {
			t.Errorf("roundtrip failed: %s -> %d -> %s", s, n, back)
		}
	}
}

// --- Helper function for creating test servers ---

func createTestServer(t *testing.T) *Server {
	t.Helper()
	srv, err := NewServer(ServerConfig{
		Interface: "lo",
		ServerIP:  net.ParseIP("10.0.0.1"),
		PoolStart: net.ParseIP("10.0.0.100"),
		PoolEnd:   net.ParseIP("10.0.0.200"),
		Netmask:   net.CIDRMask(24, 32),
		DNS:       []net.IP{net.ParseIP("8.8.8.8")},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv
}

// --- handleDiscover tests ---

func TestHandleDiscover(t *testing.T) {
	srv := createTestServer(t)
	mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}

	discover, err := dhcpv4.NewDiscovery(mac)
	if err != nil {
		t.Fatalf("NewDiscovery: %v", err)
	}

	offer, err := srv.handleDiscover(discover)
	if err != nil {
		t.Fatalf("handleDiscover: %v", err)
	}

	if offer.MessageType() != dhcpv4.MessageTypeOffer {
		t.Errorf("MessageType = %v, want Offer", offer.MessageType())
	}
	if !offer.YourIPAddr.Equal(net.ParseIP("10.0.0.100")) {
		t.Errorf("YourIPAddr = %s, want 10.0.0.100", offer.YourIPAddr)
	}
}

func TestHandleDiscoverPoolExhausted(t *testing.T) {
	// Create server with single IP pool
	srv, err := NewServer(ServerConfig{
		Interface: "lo",
		ServerIP:  net.ParseIP("10.0.0.1"),
		PoolStart: net.ParseIP("10.0.0.100"),
		PoolEnd:   net.ParseIP("10.0.0.100"),
		Netmask:   net.CIDRMask(24, 32),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	// First client gets the only IP
	mac1 := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	discover1, _ := dhcpv4.NewDiscovery(mac1)
	_, err = srv.handleDiscover(discover1)
	if err != nil {
		t.Fatalf("handleDiscover first: %v", err)
	}

	// Second client should fail (pool exhausted)
	mac2 := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x66}
	discover2, _ := dhcpv4.NewDiscovery(mac2)
	_, err = srv.handleDiscover(discover2)
	if err == nil {
		t.Fatal("expected error for exhausted pool")
	}
}

// --- handleRequest tests ---

func TestHandleRequest(t *testing.T) {
	srv := createTestServer(t)
	mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}

	// First allocate via Discover
	discover, _ := dhcpv4.NewDiscovery(mac)
	offer, err := srv.handleDiscover(discover)
	if err != nil {
		t.Fatalf("handleDiscover: %v", err)
	}

	t.Run("valid request", func(t *testing.T) {
		request, _ := dhcpv4.New()
		request.ClientHWAddr = mac
		request.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeRequest))
		request.UpdateOption(dhcpv4.OptRequestedIPAddress(offer.YourIPAddr))

		ack, err := srv.handleRequest(request)
		if err != nil {
			t.Fatalf("handleRequest: %v", err)
		}
		if ack.MessageType() != dhcpv4.MessageTypeAck {
			t.Errorf("MessageType = %v, want Ack", ack.MessageType())
		}
	})

	t.Run("wrong IP request returns NAK", func(t *testing.T) {
		// Request a different IP than allocated
		request, _ := dhcpv4.New()
		request.ClientHWAddr = mac
		request.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeRequest))
		request.UpdateOption(dhcpv4.OptRequestedIPAddress(net.ParseIP("10.0.0.200")))

		nak, err := srv.handleRequest(request)
		if err != nil {
			t.Fatalf("handleRequest: %v", err)
		}
		if nak.MessageType() != dhcpv4.MessageTypeNak {
			t.Errorf("MessageType = %v, want Nak", nak.MessageType())
		}
	})
}

func TestHandleRequestWithClientIP(t *testing.T) {
	srv := createTestServer(t)
	mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}

	// First allocate via Discover
	discover, _ := dhcpv4.NewDiscovery(mac)
	offer, _ := srv.handleDiscover(discover)

	// Request using ClientIPAddr instead of RequestedIPAddress option
	request, _ := dhcpv4.New()
	request.ClientHWAddr = mac
	request.ClientIPAddr = offer.YourIPAddr
	request.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeRequest))

	ack, err := srv.handleRequest(request)
	if err != nil {
		t.Fatalf("handleRequest: %v", err)
	}
	if ack.MessageType() != dhcpv4.MessageTypeAck {
		t.Errorf("MessageType = %v, want Ack", ack.MessageType())
	}
}

// --- buildResponse tests ---

func TestBuildResponse(t *testing.T) {
	srv := createTestServer(t)
	mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	request, _ := dhcpv4.NewDiscovery(mac)

	t.Run("Offer response", func(t *testing.T) {
		resp, err := srv.buildResponse(request, dhcpv4.MessageTypeOffer, net.ParseIP("10.0.0.100"))
		if err != nil {
			t.Fatalf("buildResponse: %v", err)
		}
		if resp.MessageType() != dhcpv4.MessageTypeOffer {
			t.Errorf("MessageType = %v", resp.MessageType())
		}
		if !resp.YourIPAddr.Equal(net.ParseIP("10.0.0.100")) {
			t.Errorf("YourIPAddr = %s", resp.YourIPAddr)
		}
		if resp.SubnetMask() == nil {
			t.Error("SubnetMask should be set")
		}
		if len(resp.Router()) == 0 {
			t.Error("Router should be set")
		}
		if len(resp.DNS()) == 0 {
			t.Error("DNS should be set")
		}
		if resp.ServerIdentifier() == nil {
			t.Error("ServerIdentifier should be set")
		}
	})

	t.Run("Ack response", func(t *testing.T) {
		resp, err := srv.buildResponse(request, dhcpv4.MessageTypeAck, net.ParseIP("10.0.0.100"))
		if err != nil {
			t.Fatalf("buildResponse: %v", err)
		}
		if resp.MessageType() != dhcpv4.MessageTypeAck {
			t.Errorf("MessageType = %v", resp.MessageType())
		}
	})
}

func TestBuildResponseWithoutDNS(t *testing.T) {
	// Create server without DNS
	srv, err := NewServer(ServerConfig{
		Interface: "lo",
		ServerIP:  net.ParseIP("10.0.0.1"),
		PoolStart: net.ParseIP("10.0.0.100"),
		PoolEnd:   net.ParseIP("10.0.0.200"),
		// No DNS
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	request, _ := dhcpv4.NewDiscovery(mac)

	resp, err := srv.buildResponse(request, dhcpv4.MessageTypeOffer, net.ParseIP("10.0.0.100"))
	if err != nil {
		t.Fatalf("buildResponse: %v", err)
	}

	if len(resp.DNS()) != 0 {
		t.Errorf("DNS should be empty, got %v", resp.DNS())
	}
}

// --- buildNAK tests ---

func TestBuildNAK(t *testing.T) {
	srv := createTestServer(t)
	mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	request, _ := dhcpv4.NewDiscovery(mac)

	nak, err := srv.buildNAK(request)
	if err != nil {
		t.Fatalf("buildNAK: %v", err)
	}
	if nak.MessageType() != dhcpv4.MessageTypeNak {
		t.Errorf("MessageType = %v, want Nak", nak.MessageType())
	}
	if nak.ServerIdentifier() == nil {
		t.Error("ServerIdentifier should be set")
	}
}

// --- handler tests ---

type mockPacketConn struct {
	writtenData []byte
	writtenAddr net.Addr
}

func (m *mockPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) { return 0, nil, nil }
func (m *mockPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	m.writtenData = p
	m.writtenAddr = addr
	return len(p), nil
}
func (m *mockPacketConn) Close() error                       { return nil }
func (m *mockPacketConn) LocalAddr() net.Addr                { return nil }
func (m *mockPacketConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockPacketConn) SetWriteDeadline(t time.Time) error { return nil }

func TestHandler(t *testing.T) {
	srv := createTestServer(t)

	t.Run("nil message", func(t *testing.T) {
		mock := &mockPacketConn{}
		srv.handler(mock, nil, nil)
		// Should not panic, no response written
		if mock.writtenData != nil {
			t.Error("unexpected response for nil message")
		}
	})

	t.Run("discover message", func(t *testing.T) {
		mock := &mockPacketConn{}
		mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
		discover, _ := dhcpv4.NewDiscovery(mac)
		srv.handler(mock, &net.UDPAddr{IP: net.IPv4zero, Port: 68}, discover)
		if mock.writtenData == nil {
			t.Error("expected response to be written")
		}
	})

	t.Run("request message", func(t *testing.T) {
		mock := &mockPacketConn{}
		mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x66}
		request, _ := dhcpv4.New()
		request.ClientHWAddr = mac
		request.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeRequest))
		srv.handler(mock, &net.UDPAddr{IP: net.IPv4zero, Port: 68}, request)
		if mock.writtenData == nil {
			t.Error("expected response to be written")
		}
	})

	t.Run("unknown message type ignored", func(t *testing.T) {
		mock := &mockPacketConn{}
		inform, _ := dhcpv4.New()
		inform.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeInform))
		srv.handler(mock, &net.UDPAddr{IP: net.IPv4zero, Port: 68}, inform)
		if mock.writtenData != nil {
			t.Error("unexpected response for Inform message")
		}
	})
}

func TestHandlerDestinationRouting(t *testing.T) {
	srv := createTestServer(t)
	mac := net.HardwareAddr{0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}
	discover, _ := dhcpv4.NewDiscovery(mac)

	t.Run("broadcast when no client IP", func(t *testing.T) {
		mock := &mockPacketConn{}
		discover.ClientIPAddr = nil
		discover.GatewayIPAddr = nil
		srv.handler(mock, &net.UDPAddr{IP: net.IPv4zero, Port: 68}, discover)

		udpAddr, ok := mock.writtenAddr.(*net.UDPAddr)
		if !ok {
			t.Fatal("expected UDP address")
		}
		if !udpAddr.IP.Equal(net.IPv4bcast) {
			t.Errorf("destination IP = %s, want broadcast", udpAddr.IP)
		}
		if udpAddr.Port != 68 {
			t.Errorf("destination port = %d, want 68", udpAddr.Port)
		}
	})

	t.Run("unicast to client IP", func(t *testing.T) {
		mock := &mockPacketConn{}
		discover2, _ := dhcpv4.NewDiscovery(net.HardwareAddr{0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xff})
		discover2.ClientIPAddr = net.ParseIP("192.168.1.50")
		srv.handler(mock, &net.UDPAddr{IP: net.IPv4zero, Port: 68}, discover2)

		udpAddr, ok := mock.writtenAddr.(*net.UDPAddr)
		if !ok {
			t.Fatal("expected UDP address")
		}
		if !udpAddr.IP.Equal(net.ParseIP("192.168.1.50")) {
			t.Errorf("destination IP = %s, want 192.168.1.50", udpAddr.IP)
		}
	})

	t.Run("relay agent address", func(t *testing.T) {
		mock := &mockPacketConn{}
		discover3, _ := dhcpv4.NewDiscovery(net.HardwareAddr{0x00, 0xaa, 0xbb, 0xcc, 0xee, 0x11})
		discover3.GatewayIPAddr = net.ParseIP("10.0.0.254")
		srv.handler(mock, &net.UDPAddr{IP: net.IPv4zero, Port: 68}, discover3)

		udpAddr, ok := mock.writtenAddr.(*net.UDPAddr)
		if !ok {
			t.Fatal("expected UDP address")
		}
		if !udpAddr.IP.Equal(net.ParseIP("10.0.0.254")) {
			t.Errorf("destination IP = %s, want relay 10.0.0.254", udpAddr.IP)
		}
		if udpAddr.Port != 67 {
			t.Errorf("destination port = %d, want 67", udpAddr.Port)
		}
	})
}

// --- Serve tests (with non-privileged port) ---

func TestServeContextCancellation(t *testing.T) {
	srv, err := NewServer(ServerConfig{
		Interface: "lo",
		ServerIP:  net.ParseIP("127.0.0.1"),
		PoolStart: net.ParseIP("127.0.0.100"),
		PoolEnd:   net.ParseIP("127.0.0.200"),
		Port:      16768, // Non-privileged port
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ctx)
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Cancel context
	cancel()

	select {
	case <-errCh:
		// Server responded to cancellation
	case <-time.After(2 * time.Second):
		t.Error("Serve did not respond to context cancellation")
	}
}

func TestServerPortConfiguration(t *testing.T) {
	t.Run("default port", func(t *testing.T) {
		srv, err := NewServer(ServerConfig{
			Interface: "lo",
			ServerIP:  net.ParseIP("10.0.0.1"),
			PoolStart: net.ParseIP("10.0.0.100"),
			PoolEnd:   net.ParseIP("10.0.0.200"),
		})
		if err != nil {
			t.Fatalf("NewServer: %v", err)
		}
		if srv.cfg.Port != 67 {
			t.Errorf("default Port = %d, want 67", srv.cfg.Port)
		}
	})

	t.Run("custom port", func(t *testing.T) {
		srv, err := NewServer(ServerConfig{
			Interface: "lo",
			ServerIP:  net.ParseIP("10.0.0.1"),
			PoolStart: net.ParseIP("10.0.0.100"),
			PoolEnd:   net.ParseIP("10.0.0.200"),
			Port:      16767,
		})
		if err != nil {
			t.Fatalf("NewServer: %v", err)
		}
		if srv.cfg.Port != 16767 {
			t.Errorf("Port = %d, want 16767", srv.cfg.Port)
		}
	})
}

func TestServerCloseAfterServe(t *testing.T) {
	srv, err := NewServer(ServerConfig{
		Interface: "lo",
		ServerIP:  net.ParseIP("127.0.0.1"),
		PoolStart: net.ParseIP("127.0.0.100"),
		PoolEnd:   net.ParseIP("127.0.0.200"),
		Port:      16769,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ctx)
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Close the server directly
	err = srv.Close()
	if err != nil {
		t.Logf("Close returned: %v (may be expected)", err)
	}

	// Wait for Serve to return
	select {
	case <-errCh:
		// Server stopped
	case <-time.After(2 * time.Second):
		t.Error("Serve did not stop after Close")
	}

	// Double close should be safe
	err = srv.Close()
	if err != nil {
		t.Errorf("Double Close returned error: %v", err)
	}
}
