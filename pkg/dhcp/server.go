package dhcp

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/server4"
)

// ServerConfig configures the DHCP server.
type ServerConfig struct {
	Interface string        // Network interface to listen on
	ServerIP  net.IP        // Server IP address
	PoolStart net.IP        // IP pool start address
	PoolEnd   net.IP        // IP pool end address
	Netmask   net.IPMask    // Subnet mask
	Gateway   net.IP        // Default gateway (optional, defaults to ServerIP)
	DNS       []net.IP      // DNS servers (optional)
	LeaseTime time.Duration // Lease duration (default: 1 hour)
	Port      int           // Server port (default: 67)
}

// Server is a simple DHCP server for testing purposes.
type Server struct {
	cfg    ServerConfig
	pool   *ipPool
	server *server4.Server
	done   chan struct{}
}

// ipPool manages IP address allocation.
type ipPool struct {
	mu     sync.Mutex
	start  uint32
	end    uint32
	next   uint32
	leases map[string]net.IP // MAC address string -> allocated IP
}

func newIPPool(start, end net.IP) (*ipPool, error) {
	s := ip4ToUint32(start.To4())
	e := ip4ToUint32(end.To4())
	if s == 0 || e == 0 {
		return nil, fmt.Errorf("invalid IP range: start=%v, end=%v", start, end)
	}
	if s > e {
		return nil, fmt.Errorf("pool start %v is greater than end %v", start, end)
	}
	return &ipPool{
		start:  s,
		end:    e,
		next:   s,
		leases: make(map[string]net.IP),
	}, nil
}

func (p *ipPool) Allocate(mac net.HardwareAddr) (net.IP, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	macStr := mac.String()

	// Return existing lease for same MAC
	if ip, ok := p.leases[macStr]; ok {
		return ip, nil
	}

	// Check if pool is exhausted
	if p.next > p.end {
		return nil, fmt.Errorf("IP pool exhausted")
	}

	// Allocate new IP
	ip := uint32ToIP4(p.next)
	p.leases[macStr] = ip
	p.next++

	return ip, nil
}

func ip4ToUint32(ip net.IP) uint32 {
	if ip == nil || len(ip) != 4 {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

func uint32ToIP4(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}

// NewServer creates a new DHCP server.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Interface == "" {
		return nil, fmt.Errorf("interface is required")
	}
	if cfg.ServerIP == nil {
		return nil, fmt.Errorf("server IP is required")
	}
	if cfg.PoolStart == nil || cfg.PoolEnd == nil {
		return nil, fmt.Errorf("IP pool range is required")
	}
	if cfg.Netmask == nil {
		cfg.Netmask = net.CIDRMask(24, 32)
	}
	if cfg.Gateway == nil {
		cfg.Gateway = cfg.ServerIP
	}
	if cfg.LeaseTime == 0 {
		cfg.LeaseTime = time.Hour
	}
	if cfg.Port == 0 {
		cfg.Port = 67 // Default DHCP server port
	}

	pool, err := newIPPool(cfg.PoolStart, cfg.PoolEnd)
	if err != nil {
		return nil, fmt.Errorf("failed to create IP pool: %w", err)
	}

	return &Server{
		cfg:  cfg,
		pool: pool,
		done: make(chan struct{}),
	}, nil
}

// Serve starts the DHCP server and blocks until the context is cancelled.
func (s *Server) Serve(ctx context.Context) error {
	laddr := &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: s.cfg.Port,
	}

	srv, err := server4.NewServer(s.cfg.Interface, laddr, s.handler)
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}
	s.server = srv

	// Handle context cancellation
	go func() {
		select {
		case <-ctx.Done():
			if err := s.Close(); err != nil {
				//ignore err
			}
		case <-s.done:
		}
	}()

	return srv.Serve()
}

// Close stops the DHCP server.
func (s *Server) Close() error {
	select {
	case <-s.done:
		// Already closed
		return nil
	default:
		close(s.done)
	}
	if s.server != nil {
		return s.server.Close()
	}
	return nil
}

func (s *Server) handler(conn net.PacketConn, peer net.Addr, m *dhcpv4.DHCPv4) {
	if m == nil {
		return
	}

	var resp *dhcpv4.DHCPv4
	var err error

	switch m.MessageType() {
	case dhcpv4.MessageTypeDiscover:
		resp, err = s.handleDiscover(m)
	case dhcpv4.MessageTypeRequest:
		resp, err = s.handleRequest(m)
	default:
		// Ignore other message types
		return
	}

	if err != nil {
		return
	}
	if resp == nil {
		return
	}

	// Send response - use broadcast for DISCOVER/REQUEST from client with no IP
	var dest net.Addr
	if m.GatewayIPAddr != nil && !m.GatewayIPAddr.IsUnspecified() {
		// Relay agent present, send to relay
		dest = &net.UDPAddr{IP: m.GatewayIPAddr, Port: 67}
	} else if m.ClientIPAddr != nil && !m.ClientIPAddr.IsUnspecified() {
		// Client has IP, send unicast
		dest = &net.UDPAddr{IP: m.ClientIPAddr, Port: 68}
	} else {
		// Broadcast
		dest = &net.UDPAddr{IP: net.IPv4bcast, Port: 68}
	}

	if _, err := conn.WriteTo(resp.ToBytes(), dest); err != nil {
		//ignore error
	}
}

func (s *Server) handleDiscover(m *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, error) {
	ip, err := s.pool.Allocate(m.ClientHWAddr)
	if err != nil {
		return nil, err
	}

	return s.buildResponse(m, dhcpv4.MessageTypeOffer, ip)
}

func (s *Server) handleRequest(m *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, error) {
	// Get requested IP from options or use allocated IP
	requestedIP := m.RequestedIPAddress()
	if requestedIP == nil || requestedIP.IsUnspecified() {
		requestedIP = m.ClientIPAddr
	}

	// Allocate (or get existing) IP for this MAC
	ip, err := s.pool.Allocate(m.ClientHWAddr)
	if err != nil {
		return nil, err
	}

	// If client requested a specific IP, verify it matches
	if requestedIP != nil && !requestedIP.IsUnspecified() && !requestedIP.Equal(ip) {
		// Client requested different IP, send NAK
		return s.buildNAK(m)
	}

	return s.buildResponse(m, dhcpv4.MessageTypeAck, ip)
}

func (s *Server) buildResponse(m *dhcpv4.DHCPv4, msgType dhcpv4.MessageType, ip net.IP) (*dhcpv4.DHCPv4, error) {
	modifiers := []dhcpv4.Modifier{
		dhcpv4.WithMessageType(msgType),
		dhcpv4.WithServerIP(s.cfg.ServerIP),
		dhcpv4.WithYourIP(ip),
		dhcpv4.WithOption(dhcpv4.OptSubnetMask(s.cfg.Netmask)),
		dhcpv4.WithOption(dhcpv4.OptRouter(s.cfg.Gateway)),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(s.cfg.ServerIP)),
		dhcpv4.WithOption(dhcpv4.OptIPAddressLeaseTime(s.cfg.LeaseTime)),
	}

	if len(s.cfg.DNS) > 0 {
		modifiers = append(modifiers, dhcpv4.WithOption(dhcpv4.OptDNS(s.cfg.DNS...)))
	}

	return dhcpv4.NewReplyFromRequest(m, modifiers...)
}

func (s *Server) buildNAK(m *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, error) {
	return dhcpv4.NewReplyFromRequest(m,
		dhcpv4.WithMessageType(dhcpv4.MessageTypeNak),
		dhcpv4.WithServerIP(s.cfg.ServerIP),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(s.cfg.ServerIP)),
	)
}
