// Package vswitch provides the core switch logic.
package vswitch

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/kuasar-sandbox/connector/pkg/internal/bpf"
)

const (
	MaxPorts = bpf.MaxPorts

	// GeneveIPOverhead is the encapsulation overhead for IP-over-GENEVE:
	// ETH(14) + IP(20) + UDP(8) + GENEVE(8) = 50 bytes
	GeneveIPOverhead = 50

	// GeneveEthOverhead is the encapsulation overhead for Ether-over-GENEVE:
	// GeneveIPOverhead + inner ETH(14) = 64 bytes
	GeneveEthOverhead = 64
)

// MgmtExtract represents a management plane extraction configuration.
//
// Format: <netns>:<dev>:<service-route1>,<service-route2>,...
//
// `<netns>` is either:
//   - A named network namespace (must already exist, e.g. created by
//     `ip netns add`); the mgmt veth peer is moved into that netns.
//   - Empty — the mgmt veth peer stays in the caller netns (typically the
//     host/root netns). Useful when the management service runs directly on
//     the host without a dedicated netns. Written as `:<dev>:<cidrs>`.
//
// Each service-route is either a single IP (implies /32) or a CIDR. Despite the
// retained field and CLI naming, these values only define destination matches
// written to mgmt_cidrs for sandbox traffic extraction. Connector does not
// assign them as addresses on the management device. Address ownership, local
// routes, service listeners, and related sysctls belong to deployment tooling.
//
// A return route scoped to the floating-IP range is added on the management
// device so management-service replies to a floating_ip route back through
// sw-mX without hijacking the mgmt namespace default route. The range is the
// fixed /20 (MaxPorts=4096) containing floating_ip_base:
//
//	ip route add <floating_ip_base>/20 dev <dev> metric <100+index>
//
// If floating_ip_base is not /20-aligned the range straddles two adjacent /20
// blocks and both are installed (no alignment requirement).
type MgmtExtract struct {
	NetNS         string       // Management namespace name; "" = caller netns
	Dev           string       // Device name in management namespace
	ServiceRoutes []*net.IPNet // Extraction match CIDRs; not interface addresses
}

// IsCallerNetNS reports whether the management plane lives in the caller's
// network namespace (i.e. NetNS was left empty in the --mgmt-extract spec).
func (m *MgmtExtract) IsCallerNetNS() bool {
	return m.NetNS == ""
}

// ParseMgmtExtract parses a management extraction string.
// Format: <netns>:<dev>:<service-route1>,<service-route2>,...
// `<netns>` may be empty to keep the mgmt veth peer in the caller netns.
func ParseMgmtExtract(s string) (*MgmtExtract, error) {
	// Split only the first two colons to get netns:dev:routes
	// This avoids issues with IPv6 addresses (not currently supported, but safe)
	parts := strings.SplitN(s, ":", 3)
	// netns (parts[0]) is allowed to be empty (= caller netns); dev and routes are not.
	if len(parts) != 3 || parts[1] == "" || parts[2] == "" {
		return nil, fmt.Errorf("invalid mgmt-extract format: %q\nexpected <netns>:<dev>:<service-route1>,<service-route2>,... (<netns> may be empty for caller netns)", s)
	}

	me := &MgmtExtract{
		NetNS: parts[0],
		Dev:   parts[1],
	}

	// Parse comma-separated extraction CIDRs into the retained ServiceRoutes field.
	for _, item := range strings.Split(parts[2], ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}

		var cidr *net.IPNet
		if strings.Contains(item, "/") {
			_, cidr2, err := net.ParseCIDR(item)
			if err != nil {
				return nil, fmt.Errorf("invalid service route %q: %w", item, err)
			}
			cidr = cidr2
		} else {
			ip := net.ParseIP(item)
			if ip == nil {
				return nil, fmt.Errorf("invalid service route %q: not a valid IP", item)
			}
			cidr = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
		}

		me.ServiceRoutes = append(me.ServiceRoutes, cidr)
	}

	if len(me.ServiceRoutes) == 0 {
		return nil, fmt.Errorf("mgmt-extract requires at least one service route")
	}

	return me, nil
}

// MgmtService is a stateless, port-aware VIP<->target translation layered on
// top of an existing --mgmt-extract management plane.
//
// Format: <VIP>:<vport>:<targetIP>:<targetPort>
//
// Sandbox traffic to VIP:vport is rewritten to targetIP:targetPort on egress
// (in addition to the inner_ip->floating_ip SNAT), and replies from
// targetIP:targetPort are rewritten back so the sandbox sees the VIP. The
// translation matches BOTH TCP and UDP. The VIP MUST fall within one of the
// --mgmt-extract extraction CIDRs (so the mgmt CIDR match selects the right mgmt
// device), and each (targetIP, targetPort) must be unique across all services
// (the reverse map keys on it). IPv4 only, consistent with the mgmt plane.
//
// The target's reachability inside the mgmt netns is the operator's
// responsibility. In particular a loopback target (e.g. 127.0.0.1:19254)
// requires `sysctl net.ipv4.conf.<mgmt-dev>.route_localnet=1` so the kernel
// accepts the redirected packet and lets the reply leave the device.
type MgmtService struct {
	VIP        net.IP
	VPort      uint16
	TargetIP   net.IP
	TargetPort uint16
}

// String renders the service in its canonical CLI form.
func (s *MgmtService) String() string {
	return fmt.Sprintf("%s:%d:%s:%d", s.VIP, s.VPort, s.TargetIP, s.TargetPort)
}

// ParseMgmtService parses a management service translation string.
// Format: <VIP>:<vport>:<targetIP>:<targetPort>
func ParseMgmtService(s string) (*MgmtService, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid mgmt-service format: %q\nexpected <VIP>:<vport>:<targetIP>:<targetPort>", s)
	}

	vip := net.ParseIP(parts[0])
	if vip == nil || vip.To4() == nil {
		return nil, fmt.Errorf("invalid mgmt-service VIP %q: must be an IPv4 address", parts[0])
	}
	vport, err := parsePort(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid mgmt-service vport %q: %w", parts[1], err)
	}
	targetIP := net.ParseIP(parts[2])
	if targetIP == nil || targetIP.To4() == nil {
		return nil, fmt.Errorf("invalid mgmt-service targetIP %q: must be an IPv4 address", parts[2])
	}
	targetPort, err := parsePort(parts[3])
	if err != nil {
		return nil, fmt.Errorf("invalid mgmt-service targetPort %q: %w", parts[3], err)
	}

	return &MgmtService{
		VIP:        vip.To4(),
		VPort:      vport,
		TargetIP:   targetIP.To4(),
		TargetPort: targetPort,
	}, nil
}

// parsePort parses a TCP/UDP port in the range 1..65535.
func parsePort(s string) (uint16, error) {
	p, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("not a number")
	}
	if p < 1 || p > 65535 {
		return 0, fmt.Errorf("must be between 1 and 65535")
	}
	return uint16(p), nil
}

// ParseTransitDevAddr parses transit device address configuration.
// Format: <ip>/<prefix>:<nexthop>
func ParseTransitDevAddr(s string) (*net.IPNet, net.IP, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return nil, nil, fmt.Errorf("invalid transit-dev-addr format, expected <ip>/<prefix>:<nexthop>")
	}

	ip, ipnet, err := net.ParseCIDR(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("invalid address: %w", err)
	}
	ipnet.IP = ip // preserve host address, not network address

	gw := net.ParseIP(parts[1])
	if gw == nil {
		return nil, nil, fmt.Errorf("invalid nexthop: %s", parts[1])
	}

	return ipnet, gw, nil
}

// Config holds the switch configuration.
type Config struct {
	Name              string            // Switch name
	SwitchNetNS       string            // Switch namespace name
	PortNetNS         string            // Ports namespace name
	NumPorts          uint32            // Number of ports
	MACAddr           net.HardwareAddr  // Virtual MAC address
	FloatingIPBase    net.IP            // Floating IP base address
	MgmtExtracts      []*MgmtExtract    // Management plane extraction CIDR matches
	MgmtServices      []*MgmtService    // Management service VIP<->target translations (require MgmtExtracts)
	TransitDev        string            // Transit device name
	TransitAddr       *net.IPNet        // Transit device address (nil if auto)
	TransitNexthop    net.IP            // Transit nexthop (nil if auto)
	TransitAddrAuto   bool              // Use DHCP to acquire address in switch namespace
	TransitDevMTU     int               // Transit device MTU (0 = no change)
	TransitDevMTUAuto bool              // Use auto-calculated MTU for transit device
	GenevePortBase    uint16            // GENEVE UDP port base
	GeneveLocator     GeneveLocator     // slot_id wire locator; zero value is legacy port mode
	GeneveTLVLocator  *GeneveTLVLocator // exact class/type for the TLV locator
	GeneveEncapEth    bool              // true = Ether-over-GENEVE, false = IP-over-GENEVE (default)
	MTU               int               // MTU for switch ports (0 = OS default)
	PortMAC           net.HardwareAddr  // Port MAC: all-zero = per-port derivation, non-zero = fixed value

	// DefaultMode is used by Start() to auto-provision all ports with this kind
	// at switch creation. Per-slot mode is still recorded in slot.Mode by
	// ProvisionPorts; this field only controls the initial bulk provision and
	// is NOT persisted. Default (PortKindVeth) preserves backward compatibility.
	// Mutually exclusive with Reserved-only start (which has no auto-provision).
	DefaultMode PortKind
}

// Validate validates the switch configuration for a full `Start` (which runs
// auto-provision). Use ValidateReserved for the `StartReserved`-only path.
func (c *Config) Validate() error {
	if err := c.validateBase(); err != nil {
		return err
	}
	// port-netns is required for veth mode (the sandbox-side veth peer lives
	// there before attach). Tap-mode ports stay in switch-netns and do not
	// need a separate port-netns. This check is skipped under ValidateReserved
	// because no provisioning happens at start time — the user supplies the
	// port-netns later (it's resolved from metadata at `provision --mode=veth`
	// time, and `provision --mode=tap` does not need it at all).
	if c.PortNetNS == "" && c.DefaultMode != PortKindTap {
		return fmt.Errorf("port netns is required for veth mode")
	}
	return nil
}

// ValidateReserved validates the switch configuration for a `StartReserved`-only
// start. Port-netns may be left empty because no port devices are provisioned at
// start time. Provisioning later via `provision --mode=veth` will surface a
// clear error if the switch was started without a port-netns.
func (c *Config) ValidateReserved() error {
	return c.validateBase()
}

// validateBase runs the checks that apply to every start path.
func (c *Config) validateBase() error {
	c.applyGeneveDefaults()
	if c.Name == "" {
		return fmt.Errorf("switch name is required")
	}
	if c.SwitchNetNS == "" {
		return fmt.Errorf("switch netns is required")
	}
	if c.NumPorts == 0 || c.NumPorts > MaxPorts {
		return fmt.Errorf("ports must be between 1 and %d", MaxPorts)
	}
	if len(c.MACAddr) != 6 {
		return fmt.Errorf("invalid MAC address")
	}
	if c.FloatingIPBase == nil {
		return fmt.Errorf("floating-ip-base is required")
	}
	if len(c.MgmtExtracts) > int(MaxMgmtCIDRPerSlot) {
		return fmt.Errorf("too many mgmt-extract entries (max %d)", MaxMgmtCIDRPerSlot)
	}
	if err := c.validateMgmtServices(); err != nil {
		return err
	}
	if err := c.validateGeneve(); err != nil {
		return err
	}
	if c.MTU < 0 || c.MTU > 65535 {
		return fmt.Errorf("MTU must be between 0 and 65535")
	}
	return nil
}

// applyGeneveDefaults keeps CLI, file, and directly-constructed Config values
// consistent. GeneveLocatorPort is already the zero value by ABI design.
func (c *Config) applyGeneveDefaults() {
	if c.GenevePortBase == 0 {
		c.GenevePortBase = DefaultGenevePortBase
	}
}

func (c *Config) validateGeneve() error {
	if !c.GeneveLocator.valid() {
		return fmt.Errorf("unknown GENEVE locator value %d", c.GeneveLocator)
	}

	switch c.GeneveLocator {
	case GeneveLocatorPort:
		if c.GeneveTLVLocator != nil {
			return fmt.Errorf("geneve_tlv_locator is only valid with geneve_locator=tlv")
		}
		lastPort := uint32(c.GenevePortBase) + c.NumPorts - 1
		if lastPort > 65535 {
			return fmt.Errorf("geneve_port_base %d with %d ports exceeds UDP port 65535", c.GenevePortBase, c.NumPorts)
		}
	case GeneveLocatorVNI:
		if c.GeneveTLVLocator != nil {
			return fmt.Errorf("geneve_tlv_locator is only valid with geneve_locator=tlv")
		}
		if c.GenevePortBase != DefaultGenevePortBase {
			return fmt.Errorf("geneve_port_base is not configurable with geneve_locator=vni; UDP port is fixed at %d", GeneveStandardPort)
		}
	case GeneveLocatorTLV:
		if c.GeneveTLVLocator == nil {
			return fmt.Errorf("geneve_tlv_locator is required with geneve_locator=tlv")
		}
		if c.GenevePortBase != DefaultGenevePortBase {
			return fmt.Errorf("geneve_port_base is not configurable with geneve_locator=tlv; UDP port is fixed at %d", GeneveStandardPort)
		}
	}
	return nil
}

// validateMgmtServices checks that every service VIP falls inside a configured
// mgmt-extract extraction CIDR, and that each (targetIP, targetPort) is unique so the
// ingress reverse map can resolve a single VIP.
func (c *Config) validateMgmtServices() error {
	if len(c.MgmtServices) == 0 {
		return nil
	}
	if len(c.MgmtExtracts) == 0 {
		return fmt.Errorf("--mgmt-service requires at least one --mgmt-extract")
	}

	type targetKey struct {
		ip   string
		port uint16
	}
	seen := make(map[targetKey]string)

	for _, svc := range c.MgmtServices {
		// VIP must fall within some mgmt-extract extraction CIDR.
		inRange := false
		for _, me := range c.MgmtExtracts {
			for _, sr := range me.ServiceRoutes {
				if sr.Contains(svc.VIP) {
					inRange = true
					break
				}
			}
			if inRange {
				break
			}
		}
		if !inRange {
			return fmt.Errorf("mgmt-service VIP %s is not within any --mgmt-extract route", svc.VIP)
		}

		// (targetIP, targetPort) must be unique across services.
		k := targetKey{ip: svc.TargetIP.String(), port: svc.TargetPort}
		if prev, ok := seen[k]; ok {
			return fmt.Errorf("mgmt-service target %s:%d is used by both %q and %q (must be unique)",
				svc.TargetIP, svc.TargetPort, prev, svc.String())
		}
		seen[k] = svc.String()
	}
	return nil
}

// PortDeviceName returns the device name for a sandbox port.
func (c *Config) PortDeviceName(slotID int) string {
	return fmt.Sprintf("%s-p%d", c.Name, slotID+1)
}

// PeerDeviceName returns the device name for a port's peer in switch namespace.
func (c *Config) PeerDeviceName(slotID int) string {
	return fmt.Sprintf("%s-n%d", c.Name, slotID+1)
}

// TapDeviceName returns the device name for a tap-mode port in switch namespace.
// Used instead of veth pair when the slot is provisioned as PortKindTap.
func (c *Config) TapDeviceName(slotID int) string {
	return fmt.Sprintf("%s-t%d", c.Name, slotID+1)
}

// MgmtDeviceName returns the device name for a management port in switch namespace.
func (c *Config) MgmtDeviceName(idx int) string {
	return fmt.Sprintf("%s-m%d", c.Name, idx)
}

// DummyDeviceName returns the device name for the block anchor dummy device.
func (c *Config) DummyDeviceName() string {
	return c.Name + "-dummy"
}

// FileConfig is the JSON file format for switch configuration.
type FileConfig struct {
	SwitchName       string            `json:"switch_name"`
	SwitchNetNS      string            `json:"switch_netns"`
	PortNetNS        string            `json:"port_netns"`
	NumPorts         uint32            `json:"num_ports"`
	MACAddr          string            `json:"mac_addr"`
	FloatingIPBase   string            `json:"floating_ip_base"`
	MgmtExtracts     []string          `json:"mgmt_extracts,omitempty"`
	MgmtServices     []string          `json:"mgmt_services,omitempty"`
	TransitDev       string            `json:"transit_dev,omitempty"`
	TransitDevAddr   string            `json:"transit_dev_addr,omitempty"`
	TransitDevMTU    string            `json:"transit_dev_mtu,omitempty"`
	GeneveLocator    GeneveLocator     `json:"geneve_locator,omitempty"`
	GenevePortBase   uint16            `json:"geneve_port_base,omitempty"`
	GeneveTLVLocator *GeneveTLVLocator `json:"geneve_tlv_locator,omitempty"`
	GeneveEncapEth   bool              `json:"geneve_encap_eth,omitempty"`
	MTU              int               `json:"mtu,omitempty"`
	PortMACAddr      string            `json:"port_mac_addr,omitempty"` // "fixed" (default), "per-port", or MAC address
}

// LoadConfigFile reads and parses a switch configuration from a JSON file.
func LoadConfigFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var fc FileConfig
	if err := json.Unmarshal(data, &fc); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	return fc.ToConfig()
}

// ToConfig converts FileConfig to Config.
func (fc *FileConfig) ToConfig() (*Config, error) {
	mac, err := net.ParseMAC(fc.MACAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid mac_addr %q: %w", fc.MACAddr, err)
	}

	fip := net.ParseIP(fc.FloatingIPBase)
	if fip == nil {
		return nil, fmt.Errorf("invalid floating_ip_base %q", fc.FloatingIPBase)
	}

	cfg := &Config{
		Name:             fc.SwitchName,
		SwitchNetNS:      fc.SwitchNetNS,
		PortNetNS:        fc.PortNetNS,
		NumPorts:         fc.NumPorts,
		MACAddr:          mac,
		FloatingIPBase:   fip,
		GeneveLocator:    fc.GeneveLocator,
		GenevePortBase:   fc.GenevePortBase,
		GeneveTLVLocator: fc.GeneveTLVLocator,
		GeneveEncapEth:   fc.GeneveEncapEth,
		MTU:              fc.MTU,
		TransitDev:       fc.TransitDev,
	}
	cfg.applyGeneveDefaults()

	for _, s := range fc.MgmtExtracts {
		me, err := ParseMgmtExtract(s)
		if err != nil {
			return nil, fmt.Errorf("invalid mgmt_extract %q: %w", s, err)
		}
		cfg.MgmtExtracts = append(cfg.MgmtExtracts, me)
	}

	for _, s := range fc.MgmtServices {
		svc, err := ParseMgmtService(s)
		if err != nil {
			return nil, fmt.Errorf("invalid mgmt_service %q: %w", s, err)
		}
		cfg.MgmtServices = append(cfg.MgmtServices, svc)
	}

	if fc.TransitDevAddr != "" {
		if fc.TransitDevAddr == "auto" {
			cfg.TransitAddrAuto = true
		} else {
			addr, gw, err := ParseTransitDevAddr(fc.TransitDevAddr)
			if err != nil {
				return nil, fmt.Errorf("invalid transit_dev_addr %q: %w", fc.TransitDevAddr, err)
			}
			cfg.TransitAddr = addr
			cfg.TransitNexthop = gw
		}
	}

	if fc.TransitDevMTU != "" {
		if fc.TransitDevMTU == "auto" {
			cfg.TransitDevMTUAuto = true
		} else {
			mtu, err := strconv.Atoi(fc.TransitDevMTU)
			if err != nil || mtu <= 0 {
				return nil, fmt.Errorf("invalid transit_dev_mtu %q", fc.TransitDevMTU)
			}
			cfg.TransitDevMTU = mtu
		}
	}

	// Parse port_mac_addr, default to "fixed"
	portMACAddr := fc.PortMACAddr
	if portMACAddr == "" {
		portMACAddr = "fixed"
	}
	switch portMACAddr {
	case "fixed":
		cfg.PortMAC = PortMACFixed(mac)
	case "per-port":
		cfg.PortMAC = make(net.HardwareAddr, 6) // all zeros
	default:
		portMAC, err := net.ParseMAC(portMACAddr)
		if err != nil {
			return nil, fmt.Errorf("invalid port_mac_addr %q: expected 'fixed', 'per-port', or MAC address", portMACAddr)
		}
		cfg.PortMAC = portMAC
	}

	return cfg, nil
}
