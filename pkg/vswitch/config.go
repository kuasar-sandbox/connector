// Package vswitch provides the core switch logic.
package vswitch

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/fullof-work/sandbox-vswitch/pkg/internal/bpf"
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
//     the host without a dedicated netns. Written as `:<dev>:<routes>`.
//
// Each service-route is either a single IP (implies /32) or a CIDR.
// All service-routes serve dual purpose:
//   - Bound as addresses on the management device (for the service to listen on)
//   - Added to mgmt_cidrs in eBPF map (for traffic extraction from sandbox)
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
	ServiceRoutes []*net.IPNet // Service addresses/CIDRs to bind and extract
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

	// Parse comma-separated service routes
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
	Name              string           // Switch name
	SwitchNetNS       string           // Switch namespace name
	PortNetNS         string           // Ports namespace name
	NumPorts          uint32           // Number of ports
	MACAddr           net.HardwareAddr // Virtual MAC address
	FloatingIPBase    net.IP           // Floating IP base address
	MgmtExtracts      []*MgmtExtract   // Management plane extractions
	TransitDev        string           // Transit device name
	TransitAddr       *net.IPNet       // Transit device address (nil if auto)
	TransitNexthop    net.IP           // Transit nexthop (nil if auto)
	TransitAddrAuto   bool             // Use DHCP to acquire address in switch namespace
	TransitDevMTU     int              // Transit device MTU (0 = no change)
	TransitDevMTUAuto bool             // Use auto-calculated MTU for transit device
	GenevePortBase    uint16           // GENEVE UDP port base
	GeneveEncapEth    bool             // true = Ether-over-GENEVE, false = IP-over-GENEVE (default)
	MTU               int              // MTU for switch ports (0 = OS default)
	PortMAC           net.HardwareAddr // Port MAC: all-zero = per-port derivation, non-zero = fixed value

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
	if c.MTU < 0 || c.MTU > 65535 {
		return fmt.Errorf("MTU must be between 0 and 65535")
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
	SwitchName     string   `json:"switch_name"`
	SwitchNetNS    string   `json:"switch_netns"`
	PortNetNS      string   `json:"port_netns"`
	NumPorts       uint32   `json:"num_ports"`
	MACAddr        string   `json:"mac_addr"`
	FloatingIPBase string   `json:"floating_ip_base"`
	MgmtExtracts   []string `json:"mgmt_extracts,omitempty"`
	TransitDev     string   `json:"transit_dev,omitempty"`
	TransitDevAddr string   `json:"transit_dev_addr,omitempty"`
	TransitDevMTU  string   `json:"transit_dev_mtu,omitempty"`
	GenevePortBase uint16   `json:"geneve_port_base,omitempty"`
	GeneveEncapEth bool     `json:"geneve_encap_eth,omitempty"`
	MTU            int      `json:"mtu,omitempty"`
	PortMACAddr    string   `json:"port_mac_addr,omitempty"` // "fixed" (default), "per-port", or MAC address
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
		Name:           fc.SwitchName,
		SwitchNetNS:    fc.SwitchNetNS,
		PortNetNS:      fc.PortNetNS,
		NumPorts:       fc.NumPorts,
		MACAddr:        mac,
		FloatingIPBase: fip,
		GenevePortBase: fc.GenevePortBase,
		GeneveEncapEth: fc.GeneveEncapEth,
		MTU:            fc.MTU,
		TransitDev:     fc.TransitDev,
	}

	for _, s := range fc.MgmtExtracts {
		me, err := ParseMgmtExtract(s)
		if err != nil {
			return nil, fmt.Errorf("invalid mgmt_extract %q: %w", s, err)
		}
		cfg.MgmtExtracts = append(cfg.MgmtExtracts, me)
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
