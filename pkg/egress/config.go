// Package egress manages the unified local and remote Geneve Egress gateway.
package egress

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

const defaultMaxContexts = 65536

var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)

type Config struct {
	Name               string       `json:"name"`
	RuntimeDir         string       `json:"runtime_dir"`
	VPP                string       `json:"vpp"`
	PluginPath         string       `json:"plugin_path"`
	LibraryPath        string       `json:"library_path,omitempty"`
	Workers            []uint32     `json:"workers,omitempty"`
	MainCore           *uint32      `json:"main_core,omitempty"`
	MaxConnections     uint32       `json:"max_connections"`
	Interfaces         []Interface  `json:"interfaces"`
	Exits              []Exit       `json:"exits"`
	Attachments        []Attachment `json:"attachments"`
	Areas              []Area       `json:"areas,omitempty"`
	AreaFiles          []string     `json:"area_files,omitempty"`
	MaxContexts        uint32       `json:"max_contexts,omitempty"`
	ContextIdleSeconds uint32       `json:"context_idle_seconds,omitempty"`
	Timeouts           NATTimeouts  `json:"timeouts,omitempty"`
	HeapSize           string       `json:"heap_size,omitempty"`
	StatsSize          string       `json:"stats_size,omitempty"`
}
type Interface struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	MTU     uint32 `json:"mtu"`
}
type Exit struct {
	Name      string   `json:"name"`
	Interface string   `json:"interface"`
	NextHop   string   `json:"next_hop"`
	Addresses []string `json:"addresses"`
}
type Attachment struct {
	Name           string `json:"name"`
	Interface      string `json:"interface"`
	Peer           string `json:"peer"`
	NextHop        string `json:"next_hop,omitempty"`
	Area           uint32 `json:"area"`
	Locator        string `json:"locator"`
	PortBase       uint32 `json:"port_base,omitempty"`
	TLVClass       uint32 `json:"tlv_class,omitempty"`
	TLVType        uint32 `json:"tlv_type,omitempty"`
	Encapsulation  string `json:"encapsulation"`
	GenerationBits uint32 `json:"generation_bits"`
	Gateway        string `json:"gateway"`
	MTU            uint32 `json:"mtu,omitempty"`
	InnerMTU       uint32 `json:"inner_mtu,omitempty"`
}
type Match struct {
	Destination string `json:"destination"`
	Protocol    string `json:"protocol"`
	PortFirst   uint16 `json:"port_first,omitempty"`
	PortLast    uint16 `json:"port_last,omitempty"`
}
type ACL struct {
	Match
	Action string `json:"action"`
}
type DNAT struct {
	Match
	Pool       uint32 `json:"pool"`
	Target     string `json:"target"`
	TargetPort uint16 `json:"target_port,omitempty"`
}
type Route struct {
	Destination string `json:"destination"`
	Pool        uint32 `json:"pool"`
}
type Pool struct {
	ID             uint32   `json:"id"`
	Exit           string   `json:"exit"`
	Addresses      []string `json:"addresses"`
	MaxConnections uint32   `json:"max_connections"`
}
type Area struct {
	VNI    uint32  `json:"vni"`
	Pools  []Pool  `json:"pools"`
	ACL    []ACL   `json:"acl"`
	DNAT   []DNAT  `json:"dnat"`
	Routes []Route `json:"routes"`
}

// NATTimeouts are connection inactivity limits, never sandbox leases.
type NATTimeouts struct {
	UDP            uint32 `json:"udp,omitempty"`
	TCPTransitory  uint32 `json:"tcp_transitory,omitempty"`
	TCPEstablished uint32 `json:"tcp_established,omitempty"`
	ICMP           uint32 `json:"icmp,omitempty"`
}

func Decode(r io.Reader, value any) error {
	raw, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	return decodeJSON(raw, value)
}

func decodeBounded(r io.Reader, value any, limit int64) error {
	raw, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return err
	}
	if int64(len(raw)) > limit {
		return fmt.Errorf("JSON exceeds %d-byte limit", limit)
	}
	return decodeJSON(raw, value)
}

func decodeJSON(raw []byte, value any) error {
	if trimmed := bytes.TrimSpace(raw); len(trimmed) == 0 || trimmed[0] != '{' {
		return errors.New("expected a JSON object")
	}
	if err := checkJSONValue(json.NewDecoder(bytes.NewReader(raw)), 0); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return errors.New("expected one complete JSON value")
	}
	return nil
}
func checkJSONValue(d *json.Decoder, depth int) error {
	if depth > 64 {
		return errors.New("JSON nesting exceeds 64 levels")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if delimiter == '{' {
		keys := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || keys[strings.ToLower(name)] {
				return errors.New("duplicate or invalid JSON member")
			}
			keys[strings.ToLower(name)] = true
			if err := checkJSONValue(d, depth+1); err != nil {
				return err
			}
		}
	} else if delimiter == '[' {
		for d.More() {
			if err := checkJSONValue(d, depth+1); err != nil {
				return err
			}
		}
	} else {
		return errors.New("unexpected JSON delimiter")
	}
	_, err = d.Token()
	return err
}
func LoadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var c Config
	if err = Decode(f, &c); err != nil {
		return nil, err
	}
	for _, name := range c.AreaFiles {
		if !filepath.IsAbs(name) {
			name = filepath.Join(filepath.Dir(path), name)
		}
		f, err := os.Open(name)
		if err != nil {
			return nil, fmt.Errorf("Area file %s: %w", name, err)
		}
		var area Area
		err = Decode(f, &area)
		closeErr := f.Close()
		if err != nil {
			return nil, fmt.Errorf("Area file %s: %w", name, err)
		}
		if closeErr != nil {
			return nil, closeErr
		}
		c.Areas = append(c.Areas, area)
	}
	if err = c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}
func ipv4(s string) (netip.Addr, error) {
	a, e := netip.ParseAddr(s)
	if e != nil || !a.Is4() || a.IsUnspecified() || a.IsMulticast() || a.IsLoopback() || a == netip.MustParseAddr("255.255.255.255") {
		return netip.Addr{}, fmt.Errorf("invalid unicast IPv4 address %q", s)
	}
	return a, nil
}
func prefix(s string) (netip.Prefix, error) {
	p, e := netip.ParsePrefix(s)
	if e != nil || !p.Addr().Is4() || p.Masked() != p {
		return netip.Prefix{}, fmt.Errorf("invalid canonical IPv4 prefix %q", s)
	}
	return p, nil
}
func protocol(s string) (uint8, error) {
	switch s {
	case "any":
		return 0, nil
	case "icmp":
		return 1, nil
	case "tcp":
		return 6, nil
	case "udp":
		return 17, nil
	}
	return 0, fmt.Errorf("unsupported protocol %q", s)
}
func (m Match) validate() error {
	if _, e := prefix(m.Destination); e != nil {
		return e
	}
	if _, e := protocol(m.Protocol); e != nil {
		return e
	}
	if m.PortFirst > m.PortLast || (m.PortFirst == 0) != (m.PortLast == 0) {
		return errors.New("invalid port interval")
	}
	if m.PortFirst != 0 && m.Protocol != "tcp" && m.Protocol != "udp" {
		return errors.New("ports require TCP or UDP")
	}
	return nil
}
func (c *Config) Validate() error {
	if !identifier.MatchString(c.Name) {
		return errors.New("invalid gateway name")
	}
	if c.RuntimeDir == "" {
		c.RuntimeDir = filepath.Join("/run/connector-egress", c.Name)
	}
	for _, p := range []string{c.RuntimeDir, c.VPP, c.PluginPath} {
		if !filepath.IsAbs(p) || strings.ContainsAny(p, "\n\r\t {}\"\\") || filepath.Clean(p) == "/" {
			return fmt.Errorf("invalid absolute runtime path %q", p)
		}
	}
	if strings.ContainsAny(c.LibraryPath, "\n\r") {
		return errors.New("invalid library path")
	}
	if c.MaxContexts == 0 {
		c.MaxContexts = defaultMaxContexts
	}
	if c.ContextIdleSeconds == 0 {
		c.ContextIdleSeconds = 1
	}
	if c.HeapSize == "" {
		c.HeapSize = "4G"
	}
	if c.StatsSize == "" {
		c.StatsSize = "1G"
	}
	for _, size := range []string{c.HeapSize, c.StatsSize} {
		if !regexp.MustCompile(`^[1-9][0-9]*[MG]$`).MatchString(size) {
			return errors.New("heap_size and stats_size must be a positive number of M or G")
		}
	}
	if c.Timeouts.UDP == 0 {
		c.Timeouts.UDP = 300
	}
	if c.Timeouts.TCPTransitory == 0 {
		c.Timeouts.TCPTransitory = 240
	}
	if c.Timeouts.TCPEstablished == 0 {
		c.Timeouts.TCPEstablished = 7440
	}
	if c.Timeouts.ICMP == 0 {
		c.Timeouts.ICMP = 60
	}
	if c.MaxConnections == 0 {
		c.MaxConnections = 65536
	}
	cpus := map[uint32]bool{}
	if c.MainCore != nil {
		cpus[*c.MainCore] = true
	}
	for _, cpu := range c.Workers {
		if cpus[cpu] {
			return errors.New("duplicate CPU assignment")
		}
		cpus[cpu] = true
	}
	if len(c.Interfaces) == 0 || len(c.Exits) == 0 {
		return errors.New("at least one interface and exit are required")
	}
	interfaces := map[string]Interface{}
	for _, i := range c.Interfaces {
		if !identifier.MatchString(i.Name) || len(i.Name) > 15 {
			return fmt.Errorf("invalid interface %q", i.Name)
		}
		if _, ok := interfaces[i.Name]; ok {
			return errors.New("duplicate interface")
		}
		p, e := netip.ParsePrefix(i.Address)
		if e != nil || !p.Addr().Is4() {
			return fmt.Errorf("invalid interface address %q", i.Address)
		}
		if _, e = ipv4(p.Addr().String()); e != nil {
			return e
		}
		if i.MTU < 128 || i.MTU > 65535 {
			return errors.New("invalid interface MTU")
		}
		interfaces[i.Name] = i
	}
	exits := map[string]Exit{}
	exitIf := map[string]bool{}
	snat := map[string]string{}
	for _, e := range c.Exits {
		if !identifier.MatchString(e.Name) {
			return errors.New("invalid exit name")
		}
		if _, ok := exits[e.Name]; ok {
			return errors.New("duplicate exit")
		}
		i, ok := interfaces[e.Interface]
		if !ok {
			return errors.New("exit references unknown interface")
		}
		exitIf[e.Interface] = true
		hop, err := ipv4(e.NextHop)
		if err != nil {
			return err
		}
		ip := netip.MustParsePrefix(i.Address)
		if !ip.Contains(hop) || hop == ip.Addr() {
			return errors.New("exit next hop must be a different on-link address")
		}
		if len(e.Addresses) == 0 {
			return errors.New("exit requires SNAT addresses")
		}
		seenAddresses := map[string]bool{}
		for _, a := range e.Addresses {
			if seenAddresses[a] {
				return errors.New("duplicate SNAT resource in exit")
			}
			seenAddresses[a] = true
			if _, err := ipv4(a); err != nil {
				return err
			}
			if prior, exists := snat[a]; exists && prior != e.Interface {
				return errors.New("SNAT address cannot belong to different external interfaces")
			}
			snat[a] = e.Interface
		}
		exits[e.Name] = e
	}
	areas := map[uint32]bool{}
	for _, a := range c.Areas {
		if areas[a.VNI] {
			return errors.New("duplicate Area")
		}
		areas[a.VNI] = true
		if err := c.ValidateArea(a); err != nil {
			return err
		}
	}
	peers := map[string]Attachment{}
	peerAreas := map[string]bool{}
	names := map[string]bool{}
	for n := range c.Attachments {
		a := &c.Attachments[n]
		if !identifier.MatchString(a.Name) || names[a.Name] {
			return errors.New("invalid or duplicate attachment name")
		}
		names[a.Name] = true
		i, ok := interfaces[a.Interface]
		if !ok || exitIf[a.Interface] {
			return errors.New("attachment requires a dedicated transit interface")
		}
		if !areas[a.Area] {
			return errors.New("attachment references unknown Area")
		}
		if _, e := ipv4(a.Peer); e != nil {
			return e
		}
		if _, e := ipv4(a.Gateway); e != nil {
			return e
		}
		key := a.Interface + "/" + a.Peer
		addr := netip.MustParsePrefix(i.Address)
		if addr.Addr().String() == a.Peer {
			return errors.New("peer collides with local VTEP")
		}
		if a.NextHop == "" {
			a.NextHop = a.Peer
		}
		hop, err := ipv4(a.NextHop)
		if err != nil || !addr.Contains(hop) || hop == addr.Addr() {
			return errors.New("transit next hop must be a different on-link address; routed peers require next_hop")
		}
		if a.Locator == "" {
			a.Locator = "port"
		}
		if a.PortBase == 0 {
			a.PortBase = 50000
		}
		switch a.Locator {
		case "port":
			if a.PortBase > 65535 {
				return errors.New("port_base exceeds the UDP port field")
			}
		case "vni":
			if a.Area > 4095 {
				return errors.New("vni locator requires a 12-bit logical Area")
			}
		case "tlv":
			if a.TLVClass > 65535 || a.TLVType > 255 {
				return errors.New("invalid TLV locator")
			}
		default:
			return errors.New("unsupported locator")
		}
		if a.Encapsulation != "ip" && a.Encapsulation != "ether" {
			return errors.New("encapsulation must be ip or ether")
		}
		if a.GenerationBits > 20 {
			return errors.New("generation_bits exceeds existing vSwitch contract")
		}
		if a.MTU == 0 {
			a.MTU = i.MTU
		}
		if a.InnerMTU == 0 {
			a.InnerMTU = 1500
		}
		profile := *a
		profile.Name, profile.Gateway, profile.Area, profile.PortBase = "", "", 0, 0
		if prior, found := peers[key]; found && prior != profile {
			return errors.New("Areas on one peer require the same locator and fencing profile")
		}
		peers[key] = profile
		identity := fmt.Sprintf("%s/%d", key, a.Area)
		if peerAreas[identity] {
			return errors.New("duplicate peer/Area attachment")
		}
		peerAreas[identity] = true
		overhead := uint32(36)
		if a.Encapsulation == "ether" {
			overhead += 14
		}
		if a.Locator == "tlv" {
			overhead += 8
		}
		if a.MTU > i.MTU || a.MTU < overhead+68 {
			return errors.New("transit MTU cannot carry IPv4 plus Geneve")
		}
		if a.InnerMTU < 68 || a.InnerMTU > 65535-overhead {
			return errors.New("invalid sandbox inner_mtu")
		}
	}
	return nil
}
func (c *Config) ValidateArea(a Area) error {
	if a.VNI > 0xffffff {
		return errors.New("Area VNI exceeds its 24-bit wire field")
	}
	pools := map[uint32]bool{}
	for _, p := range a.Pools {
		if pools[p.ID] {
			return errors.New("Pool IDs must be unique")
		}
		pools[p.ID] = true
		var found *Exit
		for i := range c.Exits {
			if c.Exits[i].Name == p.Exit {
				found = &c.Exits[i]
			}
		}
		if found == nil {
			return errors.New("Pool references unknown exit")
		}
		if len(p.Addresses) == 0 {
			return errors.New("Pool requires addresses")
		}
		seen := map[string]bool{}
		for _, ip := range p.Addresses {
			if !slices.Contains(found.Addresses, ip) || seen[ip] {
				return errors.New("Pool address must be a distinct configured exit resource")
			}
			seen[ip] = true
		}
	}
	for _, r := range a.ACL {
		if err := r.Match.validate(); err != nil {
			return err
		}
		if r.Action != "allow" && r.Action != "deny" {
			return errors.New("ACL action must be allow or deny")
		}
	}
	for _, r := range a.DNAT {
		if err := r.Match.validate(); err != nil {
			return err
		}
		if r.Protocol != "tcp" && r.Protocol != "udp" {
			return errors.New("DNAT requires TCP or UDP")
		}
		if _, err := ipv4(r.Target); err != nil {
			return err
		}
		if !pools[r.Pool] {
			return errors.New("DNAT references unknown Pool")
		}
	}
	routes := map[string]bool{}
	for _, r := range a.Routes {
		if _, err := prefix(r.Destination); err != nil {
			return err
		}
		if routes[r.Destination] || !pools[r.Pool] {
			return errors.New("duplicate route or unknown Pool")
		}
		routes[r.Destination] = true
	}
	return nil
}
func (c *Config) attachment(name string) (Attachment, Interface, error) {
	for _, a := range c.Attachments {
		if a.Name == name {
			for _, i := range c.Interfaces {
				if i.Name == a.Interface {
					return a, i, nil
				}
			}
		}
	}
	return Attachment{}, Interface{}, errors.New("unknown attachment")
}
