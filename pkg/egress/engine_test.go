package egress

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validConfig() Config {
	return Config{Name: "test", RuntimeDir: "/run/connector-egress/test", VPP: "/opt/egress/bin/vpp", PluginPath: "/opt/egress/plugins",
		Interfaces:  []Interface{{Name: "transit", Address: "198.18.0.1/24", MTU: 1500}, {Name: "outside", Address: "192.0.2.1/24", MTU: 1500}},
		Attachments: []Attachment{{Name: "local", Interface: "transit", Peer: []string{"198.18.0.2"}, Locator: "port"}},
		Areas:       []Area{{VNI: 7, Pools: []Pool{{Name: "public", Interface: "outside", NextHop: "192.0.2.2", Addresses: []string{"192.0.2.1"}, MaxConnections: 2}}, ACL: []ACL{{Match: Match{Destination: "203.0.113.0/24", Protocol: "any"}, Action: "allow"}}, Routes: []Route{{Destination: "0.0.0.0/0", Pool: "public"}}}},
	}
}

func TestConfigurationRejectsAmbiguousOrUnsafeRouting(t *testing.T) {
	for name, change := range map[string]func(*Config){
		"command injection in address": func(c *Config) { c.Areas[0].Routes[0].Destination = "0.0.0.0/0\negress-policy commit" },
		"unknown Pool":                 func(c *Config) { c.Areas[0].Routes[0].Pool = "missing" },
		"noncanonical prefix":          func(c *Config) { c.Areas[0].Routes[0].Destination = "203.0.113.1/24" },
		"unknown Pool interface":       func(c *Config) { c.Areas[0].Pools[0].Interface = "missing" },
		"ambiguous same-prefix routes": func(c *Config) {
			p := c.Areas[0].Pools[0]
			p.Name = "other"
			c.Areas[0].Pools = append(c.Areas[0].Pools, p)
			route := c.Areas[0].Routes[0]
			route.Pool = "other"
			c.Areas[0].Routes = append(c.Areas[0].Routes, route)
		},
		"VNI exceeds wire field":           func(c *Config) { c.Areas[0].VNI = 0x1000000 },
		"IP domain overlap":                func(c *Config) { c.Attachments[0].Interface = "outside"; c.Attachments[0].Peer = []string{"192.0.2.2"} },
		"TLV class exceeds wire field":     func(c *Config) { c.Attachments[0].Locator = "tlv"; c.Attachments[0].TLVClass = 65536 },
		"reserved protocol":                func(c *Config) { c.Areas[0].ACL[0].Protocol = "gre" },
		"port match on arbitrary protocol": func(c *Config) { c.Areas[0].ACL[0].PortFirst = 1; c.Areas[0].ACL[0].PortLast = 10 },
	} {
		t.Run(name, func(t *testing.T) {
			c := validConfig()
			change(&c)
			if err := c.Validate(); err == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
}
func TestStrictPublicSchema(t *testing.T) {
	for _, input := range []string{`{"name":"a","unknown":true}`, `{"name":"a"} {"name":"b"}`, `null true`, `{"name":"a","name":"b"}`, `{"areas":[{"vni":7,"vni":8}]}`} {
		var c Config
		if err := Decode(strings.NewReader(input), &c); err == nil {
			t.Errorf("accepted %s", input)
		}
	}
	c := validConfig()
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Config
	if err = Decode(strings.NewReader(string(raw)), &decoded); err != nil {
		t.Fatal(err)
	}
	if err = decoded.Validate(); err != nil {
		t.Fatal(err)
	}
}

type recordingRunner struct {
	commands []string
	fail     string
	lost     bool
}

func (r *recordingRunner) Run(_ context.Context, command string) (string, error) {
	r.commands = append(r.commands, command)
	if r.fail != "" && strings.HasPrefix(command, r.fail) {
		return "rejected staged configuration", nil
	}
	if command == "egress-geneve commit" {
		if r.lost {
			return "", context.DeadlineExceeded
		}
		return `{"committed":true}`, nil
	}
	if command == "egress-policy commit" {
		for i := len(r.commands) - 1; i >= 0; i-- {
			if strings.HasPrefix(r.commands[i], "egress-policy begin area ") {
				var id uint32
				fmt.Sscanf(r.commands[i], "egress-policy begin area %d", &id)
				return fmt.Sprintf(`{"area":%d,"staged":true}`, id), nil
			}
		}
	}
	if strings.HasPrefix(command, "create host-interface ") {
		return "host-" + strings.Fields(command)[4], nil
	}
	return "", nil
}
func TestAreaFilesLoadAsOneValidatedConfiguration(t *testing.T) {
	dir := t.TempDir()
	c := validConfig()
	a := c.Areas[0]
	c.Areas = nil
	c.AreaFiles = []string{"area.json"}
	write := func(name string, value any) {
		t.Helper()
		b, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	write("gateway.json", c)
	write("area.json", a)
	loaded, err := LoadConfig(filepath.Join(dir, "gateway.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Areas) != 1 || loaded.Areas[0].VNI != 7 {
		t.Fatal("Area file not loaded")
	}
	a.Routes[0].Pool = "missing"
	write("area.json", a)
	if _, err = LoadConfig(filepath.Join(dir, "gateway.json")); err == nil {
		t.Fatal("invalid referenced Area accepted")
	}
	if err = os.Remove(filepath.Join(dir, "area.json")); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadConfig(filepath.Join(dir, "gateway.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}
func TestReloadStagesWholeFileSetBeforePublication(t *testing.T) {
	c := validConfig()
	r := &recordingRunner{}
	e, err := NewEngine(c, r)
	if err != nil {
		t.Fatal(err)
	}
	next := validConfig()
	a := next.Areas[0]
	a.VNI = 8
	next.Areas = append(next.Areas, a)
	if err = e.Reload(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	if r.commands[len(r.commands)-1] != "egress-geneve commit" {
		t.Fatal("configuration did not publish once after staging")
	}
	count := 0
	for _, cmd := range r.commands {
		if cmd == "egress-policy commit" {
			count++
		}
		if strings.Contains(cmd, "session") || strings.Contains(cmd, "lease") {
			t.Fatal("sandbox lifecycle command", cmd)
		}
	}
	if count != 2 {
		t.Fatal("new Area not staged")
	}
	r.commands = nil
	r.fail = "egress-policy route"
	next.Areas[0].Pools[0].MaxConnections = 10
	if err = e.Reload(context.Background(), next); err == nil {
		t.Fatal("native preparation failure accepted")
	}
	for _, cmd := range r.commands {
		if cmd == "egress-geneve commit" {
			t.Fatal("published incomplete file set")
		}
	}
	if e.config.Areas[0].Pools[0].MaxConnections == 10 || e.Failure() != nil {
		t.Fatal("preparation failure lost last good configuration")
	}
}
func TestMalformedConfigurationNeverReachesNativeRuntime(t *testing.T) {
	r := &recordingRunner{}
	e, _ := NewEngine(validConfig(), r)
	c := validConfig()
	c.Areas[0].Routes[0].Pool = "missing"
	if err := e.Reload(context.Background(), c); err == nil {
		t.Fatal("invalid configuration accepted")
	}
	if len(r.commands) != 0 {
		t.Fatal("invalid config reached dataplane")
	}
}
func TestLostPublicationResponseCannotClaimRollback(t *testing.T) {
	r := &recordingRunner{lost: true}
	e, _ := NewEngine(validConfig(), r)
	if err := e.Reload(context.Background(), validConfig()); err == nil || e.Failure() == nil {
		t.Fatal("ambiguous commit was reported safe")
	}
}
func TestNamedPoolsAndSourcesReloadWithoutRestart(t *testing.T) {
	c := validConfig()
	r := &recordingRunner{}
	e, err := NewEngine(c, r)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Setup(context.Background()); err != nil {
		t.Fatal(err)
	}
	id := e.poolIDs[poolKey{7, "public"}]
	c.Areas[0].Pools[0].NextHop = "192.0.2.3"
	c.Areas[0].Pools[0].Addresses = []string{"192.0.2.9"}
	c.Attachments[0].Peer = []string{"198.18.0.0/24", "203.0.113.8"}
	c.Attachments[0].NextHop = "198.18.0.254"
	if err = e.Reload(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if e.poolIDs[poolKey{7, "public"}] != id {
		t.Fatal("Pool identity changed with its resource definition")
	}
	c.Areas[0].Pools = append([]Pool{{Name: "new", Interface: "outside", NextHop: "192.0.2.2", Addresses: []string{"192.0.2.10"}}}, c.Areas[0].Pools...)
	if err = e.Reload(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if e.poolIDs[poolKey{7, "public"}] != id {
		t.Fatal("Pool identity depends on array order")
	}
	c.Areas[0].Pools[1].Name = "renamed"
	c.Areas[0].Routes[0].Pool = "renamed"
	if err = e.Reload(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if e.poolIDs[poolKey{7, "renamed"}] == id {
		t.Fatal("rename aliased live mappings for removed name")
	}
	c.Interfaces[0].MTU++
	r.commands = nil
	if err = e.Reload(context.Background(), c); err == nil || len(r.commands) != 0 {
		t.Fatal("physical resource change did not require restart")
	}
}

func TestOptionalPeerRangesAndIngressAmbiguity(t *testing.T) {
	c := validConfig()
	c.Attachments[0].Peer = nil
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.Attachments[0].Peer = []string{"198.18.0.2", "203.0.113.0/24"}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.Attachments[0].Peer[0] != "198.18.0.2/32" {
		t.Fatal("IP source was not normalized")
	}
	copy := c.Attachments[0]
	copy.Name, copy.Peer = "overlap", []string{"203.0.113.1"}
	c.Attachments = append(c.Attachments, copy)
	if err := c.Validate(); err != nil {
		t.Fatal("compatible source overlap rejected", err)
	}
	c.Attachments[1].Locator = "vni"
	if err := c.Validate(); err == nil {
		t.Fatal("ambiguous decoder accepted")
	}
	c.Attachments[1].Peer = []string{"198.51.100.0/24"}
	if err := c.Validate(); err != nil {
		t.Fatal("disjoint source profiles rejected", err)
	}
}

func TestRepeatedGatewayAddressRequiresUnambiguousSources(t *testing.T) {
	c := validConfig()
	i := c.Interfaces[0]
	i.Name = "transit2"
	c.Interfaces = append(c.Interfaces, i)
	a := c.Attachments[0]
	a.Name, a.Interface, a.Peer = "second", "transit2", []string{"203.0.113.0/24"}
	c.Attachments = append(c.Attachments, a)
	if err := c.Validate(); err != nil {
		t.Fatal("disjoint peers at a repeated gateway IP rejected", err)
	}
	c.Attachments[1].Peer = nil
	if err := c.Validate(); err == nil {
		t.Fatal("same access identity accepted through ambiguous return devices")
	}
}

func TestSharedTransitAndPoolInterface(t *testing.T) {
	c := validConfig()
	c.Areas[0].Pools[0].Interface = "transit"
	c.Areas[0].Pools[0].NextHop = "198.18.0.254"
	c.Areas[0].Pools[0].Addresses = []string{"198.18.0.10"}
	if err := c.Validate(); err != nil {
		t.Fatal("unambiguous shared interface rejected", err)
	}
	c.Areas[0].Pools[0].Addresses = []string{"198.18.0.1"}
	if err := c.Validate(); err == nil {
		t.Fatal("Geneve and NAT return address overlap accepted")
	}
}

func TestRemovedPublicFieldsAreRejected(t *testing.T) {
	for _, member := range []string{`"max_contexts":1`, `"max_connections":1`, `"exits":[]`,
		`"attachments":[{"gateway":"10.7.0.1"}]`, `"attachments":[{"area":7}]`,
		`"attachments":[{"generation_bits":4}]`, `"attachments":[{"encapsulation":"ether"}]`,
		`"attachments":[{"port_base":50000}]`, `"areas":[{"pools":[{"id":0}]}]`} {
		var c Config
		if err := Decode(strings.NewReader("{"+member+"}"), &c); err == nil {
			t.Fatal("removed field accepted", member)
		}
	}
}

func TestAllExistingLocatorProfiles(t *testing.T) {
	for _, locator := range []string{"port", "vni", "tlv"} {
		c := validConfig()
		c.Attachments[0].Locator = locator
		if locator == "tlv" {
			c.Attachments[0].TLVClass, c.Attachments[0].TLVType = 258, 129
		}
		if err := c.Validate(); err != nil {
			t.Fatal(locator, err)
		}
	}
}
func TestNoGatewayListenerConfiguration(t *testing.T) {
	c := validConfig()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	s := startup(c)
	for _, forbidden := range []string{"cli-listen", "socksvr", "api.sock", "stats.sock", "control.sock"} {
		if strings.Contains(s, forbidden) {
			t.Fatal("API listener configured", forbidden)
		}
	}
	if !strings.Contains(s, "socket-name none") {
		t.Fatal("native statistics endpoint not disabled")
	}
}

// These values cross the removed object ceilings. A large locator or an
// arbitrary Pool name must not translate to an admission count or array size.
func TestConfigurationScalesByResourcesInsteadOfFixedObjectCounts(t *testing.T) {
	c := validConfig()
	for cpu := uint32(0); cpu < 65; cpu++ {
		c.Workers = append(c.Workers, cpu)
	}
	for i := 0; i < 1024; i++ {
		c.Areas[0].Pools = append(c.Areas[0].Pools, Pool{Name: fmt.Sprintf("pool%d", i), Interface: "outside", NextHop: "192.0.2.2", Addresses: []string{"192.0.2.1"}})
	}
	for i := 0; i < 4097; i++ {
		c.Areas[0].ACL = append(c.Areas[0].ACL, ACL{Match: Match{Destination: "198.51.100.0/24", Protocol: "tcp"}, Action: "deny"})
		c.Areas[0].DNAT = append(c.Areas[0].DNAT, DNAT{Match: Match{Destination: "203.0.113.0/24", Protocol: "tcp"}, Pool: "public", Target: "203.0.113.1"})
		c.Areas[0].Routes = append(c.Areas[0].Routes, Route{Destination: fmt.Sprintf("10.%d.%d.1/32", i/256, i%256), Pool: "public"})
	}
	for i := 1; i <= 257; i++ {
		address := fmt.Sprintf("198.51.%d.%d", i/256, i%256)
		c.Areas[0].Pools[0].Addresses = append(c.Areas[0].Pools[0].Addresses, address)
		c.Areas = append(c.Areas, Area{VNI: uint32(1000 + i)})
		attachment := c.Attachments[0]
		attachment.Name = fmt.Sprintf("peer%d", i)
		attachment.Peer = []string{address}
		c.Attachments = append(c.Attachments, attachment)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}
