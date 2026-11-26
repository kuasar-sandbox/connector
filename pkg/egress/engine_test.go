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
		Exits:       []Exit{{Name: "public", Interface: "outside", NextHop: "192.0.2.2", Addresses: []string{"192.0.2.1"}}},
		Attachments: []Attachment{{Name: "local", Interface: "transit", Peer: "198.18.0.2", Area: 7, Locator: "port", PortBase: 50000, Encapsulation: "ether", GenerationBits: 4, Gateway: "10.7.0.1"}},
		Areas:       []Area{{VNI: 7, Pools: []Pool{{ID: 0, Exit: "public", Addresses: []string{"192.0.2.1"}, MaxConnections: 2}}, ACL: []ACL{{Match: Match{Destination: "203.0.113.0/24", Protocol: "any"}, Action: "allow"}}, Routes: []Route{{Destination: "0.0.0.0/0", Pool: 0}}}},
	}
}

func TestConfigurationRejectsAmbiguousOrUnsafeRouting(t *testing.T) {
	for name, change := range map[string]func(*Config){
		"command injection in address":      func(c *Config) { c.Areas[0].Routes[0].Destination = "0.0.0.0/0\negress-policy commit" },
		"unknown Pool":                      func(c *Config) { c.Areas[0].Routes[0].Pool = 5 },
		"noncanonical prefix":               func(c *Config) { c.Areas[0].Routes[0].Destination = "203.0.113.1/24" },
		"unknown exit resource":             func(c *Config) { c.Areas[0].Pools[0].Addresses = []string{"192.0.2.9"} },
		"ambiguous same-prefix routes":      func(c *Config) { c.Areas[0].Routes = append(c.Areas[0].Routes, c.Areas[0].Routes[0]) },
		"wire VNI used as logical Area":     func(c *Config) { c.Attachments[0].Locator = "vni"; c.Attachments[0].Area = 8199; c.Areas[0].VNI = 8199 },
		"IP domain overlap":                 func(c *Config) { c.Attachments[0].Interface = "outside"; c.Attachments[0].Peer = "192.0.2.2" },
		"port value exceeds its wire field": func(c *Config) { c.Attachments[0].PortBase = 65536 },
		"reserved protocol":                 func(c *Config) { c.Areas[0].ACL[0].Protocol = "gre" },
		"port match on arbitrary protocol":  func(c *Config) { c.Areas[0].ACL[0].PortFirst = 1; c.Areas[0].ACL[0].PortLast = 10 },
		"duplicate SNAT resource":           func(c *Config) { c.Exits[0].Addresses = append(c.Exits[0].Addresses, c.Exits[0].Addresses[0]) },
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
	if loaded.MaxContexts < 10000 {
		t.Fatal("default gateway budget excludes 10k")
	}
	a.Routes[0].Pool = 63
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
	c.Areas[0].Routes[0].Pool = 63
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
func TestSharedExitInterfaceUsesOneReturnFIB(t *testing.T) {
	c := validConfig()
	c.Exits = append(c.Exits, Exit{Name: "other", Interface: "outside", NextHop: "192.0.2.3", Addresses: []string{"192.0.2.1"}})
	c.Areas[0].Pools = append(c.Areas[0].Pools, Pool{ID: 1, Exit: "other", Addresses: []string{"192.0.2.1"}})
	r := &recordingRunner{}
	e, err := NewEngine(c, r)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Setup(context.Background()); err != nil {
		t.Fatal(err)
	}
	text := strings.Join(r.commands, "\n")
	if strings.Count(text, "set interface nat44 out host-outside") != 1 || strings.Count(text, "nat44 add address 192.0.2.1") != 1 {
		t.Fatal("shared resources configured twice")
	}
	for _, want := range []string{"pool id 0 table 3 return-table 2", "pool id 1 table 4 return-table 2"} {
		if !strings.Contains(text, want) {
			t.Fatal(want, text)
		}
	}
}
func TestAllExistingLocatorProfiles(t *testing.T) {
	for _, locator := range []string{"port", "vni", "tlv"} {
		for _, encap := range []string{"ether", "ip"} {
			c := validConfig()
			c.Attachments[0].Locator = locator
			c.Attachments[0].Encapsulation = encap
			c.Attachments[0].TLVClass = 258
			c.Attachments[0].TLVType = 129
			if err := c.Validate(); err != nil {
				t.Fatal(locator, encap, err)
			}
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

// These values cross the removed policy/object ceilings. Sparse public Pool
// IDs must not cause arrays to be allocated up to the largest numeric ID.
func TestConfigurationScalesByResourcesInsteadOfFixedObjectCounts(t *testing.T) {
	c := validConfig()
	c.MaxConnections = 2 * 1048576
	for cpu := uint32(0); cpu < 65; cpu++ {
		c.Workers = append(c.Workers, cpu)
	}
	for i := 0; i < 1024; i++ {
		c.Exits = append(c.Exits, Exit{Name: fmt.Sprintf("exit%d", i), Interface: "outside", NextHop: "192.0.2.2", Addresses: []string{"192.0.2.1"}})
	}
	for id := uint32(1); id <= 65; id++ {
		c.Areas[0].Pools = append(c.Areas[0].Pools, Pool{ID: id * 65537, Exit: "public", Addresses: []string{"192.0.2.1"}})
	}
	c.Areas[0].Pools = append(c.Areas[0].Pools, Pool{ID: ^uint32(0), Exit: "public", Addresses: []string{"192.0.2.1"}})
	for i := 0; i < 4097; i++ {
		c.Areas[0].ACL = append(c.Areas[0].ACL, ACL{Match: Match{Destination: "198.51.100.0/24", Protocol: "tcp"}, Action: "deny"})
		c.Areas[0].DNAT = append(c.Areas[0].DNAT, DNAT{Match: Match{Destination: "203.0.113.0/24", Protocol: "tcp"}, Pool: ^uint32(0), Target: "203.0.113.1"})
		c.Areas[0].Routes = append(c.Areas[0].Routes, Route{Destination: fmt.Sprintf("10.%d.%d.1/32", i/256, i%256), Pool: ^uint32(0)})
	}
	for i := 1; i <= 257; i++ {
		address := fmt.Sprintf("198.51.%d.%d", i/256, i%256)
		c.Exits[0].Addresses = append(c.Exits[0].Addresses, address)
		c.Areas[0].Pools[0].Addresses = append(c.Areas[0].Pools[0].Addresses, address)
		c.Interfaces = append(c.Interfaces, Interface{Name: fmt.Sprintf("transit%d", i), Address: "198.18.0.1/24", MTU: 1500})
		area := Area{VNI: uint32(1000 + i)}
		c.Areas = append(c.Areas, area)
		attachment := c.Attachments[0]
		attachment.Name = fmt.Sprintf("peer%d", i)
		attachment.Area = area.VNI
		c.Attachments = append(c.Attachments, attachment)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	e, err := NewEngine(c, &recordingRunner{})
	if err != nil {
		t.Fatal(err)
	}
	used := map[int]bool{}
	for _, iface := range c.Interfaces {
		used[e.interfaceTable(iface.Name)] = true
	}
	for i := range c.Exits {
		table := len(c.Interfaces) + 1 + i
		if used[table] {
			t.Fatal("interface and exit FIB IDs collide", table)
		}
		used[table] = true
	}
}
