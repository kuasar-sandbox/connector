package egress

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestOriginalYAMLAreaContract(t *testing.T) {
	dir := t.TempDir()
	main := `# Main file remains independent of Area policy.
name: test
vpp: /opt/egress/bin/vpp
plugin_path: /opt/egress/plugins
interfaces:
  - {name: transit, address: 198.18.0.1/24, mtu: 1500}
  - {name: outside, address: 192.0.2.1/24, mtu: 1500}
attachments:
  - {name: local, interface: transit}
area_files: [area.yaml]
`
	area := `vni: 7
pools:
  - name: public
    interface: outside
    next_hop: 192.0.2.2
    addresses: [192.0.2.4/31, "192.0.2.5-192.0.2.6"]
acl:
  - destination: [203.0.113.0/24, 198.18.1.1]
    protocol: [tcp, udp]
    ports: [53, "8000-8002"]
    action: allow
  - action: deny
dnat:
  - destination: [198.18.1.1]
    protocol: [tcp, udp]
    ports: [53]
    pool: public
    target: 203.0.113.11
# routes is deliberately absent: the only Pool is the default exit.
`
	if err := os.WriteFile(filepath.Join(dir, "gateway.yaml"), []byte(main), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "area.yaml"), []byte(area), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(filepath.Join(dir, "gateway.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	a := c.Areas[0]
	if !reflect.DeepEqual(a.Pools[0].Addresses, StringSet{"192.0.2.4", "192.0.2.5", "192.0.2.6"}) {
		t.Fatal(a.Pools)
	}
	if len(a.ACL) != 9 || a.ACL[8].Action != "deny" || a.ACL[8].Destination != "0.0.0.0/0" || a.ACL[8].Protocol != "any" {
		t.Fatal(a.ACL)
	}
	if len(a.DNAT) != 2 || len(a.Routes) != 1 || a.Routes[0].Pool != "public" || a.Routes[0].Destination != "0.0.0.0/0" {
		t.Fatal(a)
	}
	raw, _ := json.Marshal(c)
	var decoded Config
	if err := Decode(strings.NewReader(string(raw)), &decoded); err != nil {
		t.Fatal(err)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*c, decoded) {
		t.Fatal("normalization is not idempotent or formats differ")
	}
	runner := &recordingRunner{}
	engine, err := NewEngine(*c, runner)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Reload(context.Background(), *c); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(runner.commands, "\n")
	if !strings.Contains(joined, "egress-policy route dst 0.0.0.0/0 pool 0") || !strings.Contains(joined, "egress-policy acl dst 0.0.0.0/0 proto 0 ports 0 0 deny") {
		t.Fatal(joined)
	}
}

func TestOmittedAndEmptyRoutesRemainDistinct(t *testing.T) {
	for _, tc := range []struct {
		name   string
		pools  int
		routes []Route
		want   int
		reject bool
	}{
		{"single omitted", 1, nil, 1, false}, {"single explicit empty", 1, []Route{}, 0, false},
		{"multiple omitted", 2, nil, 0, true}, {"multiple explicit empty", 2, []Route{}, 0, false},
		{"zero Pools", 0, nil, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			c.Areas[0].Routes = tc.routes
			if tc.pools == 0 {
				c.Areas[0].Pools = nil
			} else if tc.pools == 2 {
				p := c.Areas[0].Pools[0]
				p.Name = "second"
				c.Areas[0].Pools = append(c.Areas[0].Pools, p)
			}
			err := c.Validate()
			if (err != nil) != tc.reject {
				t.Fatalf("%v", err)
			}
			if !tc.reject && len(c.Areas[0].Routes) != tc.want {
				t.Fatal(c.Areas[0].Routes)
			}
		})
	}
}

func TestSourceCollectionsAndAmbiguities(t *testing.T) {
	for _, input := range []string{
		"name: test\nName: other\n", "name: test\nunknown: 1\n", "name: test\n---\nname: second\n",
		"areas: [{vni: 7, routes: null}]", "areas: [{vni: 7, routes: [] , routes: []}]",
		"name: test\ninterfaces: [*unknown]\n", "name: &loop [*loop]",
	} {
		var c Config
		if err := Decode(strings.NewReader(input), &c); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
	for _, input := range []string{
		`{"destination":[],"action":"allow"}`, `{"cidrs":["10.0.0.0/8"],"action":"allow"}`,
		`{"protocol":[],"action":"allow"}`, `{"protocol":"icmp","ports":53,"action":"allow"}`,
		`{"ports":"100-80","action":"allow"}`, `{"ports":65536,"action":"allow"}`,
		`{"port_first":80,"port_last":80,"action":"allow"}`, `{"protocols":["udp"],"action":"allow"}`,
	} {
		var area Area
		if err := Decode(strings.NewReader(`{"vni":7,"acl":[`+input+`]}`), &area); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
	c := validConfig()
	c.Areas[0].Pools[0].Addresses = []string{"192.0.2.4/31", "192.0.2.5", "192.0.2.5"}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(c.Areas[0].Pools[0].Addresses) != 2 {
		t.Fatal(c.Areas[0].Pools)
	}
}

func TestUnifiedRangesAndRouteSpecificity(t *testing.T) {
	input := `{"vni":7,"pools":[{"name":"public","interface":"outside","next_hop":"192.0.2.2","addresses":"192.0.2.4-192.0.2.7"}],"acl":[{"destination":["10.0.0.4-10.0.0.7","10.0.0.4/30"],"protocol":"udp","ports":[80,"80-82",83],"action":"deny"}],"routes":[{"destination":["10.0.0.0/24","10.0.1.0/24","10.0.0.0/24"],"pool":"public"}]}`
	c := validConfig()
	if err := Decode(strings.NewReader(input), &c.Areas[0]); err != nil {
		t.Fatal(err)
	}
	c.Attachments[0].Peer = StringSet{"198.18.0.2-198.18.0.254", "198.18.0.4/30"}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	a := c.Areas[0]
	if len(a.Pools[0].Addresses) != 4 || len(a.ACL) != 1 || a.ACL[0].Destination != "10.0.0.4/30" || a.ACL[0].PortFirst != 80 || a.ACL[0].PortLast != 83 {
		t.Fatal(a)
	}
	if len(a.Routes) != 2 || a.Routes[0].Destination != "10.0.0.0/24" || a.Routes[1].Destination != "10.0.1.0/24" {
		t.Fatal("route LPM priority changed", a.Routes)
	}
	if len(c.Attachments[0].Peer) > 16 {
		t.Fatal("source range was enumerated", c.Attachments[0].Peer)
	}
	for _, bad := range []string{"192.0.2.8-192.0.2.4", "192.0.2.1-2001:db8::1", "192.0.2.3/24"} {
		if _, err := parseAddressRange(bad); err == nil {
			t.Fatal(bad)
		}
	}
}
