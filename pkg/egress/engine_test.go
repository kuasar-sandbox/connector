package egress

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func validConfig() Config {
	return Config{Name: "test", RuntimeDir: "/run/connector-egress/test", VPP: "/opt/egress/bin/vpp", VPPCTL: "/opt/egress/bin/vppctl", PluginPath: "/opt/egress/plugins",
		Interfaces:  []Interface{{Name: "transit", Address: "198.18.0.1/24", MTU: 1500}, {Name: "outside", Address: "192.0.2.1/24", MTU: 1500}},
		Exits:       []Exit{{Name: "public", Interface: "outside", NextHop: "192.0.2.2", Addresses: []string{"192.0.2.1"}}},
		Attachments: []Attachment{{Name: "local", Interface: "transit", Peer: "198.18.0.2", Area: 7, Locator: "port", PortBase: 50000, Encapsulation: "ether", GenerationBits: 4, Gateway: "10.7.0.1"}},
		Areas:       []Area{{VNI: 7, Pools: []Pool{{ID: 0, Exit: "public", Addresses: []string{"192.0.2.1"}, MaxConnections: 2}}, ACL: []ACL{{Match: Match{Destination: "203.0.113.0/24", Protocol: "any"}, Action: "allow"}}, Routes: []Route{{Destination: "0.0.0.0/0", Pool: 0}}}},
	}
}

type recordingRunner struct {
	commands []string
	reply    func(string) (string, error)
}

func (r *recordingRunner) Run(_ context.Context, c string) (string, error) {
	r.commands = append(r.commands, c)
	if r.reply != nil {
		return r.reply(c)
	}
	return "", nil
}
func TestConfigurationRejectsAmbiguousOrUnsafeRouting(t *testing.T) {
	for name, change := range map[string]func(*Config){
		"command injection in address":       func(c *Config) { c.Areas[0].Routes[0].Destination = "0.0.0.0/0\negress-policy commit" },
		"unknown Pool":                       func(c *Config) { c.Areas[0].Routes[0].Pool = 5 },
		"noncanonical prefix":                func(c *Config) { c.Areas[0].Routes[0].Destination = "203.0.113.1/24" },
		"unknown exit resource":              func(c *Config) { c.Areas[0].Pools[0].Addresses = []string{"192.0.2.9"} },
		"ambiguous same-prefix routes":       func(c *Config) { c.Areas[0].Routes = append(c.Areas[0].Routes, c.Areas[0].Routes[0]) },
		"wire VNI used as logical Area":      func(c *Config) { c.Attachments[0].Locator = "vni"; c.Attachments[0].Area = 8199; c.Areas[0].VNI = 8199 },
		"IP domain overlap":                  func(c *Config) { c.Attachments[0].Interface = "outside"; c.Attachments[0].Peer = "192.0.2.2" },
		"port locator overlaps standard UDP": func(c *Config) { c.Attachments[0].PortBase = 6000 },
		"reserved protocol":                  func(c *Config) { c.Areas[0].ACL[0].Protocol = "gre" },
		"port match on arbitrary protocol":   func(c *Config) { c.Areas[0].ACL[0].PortFirst = 1; c.Areas[0].ACL[0].PortLast = 10 },
		"duplicate SNAT resource":            func(c *Config) { c.Exits[0].Addresses = append(c.Exits[0].Addresses, c.Exits[0].Addresses[0]) },
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
func TestAllExistingLocatorProfiles(t *testing.T) {
	for _, mode := range []string{"port", "vni", "tlv"} {
		for _, encap := range []string{"ip", "ether"} {
			t.Run(mode+"/"+encap, func(t *testing.T) {
				c := validConfig()
				c.Attachments[0].Locator = mode
				c.Attachments[0].Encapsulation = encap
				c.Attachments[0].TLVClass = 65535
				c.Attachments[0].TLVType = 0x81
				if err := c.Validate(); err != nil {
					t.Fatal(err)
				}
				s := SessionRequest{ID: "sandbox", Attachment: "local", Slot: 4095, InnerIP: "10.7.0.2", ReturnMAC: "02:00:00:00:80:01", LeaseSeconds: 300}
				if err := c.ValidateSession(s); err != nil {
					t.Fatal(err)
				}
				if encap == "ether" {
					s.Generation = 15
					if err := c.ValidateSession(s); err != nil {
						t.Fatal(err)
					}
					s.Generation = 16
				} else {
					s.Generation = 1
				}
				if err := c.ValidateSession(s); err == nil {
					t.Fatal("unrepresentable generation accepted")
				}
			})
		}
	}
}
func TestInvalidAreaNeverReachesDataplane(t *testing.T) {
	r := &recordingRunner{}
	c := validConfig()
	engine, err := NewEngine(c, r)
	if err != nil {
		t.Fatal(err)
	}
	a := c.Areas[0]
	a.Routes = append(a.Routes, Route{Destination: "10.0.0.0/8", Pool: 63})
	if err = engine.ApplyArea(context.Background(), a); err == nil {
		t.Fatal("unknown pool accepted")
	}
	if len(r.commands) != 0 {
		t.Fatalf("changed native policy: %v", r.commands)
	}
}
func TestStagingFailureAbortsWithoutPublishing(t *testing.T) {
	r := &recordingRunner{reply: func(s string) (string, error) {
		if strings.HasPrefix(s, "egress-policy route ") {
			return "invalid route", nil
		}
		return "", nil
	}}
	c := validConfig()
	engine, _ := NewEngine(c, r)
	if err := engine.ApplyArea(context.Background(), c.Areas[0]); err == nil {
		t.Fatal("native rejection accepted")
	}
	for _, s := range r.commands {
		if s == "egress-policy commit" {
			t.Fatal("published incomplete policy")
		}
	}
	if r.commands[len(r.commands)-1] != "egress-policy abort" {
		t.Fatal("transaction not aborted")
	}
	if engine.Failure() != nil {
		t.Fatal("staging rejection unnecessarily poisoned committed policy")
	}
}
func TestUnknownCommitOutcomeStopsFurtherMutations(t *testing.T) {
	r := &recordingRunner{reply: func(s string) (string, error) {
		if s == "egress-policy commit" {
			return "", context.DeadlineExceeded
		}
		return "", nil
	}}
	c := validConfig()
	engine, _ := NewEngine(c, r)
	if err := engine.ApplyArea(context.Background(), c.Areas[0]); err == nil {
		t.Fatal("lost commit response accepted")
	}
	count := len(r.commands)
	if err := engine.ApplyArea(context.Background(), c.Areas[0]); err == nil || len(r.commands) != count {
		t.Fatal("mutated policy after ambiguous commit")
	}
	if engine.Failure() == nil {
		t.Fatal("supervisor cannot observe fatal ambiguity")
	}
}
func TestSessionTokensAndLostGrantRollback(t *testing.T) {
	c := validConfig()
	r := &recordingRunner{reply: func(s string) (string, error) {
		if s == "show egress-geneve" {
			return "", nil
		}
		if strings.HasPrefix(s, "egress-geneve session") {
			return "", errors.New("lost grant response")
		}
		if strings.HasPrefix(s, "egress-geneve retire") {
			return `{"table":10000,"retired":true}`, nil
		}
		return "", fmt.Errorf("unexpected command %q", s)
	}}
	engine, _ := NewEngine(c, r)
	request := SessionRequest{ID: "sandbox", Attachment: "local", Slot: 0, Generation: 1, InnerIP: "10.7.0.2", ReturnMAC: "02:00:00:00:80:01", LeaseSeconds: 10}
	if _, err := engine.Open(context.Background(), request); err == nil {
		t.Fatal("lost grant accepted")
	}
	if r.commands[len(r.commands)-1] != "egress-geneve retire table 10000" {
		t.Fatal("ambiguous grant not revoked")
	}
	if engine.Failure() == nil {
		t.Fatal("ambiguous asynchronous grant must stop dataplane even after best-effort retirement")
	}
	engine.failed = nil
	engine.sessions["sandbox"] = Session{SessionRequest: request, Token: "new-token", Table: 10000}
	count := len(r.commands)
	if _, err := engine.Renew(context.Background(), "sandbox", "old-token", 5); err == nil {
		t.Fatal("stale token renewed new owner")
	}
	if err := engine.Close(context.Background(), "sandbox", "old-token"); err == nil {
		t.Fatal("stale token revoked new owner")
	}
	if len(r.commands) != count {
		t.Fatal("stale token reached native runtime")
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

func TestRoutedOverlappingPeersAndNativeSNATOwnership(t *testing.T) {
	c := validConfig()
	c.Interfaces = append(c.Interfaces, Interface{Name: "remote", Address: "198.18.0.1/24", MTU: 9000})
	a := c.Attachments[0]
	a.Name, a.Interface, a.Peer, a.NextHop = "remote", "remote", "198.18.1.2", "198.18.0.2"
	c.Attachments[0].Peer, c.Attachments[0].NextHop = a.Peer, a.NextHop
	c.Attachments = append(c.Attachments, a)
	c.Exits[0].Addresses = append(c.Exits[0].Addresses, "192.0.2.3")
	r := &recordingRunner{reply: func(command string) (string, error) {
		if strings.HasPrefix(command, "create host-interface") {
			return "host-" + strings.Fields(command)[4], nil
		}
		if command == "egress-policy commit" {
			return `{"area":7,"terminated":0}`, nil
		}
		return "", nil
	}}
	e, err := NewEngine(c, r)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Setup(context.Background()); err != nil {
		t.Fatal(err)
	}
	commands := strings.Join(r.commands, "\n")
	for _, expected := range []string{
		"ip route add table 1000 198.18.1.2/32 via 198.18.0.2 host-transit",
		"ip route add table 1002 198.18.1.2/32 via 198.18.0.2 host-remote",
		"nat44 add address 192.0.2.3",
	} {
		if !strings.Contains(commands, expected) {
			t.Errorf("missing %s", expected)
		}
	}
	if strings.Contains(commands, "set interface ip address host-outside 192.0.2.3") {
		t.Fatal("SNAT resource was incorrectly installed as an overlapping interface alias")
	}
	c.Attachments[1].NextHop = ""
	if err := c.Validate(); err == nil {
		t.Fatal("routed peer without an on-link next hop accepted")
	}
}

func TestReturnMTUHonorsBothGuestAndUnderlay(t *testing.T) {
	for _, tc := range []struct {
		locator, encap    string
		path, guest, want uint32
	}{
		{"port", "ether", 9000, 0, 1550}, {"vni", "ip", 9000, 1400, 1436},
		{"tlv", "ether", 9000, 1400, 1458}, {"tlv", "ether", 1500, 1500, 1500},
	} {
		t.Run(fmt.Sprintf("%s-%s-%d", tc.locator, tc.encap, tc.path), func(t *testing.T) {
			c := validConfig()
			c.Interfaces[0].MTU = 9000
			a := &c.Attachments[0]
			a.Locator, a.Encapsulation, a.MTU, a.InnerMTU = tc.locator, tc.encap, tc.path, tc.guest
			r := &recordingRunner{reply: func(command string) (string, error) {
				if strings.HasPrefix(command, "egress-geneve session ") {
					return `{"table":10000,"interface":5,"lease":30}`, nil
				}
				return "", nil
			}}
			e, err := NewEngine(c, r)
			if err != nil {
				t.Fatal(err)
			}
			_, err = e.Open(context.Background(), SessionRequest{ID: "sandbox", Attachment: "local", InnerIP: "10.7.0.2", ReturnMAC: "02:00:00:00:80:01", LeaseSeconds: 30})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(r.commands[len(r.commands)-1], fmt.Sprintf(" mtu %d ", tc.want)) {
				t.Fatal(r.commands)
			}
		})
	}
}

func TestAmbiguousLifecycleAcknowledgementFailsClosed(t *testing.T) {
	for _, operation := range []string{"renew", "close"} {
		for _, response := range []string{`{"table":`, `{}`, `{"table":10001,"retiring":true}`} {
			t.Run(operation+response, func(t *testing.T) {
				r := &recordingRunner{reply: func(string) (string, error) { return response, nil }}
				e, _ := NewEngine(validConfig(), r)
				e.sessions["sandbox"] = Session{Token: "token", Table: 10000}
				var err error
				if operation == "renew" {
					_, err = e.Renew(context.Background(), "sandbox", "token", 30)
				} else {
					err = e.Close(context.Background(), "sandbox", "token")
				}
				if err == nil || e.Failure() == nil {
					t.Fatal("ambiguous lifecycle result left dataplane enabled")
				}
			})
		}
	}
}

func TestRegistrationRetryKeepsIdentityAfterRenewal(t *testing.T) {
	live := false
	grants, renewals := 0, 0
	runner := &recordingRunner{reply: func(command string) (string, error) {
		switch {
		case command == "show egress-geneve":
			if live {
				return `{"table":10000,"remaining":30}`, nil
			}
			return "", nil
		case strings.HasPrefix(command, "egress-geneve session "):
			grants++
			live = true
			return `{"table":10000,"interface":5,"lease":60}`, nil
		case command == "egress-geneve renew table 10000 lease 30":
			renewals++
			return `{"table":10000,"retiring":false}`, nil
		default:
			return "", fmt.Errorf("unexpected command %q", command)
		}
	}}
	engine, err := NewEngine(validConfig(), runner)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	engine.now = func() time.Time { return now }
	request := SessionRequest{ID: "sandbox", Attachment: "local", Slot: 0, Generation: 1, InnerIP: "10.7.0.2", ReturnMAC: "02:00:00:00:80:01", LeaseSeconds: 60}
	original, err := engine.Open(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(10 * time.Second)
	renewed, err := engine.Renew(context.Background(), request.ID, original.Token, 30)
	if err != nil {
		t.Fatal(err)
	}
	if !renewed.ExpiresAt.Equal(now.Add(30 * time.Second)) {
		t.Fatal("renewal did not update expiry")
	}
	retry, err := engine.Open(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if retry != renewed || retry.SessionRequest != request || retry.Token != original.Token || retry.Table != original.Table {
		t.Fatal("registration retry changed the live grant")
	}
	changed := request
	changed.LeaseSeconds = 30
	if _, err := engine.Open(context.Background(), changed); err == nil {
		t.Fatal("a changed registration replaced the original identity")
	}
	if grants != 1 || renewals != 1 {
		t.Fatal("registration retry created or renewed a native grant")
	}
}
