package vswitch

import (
	"net"
	"testing"

	"github.com/cilium/ebpf"
)

func TestParseMgmtService(t *testing.T) {
	svc, err := ParseMgmtService("169.254.169.254:80:127.0.0.1:19254")
	if err != nil {
		t.Fatalf("ParseMgmtService: %v", err)
	}
	if !svc.VIP.Equal(net.ParseIP("169.254.169.254")) {
		t.Errorf("VIP: got %v", svc.VIP)
	}
	if svc.VPort != 80 {
		t.Errorf("VPort: got %d, want 80", svc.VPort)
	}
	if !svc.TargetIP.Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("TargetIP: got %v", svc.TargetIP)
	}
	if svc.TargetPort != 19254 {
		t.Errorf("TargetPort: got %d, want 19254", svc.TargetPort)
	}
	if got := svc.String(); got != "169.254.169.254:80:127.0.0.1:19254" {
		t.Errorf("String: got %q", got)
	}
}

func TestParseMgmtServiceInvalid(t *testing.T) {
	cases := []string{
		"",
		"169.254.169.254:80:127.0.0.1",         // too few fields
		"169.254.169.254:80:127.0.0.1:1:2",     // too many fields
		"notanip:80:127.0.0.1:19254",           // bad VIP
		"169.254.169.254:0:127.0.0.1:19254",    // vport 0
		"169.254.169.254:80:127.0.0.1:70000",   // tport > 65535
		"169.254.169.254:http:127.0.0.1:19254", // non-numeric port
		"::1:80:127.0.0.1:19254",               // IPv6 VIP not allowed
		"169.254.169.254:80:fe80::1:19254",     // IPv6 target not allowed
	}
	for _, c := range cases {
		if _, err := ParseMgmtService(c); err == nil {
			t.Errorf("ParseMgmtService(%q): expected error, got nil", c)
		}
	}
}

// baseConfigWithExtract returns a minimal valid Config with one mgmt-extract
// covering 169.254.169.0/24.
func baseConfigWithExtract(t *testing.T) *Config {
	t.Helper()
	me, err := ParseMgmtExtract(":mgmt0:169.254.169.0/24")
	if err != nil {
		t.Fatalf("ParseMgmtExtract: %v", err)
	}
	return &Config{
		Name:           "sw0",
		SwitchNetNS:    "sw_ns",
		PortNetNS:      "port_ns",
		NumPorts:       16,
		MACAddr:        net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		FloatingIPBase: net.ParseIP("100.100.96.0"),
		MgmtExtracts:   []*MgmtExtract{me},
	}
}

func TestValidateMgmtServicesInRange(t *testing.T) {
	cfg := baseConfigWithExtract(t)
	svc, _ := ParseMgmtService("169.254.169.254:80:127.0.0.1:19254")
	cfg.MgmtServices = []*MgmtService{svc}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidateMgmtServicesOutOfRange(t *testing.T) {
	cfg := baseConfigWithExtract(t)
	// VIP 10.0.0.1 is outside the 169.254.169.0/24 extract route.
	svc, _ := ParseMgmtService("10.0.0.1:80:127.0.0.1:19254")
	cfg.MgmtServices = []*MgmtService{svc}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate: expected out-of-range error, got nil")
	}
}

func TestValidateMgmtServicesDuplicateTarget(t *testing.T) {
	cfg := baseConfigWithExtract(t)
	a, _ := ParseMgmtService("169.254.169.254:80:127.0.0.1:19254")
	b, _ := ParseMgmtService("169.254.169.253:81:127.0.0.1:19254") // same target
	cfg.MgmtServices = []*MgmtService{a, b}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate: expected duplicate-target error, got nil")
	}
}

func TestValidateMgmtServicesRequiresExtract(t *testing.T) {
	cfg := baseConfigWithExtract(t)
	cfg.MgmtExtracts = nil // no extract
	svc, _ := ParseMgmtService("169.254.169.254:80:127.0.0.1:19254")
	cfg.MgmtServices = []*MgmtService{svc}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate: expected requires-extract error, got nil")
	}
}

// svcRecorder is a BPFMap that records svc map writes by key.
type svcRecorder struct {
	entries map[SvcKey]SvcVal
}

func newSvcRecorder() *svcRecorder { return &svcRecorder{entries: map[SvcKey]SvcVal{}} }

func (m *svcRecorder) Lookup(key, valueOut any) error { return nil }
func (m *svcRecorder) Delete(key any) error           { return nil }
func (m *svcRecorder) Update(key, value any, flags ebpf.MapUpdateFlags) error {
	k := key.(*SvcKey)
	v := value.(*SvcVal)
	m.entries[*k] = *v
	return nil
}

func TestWriteMgmtServices(t *testing.T) {
	svc, _ := ParseMgmtService("169.254.169.254:80:127.0.0.1:19254")
	fwd := newSvcRecorder()
	rev := newSvcRecorder()
	if err := WriteMgmtServices(fwd, rev, []*MgmtService{svc}); err != nil {
		t.Fatalf("WriteMgmtServices: %v", err)
	}

	// One service -> 2 entries each (TCP + UDP) in fwd and rev.
	if len(fwd.entries) != 2 {
		t.Errorf("fwd entries: got %d, want 2", len(fwd.entries))
	}
	if len(rev.entries) != 2 {
		t.Errorf("rev entries: got %d, want 2", len(rev.entries))
	}

	vip := IPToUint32(net.ParseIP("169.254.169.254"))
	target := IPToUint32(net.ParseIP("127.0.0.1"))

	// fwd: {VIP,80,tcp} -> {target,19254}
	fk := SvcKey{Ip: vip, Port: 80, Proto: 6}
	fv, ok := fwd.entries[fk]
	if !ok {
		t.Fatalf("fwd missing TCP entry for VIP:80")
	}
	if fv.Ip != target || fv.Port != 19254 {
		t.Errorf("fwd val: got ip=%#x port=%d", fv.Ip, fv.Port)
	}

	// rev: {target,19254,udp} -> {VIP,80}
	rk := SvcKey{Ip: target, Port: 19254, Proto: 17}
	rv, ok := rev.entries[rk]
	if !ok {
		t.Fatalf("rev missing UDP entry for target:19254")
	}
	if rv.Ip != vip || rv.Port != 80 {
		t.Errorf("rev val: got ip=%#x port=%d", rv.Ip, rv.Port)
	}
}
