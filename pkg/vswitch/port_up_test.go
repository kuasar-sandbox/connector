package vswitch

import (
	"bytes"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kuasar-sandbox/connector/pkg/internal/bpf"
)

func deferredPortFixture(t *testing.T) (*switchContext, *MmappedSlots) {
	t.Helper()
	t.Cleanup(resetDeps)
	s, slots := newGeneveAttachTestContext(&SwitchConfig{GenerationBits: 4, Features: SwitchFDeferredUp}, true)
	writeGeneveOptsFn = func(BPFMap, uint32, *GeneveOptsValue) error { return nil }
	out, err := s.Attach(AttachOptions{Port: 1, InnerIP: net.ParseIP("10.0.0.1"), Generation: 3, AdminDown: true, SkipDevice: true})
	if err != nil {
		t.Fatal(err)
	}
	if !out.AdminDown || out.Port != 1 || slots.GetSlot(0).Flags != 0 {
		t.Fatal("deferred attachment not allocated/down", out)
	}
	return s, slots
}

func TestDeferredAttachAndSetPortUp(t *testing.T) {
	for _, final := range []string{"10.0.0.1", "10.0.0.2"} {
		t.Run(final, func(t *testing.T) {
			s, slots := deferredPortFixture(t)
			before := *slots.GetSlot(0)
			beforeFloating := FloatingIPForAttachment(s.cfg.FloatingIpBase, 0, before.Generation)
			acquireControlLockFn = func(string) (*ControlLock, error) { t.Fatal("SetPortUp took control lock"); return nil, nil }
			syscallFlock = func(int, int) error { t.Fatal("SetPortUp used flock"); return nil }
			var written GeneveOptsValue
			writeGeneveOptsFn = func(_ BPFMap, id uint32, v *GeneveOptsValue) error {
				if id != 0 || slots.GetSlot(id).Flags != 0 || slots.GetInnerIP(id) != before.InnerIp {
					t.Fatal("published before map write")
				}
				written = *v
				return nil
			}
			opts := PortUpOptions{Port: 1, InnerIP: net.ParseIP(final), TransitGatewayIP: net.ParseIP("192.0.2.1"), TransitGeneveVNI: 42,
				TransitMAC: net.HardwareAddr{2, 0, 0, 0, 0, 9}, TransitGeneveOpts: []GeneveOption{{Class: 1, Type: 2, Data: []byte{1, 2, 3, 4}}}}
			if err := s.SetPortUp(opts); err != nil {
				t.Fatal(err)
			}
			got := slots.GetSlot(0)
			if slots.GetInnerIP(0) != bpf.IPToUint32(opts.InnerIP) || got.Flags != PortFUp || got.TransitGatewayIp != bpf.IPToUint32(opts.TransitGatewayIP) || got.TransitGeneveVni != 42 || !bytes.Equal(got.TransitMac[:], opts.TransitMAC) || got.GeneveOptsLen != written.Len || written.Len == 0 {
				t.Fatalf("final configuration: %+v", got)
			}
			if got.Generation != before.Generation || got.StatsReady != before.StatsReady || got.Ifindex != before.Ifindex || FloatingIPForAttachment(s.cfg.FloatingIpBase, 0, got.Generation) != beforeFloating {
				t.Fatal("attachment identity/readiness changed")
			}
			snapshot := *got
			if err := s.SetPortUp(opts); err == nil || !strings.Contains(err.Error(), "already up") {
				t.Fatal("up port accepted", err)
			}
			if *got != snapshot {
				t.Fatal("rejected up request changed slot")
			}
			if err := s.Detach(DetachOptions{Port: 1, SkipDevice: true}); err != nil {
				t.Fatal(err)
			}
			if slots.GetInnerIP(0) != InnerIPFree || got.Flags != 0 {
				t.Fatal("updated address not released")
			}
		})
	}
}

func TestSetPortUpClearsProvisionalTransit(t *testing.T) {
	s, slots := deferredPortFixture(t)
	slot := slots.GetSlot(0)
	slot.TransitGatewayIp = 123
	slot.TransitGeneveVni = 99
	slot.TransitMac = [6]byte{2, 1, 2, 3, 4, 5}
	slot.GeneveOptsLen = 8
	writeGeneveOptsFn = func(_ BPFMap, _ uint32, v *GeneveOptsValue) error {
		if *v != (GeneveOptsValue{}) {
			t.Fatal("empty options did not overwrite map", v)
		}
		return nil
	}
	if err := s.SetPortUp(PortUpOptions{Port: 1, InnerIP: net.ParseIP("10.0.0.2")}); err != nil {
		t.Fatal(err)
	}
	if slot.TransitGatewayIp != 0 || slot.TransitGeneveVni != 0 || slot.TransitMac != ([6]byte{}) || slot.GeneveOptsLen != 0 {
		t.Fatal("provisional fields retained", slot)
	}
}

func TestSetPortUpFailureRemainsDownAndRetryable(t *testing.T) {
	for _, stage := range []string{"mtu", "map"} {
		t.Run(stage, func(t *testing.T) {
			s, slots := deferredPortFixture(t)
			before := *slots.GetSlot(0)
			injected := errors.New("injected " + stage + " failure")
			validateAttachMTUFn = func(*switchContext, uint32, PortKind, int) error {
				if stage == "mtu" {
					return injected
				}
				return nil
			}
			writeGeneveOptsFn = func(BPFMap, uint32, *GeneveOptsValue) error {
				if stage == "map" {
					return injected
				}
				t.Fatal("map after MTU failure")
				return nil
			}
			opts := PortUpOptions{Port: 1, InnerIP: net.ParseIP("10.0.0.2"), TransitGeneveOpts: []GeneveOption{{Class: 1, Type: 2}}}
			if err := s.SetPortUp(opts); !errors.Is(err, injected) {
				t.Fatal("failure not returned", err)
			}
			if *slots.GetSlot(0) != before {
				t.Fatal("failed validation/map write mutated slot")
			}
			validateAttachMTUFn = func(*switchContext, uint32, PortKind, int) error { return nil }
			writeGeneveOptsFn = func(BPFMap, uint32, *GeneveOptsValue) error { return nil }
			if err := s.SetPortUp(opts); err != nil {
				t.Fatal("retry", err)
			}
		})
	}
}

func TestSetPortUpRejectsInvalidInputsBeforeMutation(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*PortUpOptions, *switchContext)
	}{
		{"zero port", func(o *PortUpOptions, _ *switchContext) { o.Port = 0 }},
		{"negative port", func(o *PortUpOptions, _ *switchContext) { o.Port = -1 }},
		{"large port", func(o *PortUpOptions, _ *switchContext) { o.Port = int(uint64(1)<<32) + 1 }},
		{"nil IP", func(o *PortUpOptions, _ *switchContext) { o.InnerIP = nil }},
		{"free sentinel", func(o *PortUpOptions, _ *switchContext) { o.InnerIP = net.IPv4zero }},
		{"reserved sentinel", func(o *PortUpOptions, _ *switchContext) { o.InnerIP = net.IPv4bcast }},
		{"IPv6", func(o *PortUpOptions, _ *switchContext) { o.InnerIP = net.ParseIP("2001:db8::1") }},
		{"IPv6 gateway", func(o *PortUpOptions, _ *switchContext) { o.TransitGatewayIP = net.ParseIP("2001:db8::1") }},
		{"short MAC", func(o *PortUpOptions, _ *switchContext) { o.TransitMAC = net.HardwareAddr{1, 2} }},
		{"EUI64", func(o *PortUpOptions, _ *switchContext) { o.TransitMAC = make(net.HardwareAddr, 8) }},
		{"VNI overflow", func(o *PortUpOptions, _ *switchContext) { o.TransitGeneveVNI = 1 << 24 }},
		{"bad options", func(o *PortUpOptions, _ *switchContext) {
			o.TransitGeneveOpts = []GeneveOption{{Class: 1, Data: []byte{1}}}
		}},
		{"old ABI", func(_ *PortUpOptions, s *switchContext) { s.cfg.Features = 0 }},
		{"old publication reader", func(_ *PortUpOptions, s *switchContext) { s.cfg.Features = SwitchFPortUp }},
		{"missing map", func(_ *PortUpOptions, s *switchContext) { s.maps.GeneveOpts = nil }},
		{"Free", func(_ *PortUpOptions, s *switchContext) { s.mmapSlots.TryRelease(0, s.mmapSlots.GetInnerIP(0)) }},
		{"Reserved", func(_ *PortUpOptions, s *switchContext) { s.mmapSlots.TryReserve(0, s.mmapSlots.GetInnerIP(0)) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, slots := deferredPortFixture(t)
			opts := PortUpOptions{Port: 1, InnerIP: net.ParseIP("10.0.0.2")}
			c.mutate(&opts, s)
			before := *slots.GetSlot(0)
			writeGeneveOptsFn = func(BPFMap, uint32, *GeneveOptsValue) error { t.Fatal("map write on rejection"); return nil }
			validateAttachMTUFn = func(*switchContext, uint32, PortKind, int) error { t.Fatal("MTU lookup on rejection"); return nil }
			if err := s.SetPortUp(opts); err == nil {
				t.Fatal("accepted invalid request")
			}
			if *slots.GetSlot(0) != before {
				t.Fatal("invalid input changed slot")
			}
		})
	}
}

func TestSetPortUpRespectsObservedManagementTakeover(t *testing.T) {
	for _, stage := range []string{"mtu", "map"} {
		t.Run(stage, func(t *testing.T) {
			s, slots := deferredPortFixture(t)
			takeover := func() {
				if !slots.TryReserve(0, slots.GetInnerIP(0)) {
					t.Fatal("takeover failed")
				}
			}
			validateAttachMTUFn = func(*switchContext, uint32, PortKind, int) error {
				if stage == "mtu" {
					takeover()
				}
				return nil
			}
			writeGeneveOptsFn = func(BPFMap, uint32, *GeneveOptsValue) error {
				if stage == "map" {
					takeover()
				} else {
					t.Fatal("continued after observed takeover")
				}
				return nil
			}
			if err := s.SetPortUp(PortUpOptions{Port: 1, InnerIP: net.ParseIP("10.0.0.2"), TransitGeneveOpts: []GeneveOption{{Class: 1, Type: 2}}}); err == nil {
				t.Fatal("takeover ignored")
			}
			if slots.GetInnerIP(0) != InnerIPReserved || slots.GetSlot(0).Flags != 0 {
				t.Fatal("management state undone")
			}
		})
	}
}

func TestDeferredAttachDetachAndDefaultReuse(t *testing.T) {
	s, slots := deferredPortFixture(t)
	if err := s.Detach(DetachOptions{Port: 1, SkipDevice: true}); err != nil {
		t.Fatal(err)
	}
	out, err := s.Attach(AttachOptions{Port: 1, InnerIP: net.ParseIP("10.0.0.2"), SkipDevice: true})
	if err != nil || out.AdminDown || atomic.LoadUint32(&slots.GetSlot(0).Flags) != PortFUp {
		t.Fatal("default Attach inherited down", out, err)
	}
}

func TestAttachRejectsControlSentinelAndBadNetwork(t *testing.T) {
	for _, kind := range []string{"reserved", "gateway", "mac"} {
		t.Run(kind, func(t *testing.T) {
			defer resetDeps()
			s, slots := newGeneveAttachTestContext(&SwitchConfig{}, true)
			o := AttachOptions{InnerIP: net.ParseIP("10.0.0.1"), AdminDown: true, SkipDevice: true}
			switch kind {
			case "reserved":
				o.InnerIP = net.IPv4bcast
			case "gateway":
				o.TransitGatewayIP = net.ParseIP("::1")
			case "mac":
				o.TransitMAC = make(net.HardwareAddr, 8)
			}
			before := *slots.GetSlot(0)
			if _, err := s.Attach(o); err == nil {
				t.Fatal("invalid provisional configuration accepted")
			}
			if *slots.GetSlot(0) != before {
				t.Fatal("claim before input validation")
			}
		})
	}
}

func TestDeferredAttachRejectsOldReaderBeforeClaim(t *testing.T) {
	defer resetDeps()
	s, slots := newGeneveAttachTestContext(&SwitchConfig{}, true)
	writeGeneveOptsFn = func(BPFMap, uint32, *GeneveOptsValue) error { t.Fatal("old reader reached map write"); return nil }
	if _, err := s.Attach(AttachOptions{InnerIP: net.ParseIP("10.0.0.1"), AdminDown: true, SkipDevice: true}); err == nil || !strings.Contains(err.Error(), "rebuild") {
		t.Fatal("old reader accepted", err)
	}
	if slots.GetInnerIP(0) != InnerIPFree {
		t.Fatal("old reader claimed slot")
	}
}
