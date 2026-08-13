package vswitch

import (
	"bytes"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	vnetlink "github.com/vishvananda/netlink"

	"github.com/kuasar-sandbox/connector/pkg/internal/bpf"
	connectornetlink "github.com/kuasar-sandbox/connector/pkg/netlink"
	"github.com/kuasar-sandbox/connector/pkg/netns"
)

func newGeneveAttachTestContext(cfg *SwitchConfig, withOptionsMap bool) (*switchContext, *MmappedSlots) {
	if cfg.N_ports == 0 {
		cfg.N_ports = 2
	}
	if cfg.GenevePortBase == 0 {
		cfg.GenevePortBase = uint32(DefaultGenevePortBase)
	}
	slots := newMmappedSlotsForTest(cfg.N_ports)
	maps := &bpf.Maps{}
	if withOptionsMap {
		maps.GeneveOpts = &ebpf.Map{}
		acquireControlLockFn = func(string) (*ControlLock, error) { return &ControlLock{}, nil }
		verifyCurrentSwitchFn = func(*switchContext) error { return nil }
	}
	return &switchContext{
		name:      "sw0",
		maps:      maps,
		cfg:       cfg,
		meta:      &SwitchMetadata{},
		mmapSlots: slots,
		statsMgr:  NewStatsManager(&mockBPFMapWithSlot{}, cfg.N_ports),
	}, slots
}

func TestAttachLegacySwitchWithoutGeneveOptsMap(t *testing.T) {
	defer resetDeps()
	s, slots := newGeneveAttachTestContext(&SwitchConfig{}, false)
	if _, err := s.Attach(AttachOptions{InnerIP: net.ParseIP("10.0.0.1"), SkipDevice: true}); err != nil {
		t.Fatalf("legacy empty attach: %v", err)
	}
	if slots.GetSlot(0).GeneveOptsLen != 0 {
		t.Fatalf("legacy hint = %d", slots.GetSlot(0).GeneveOptsLen)
	}

	if err := s.Detach(DetachOptions{Port: 1, SkipDevice: true}); err != nil {
		t.Fatal(err)
	}
	_, err := s.Attach(AttachOptions{
		InnerIP:           net.ParseIP("10.0.0.2"),
		SkipDevice:        true,
		TransitGeneveOpts: []GeneveOption{{Class: 1, Type: 2}},
	})
	if err == nil || !strings.Contains(err.Error(), "rebuild the switch") {
		t.Fatalf("legacy non-empty options error = %v", err)
	}
	if slots.GetInnerIP(0) != 0 {
		t.Fatal("non-empty options validation allocated a legacy slot")
	}
}

func TestAttachFixedLocatorRequiresGeneveOptsMap(t *testing.T) {
	for _, locator := range []GeneveLocator{GeneveLocatorVNI, GeneveLocatorTLV} {
		t.Run(locator.String(), func(t *testing.T) {
			cfg := &SwitchConfig{GeneveLocator: uint8(locator)}
			s, slots := newGeneveAttachTestContext(cfg, false)
			_, err := s.Attach(AttachOptions{InnerIP: net.ParseIP("10.0.0.1"), SkipDevice: true})
			if err == nil || !strings.Contains(err.Error(), "rebuild the switch") {
				t.Fatalf("error = %v", err)
			}
			if slots.GetInnerIP(0) != 0 {
				t.Fatal("capability validation happened after CAS")
			}
		})
	}
}

func TestAttachGeneveOptionsMapFailureRollsBack(t *testing.T) {
	defer resetDeps()
	s, slots := newGeneveAttachTestContext(&SwitchConfig{}, true)
	writeGeneveOptsFn = func(BPFMap, uint32, *GeneveOptsValue) error {
		return errors.New("injected update failure")
	}
	_, err := s.Attach(AttachOptions{
		InnerIP:           net.ParseIP("10.0.0.1"),
		SkipDevice:        true,
		TransitGeneveOpts: []GeneveOption{{Class: 1, Type: 2}},
	})
	if err == nil || !strings.Contains(err.Error(), "injected update failure") {
		t.Fatalf("error = %v", err)
	}
	if slots.GetInnerIP(0) != 0 || slots.GetSlot(0).GeneveOptsLen != 0 {
		t.Fatalf("rollback state: inner=%#x hint=%d", slots.GetInnerIP(0), slots.GetSlot(0).GeneveOptsLen)
	}
}

func TestAttachGeneveControlLockFailureBeforeCAS(t *testing.T) {
	defer resetDeps()
	s, slots := newGeneveAttachTestContext(&SwitchConfig{}, true)
	acquireControlLockFn = func(string) (*ControlLock, error) {
		return nil, errors.New("injected lock failure")
	}
	_, err := s.Attach(AttachOptions{InnerIP: net.ParseIP("10.0.0.1"), SkipDevice: true})
	if err == nil || !strings.Contains(err.Error(), "injected lock failure") {
		t.Fatalf("error = %v", err)
	}
	if slots.GetInnerIP(0) != InnerIPFree {
		t.Fatalf("lock failure allocated slot: inner=%#x", slots.GetInnerIP(0))
	}
}

func TestAttachGeneveSwitchVerificationFailureBeforeCAS(t *testing.T) {
	defer resetDeps()
	s, slots := newGeneveAttachTestContext(&SwitchConfig{}, true)
	verifyCurrentSwitchFn = func(*switchContext) error {
		return errors.New("injected stale switch")
	}

	_, err := s.Attach(AttachOptions{InnerIP: net.ParseIP("10.0.0.1"), SkipDevice: true})
	if err == nil || !strings.Contains(err.Error(), "injected stale switch") {
		t.Fatalf("error = %v", err)
	}
	if slots.GetInnerIP(0) != InnerIPFree {
		t.Fatalf("switch verification failure allocated slot: inner=%#x", slots.GetInnerIP(0))
	}
}

func TestAttachRollbackDoesNotClearConcurrentOwnerHint(t *testing.T) {
	defer resetDeps()
	s, slots := newGeneveAttachTestContext(&SwitchConfig{}, true)
	firstIP := bpf.IPToUint32(net.ParseIP("10.0.0.1"))
	secondIP := bpf.IPToUint32(net.ParseIP("10.0.0.2"))
	writeGeneveOptsFn = func(BPFMap, uint32, *GeneveOptsValue) error {
		if !slots.TryRelease(0, firstIP) || !slots.TryAllocate(0, secondIP) {
			t.Fatal("simulate concurrent slot reattach")
		}
		slots.GetSlot(0).GeneveOptsLen = 12
		return errors.New("injected stale attach failure")
	}

	_, err := s.Attach(AttachOptions{
		InnerIP:           net.ParseIP("10.0.0.1"),
		SkipDevice:        true,
		TransitGeneveOpts: []GeneveOption{{Class: 1, Type: 2}},
	})
	if err == nil || !strings.Contains(err.Error(), "injected stale attach failure") {
		t.Fatalf("error = %v", err)
	}
	if got := slots.GetInnerIP(0); got != secondIP {
		t.Fatalf("concurrent owner inner IP = %#x, want %#x", got, secondIP)
	}
	if got := slots.GetSlot(0).GeneveOptsLen; got != 12 {
		t.Fatalf("concurrent owner's GENEVE options hint = %d, want 12", got)
	}
}

func TestAttachEmptyOptionsOverwritesOldMapValue(t *testing.T) {
	defer resetDeps()
	s, slots := newGeneveAttachTestContext(&SwitchConfig{}, true)
	slots.GetSlot(0).GeneveOptsLen = 12
	var written GeneveOptsValue
	writeGeneveOptsFn = func(_ BPFMap, slotID uint32, value *GeneveOptsValue) error {
		if slotID != 0 {
			t.Fatalf("slotID = %d", slotID)
		}
		written = *value
		return nil
	}
	if _, err := s.Attach(AttachOptions{InnerIP: net.ParseIP("10.0.0.1"), SkipDevice: true}); err != nil {
		t.Fatal(err)
	}
	if written.Len != 0 || written.Critical != 0 || written.Data != [64]uint8{} {
		t.Fatalf("empty overwrite = %#v", written)
	}
	if slots.GetSlot(0).GeneveOptsLen != 0 {
		t.Fatalf("empty attach hint = %d", slots.GetSlot(0).GeneveOptsLen)
	}
}

func TestAttachSlotReuseDoesNotInheritOptions(t *testing.T) {
	defer resetDeps()
	s, slots := newGeneveAttachTestContext(&SwitchConfig{}, true)
	var writes []GeneveOptsValue
	writeGeneveOptsFn = func(_ BPFMap, _ uint32, value *GeneveOptsValue) error {
		writes = append(writes, *value)
		return nil
	}
	first := AttachOptions{
		InnerIP:           net.ParseIP("10.0.0.1"),
		SkipDevice:        true,
		TransitGeneveOpts: []GeneveOption{{Class: 0x0102, Type: 2, Data: []byte{0, 0, 0, 1}}},
	}
	if _, err := s.Attach(first); err != nil {
		t.Fatal(err)
	}
	if slots.GetSlot(0).GeneveOptsLen != 8 {
		t.Fatalf("first hint = %d", slots.GetSlot(0).GeneveOptsLen)
	}
	if err := s.Detach(DetachOptions{Port: 1, SkipDevice: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Attach(AttachOptions{InnerIP: net.ParseIP("10.0.0.2"), SkipDevice: true}); err != nil {
		t.Fatal(err)
	}
	if len(writes) != 2 || writes[0].Len != 8 || writes[1].Len != 0 || writes[1].Data != [64]uint8{} {
		t.Fatalf("map writes = %#v", writes)
	}
	if slots.GetSlot(0).GeneveOptsLen != 0 {
		t.Fatalf("second hint = %d", slots.GetSlot(0).GeneveOptsLen)
	}
}

func TestAttachMTUFailureRollsBackWithHintZero(t *testing.T) {
	defer resetDeps()
	s, slots := newGeneveAttachTestContext(&SwitchConfig{}, true)
	writeGeneveOptsFn = func(BPFMap, uint32, *GeneveOptsValue) error { return nil }
	validateAttachMTUFn = func(*switchContext, uint32, PortKind, int) error {
		return errors.New("MTU too small")
	}
	_, err := s.Attach(AttachOptions{
		InnerIP:           net.ParseIP("10.0.0.1"),
		SkipDevice:        true,
		TransitGeneveOpts: []GeneveOption{{Class: 1, Type: 2}},
	})
	if err == nil || !strings.Contains(err.Error(), "MTU too small") {
		t.Fatalf("error = %v", err)
	}
	if slots.GetInnerIP(0) != 0 || slots.GetSlot(0).GeneveOptsLen != 0 {
		t.Fatalf("rollback state: inner=%#x hint=%d", slots.GetInnerIP(0), slots.GetSlot(0).GeneveOptsLen)
	}
}

func TestAttachOverwritesTransitBeforeMTUValidation(t *testing.T) {
	defer resetDeps()
	s, slots := newGeneveAttachTestContext(&SwitchConfig{}, true)
	slot := slots.GetSlot(0)
	slot.TransitGatewayIp = 0xc0000201
	slot.TransitGeneveVni = 0x00ffffff
	slot.SetTransitMacAddr(net.HardwareAddr{0, 1, 2, 3, 4, 5})
	slot.GeneveOptsLen = 12

	innerIP := net.ParseIP("10.0.0.1")
	wantInnerIP := bpf.IPToUint32(innerIP)
	wantGateway := bpf.IPToUint32(net.ParseIP("192.0.2.2"))
	wantMAC := net.HardwareAddr{6, 7, 8, 9, 10, 11}
	assertInitialized := func(stage string) {
		if got := slots.GetInnerIP(0); got != wantInnerIP || got == InnerIPReserved {
			t.Fatalf("inner IP during %s = %#x, want allocated %#x", stage, got, wantInnerIP)
		}
		got := slots.GetSlot(0)
		if got.GeneveOptsLen != 0 {
			t.Fatalf("options hint during %s = %d, want 0", stage, got.GeneveOptsLen)
		}
		if got.TransitGatewayIp != wantGateway || got.TransitGeneveVni != 0x123 {
			t.Fatalf("transit fields during %s = gateway %#x VNI %#x", stage, got.TransitGatewayIp, got.TransitGeneveVni)
		}
		if mac := net.HardwareAddr(got.TransitMac[:]); !bytes.Equal(mac, wantMAC) {
			t.Fatalf("transit MAC during %s = %s, want %s", stage, mac, wantMAC)
		}
	}
	writeGeneveOptsFn = func(BPFMap, uint32, *GeneveOptsValue) error {
		assertInitialized("options map update")
		return nil
	}
	validateAttachMTUFn = func(*switchContext, uint32, PortKind, int) error {
		assertInitialized("MTU validation")
		return errors.New("MTU too small")
	}

	_, err := s.Attach(AttachOptions{
		InnerIP:           innerIP,
		TransitGatewayIP:  net.ParseIP("192.0.2.2"),
		TransitGeneveVNI:  0x123,
		TransitMAC:        wantMAC,
		SkipDevice:        true,
		TransitGeneveOpts: []GeneveOption{{Class: 1, Type: 2}},
	})
	if err == nil || !strings.Contains(err.Error(), "MTU too small") {
		t.Fatalf("error = %v", err)
	}
	if slots.GetInnerIP(0) != InnerIPFree || slots.GetSlot(0).GeneveOptsLen != 0 {
		t.Fatalf("rollback state: inner=%#x hint=%d", slots.GetInnerIP(0), slots.GetSlot(0).GeneveOptsLen)
	}
}

func TestAttachDeviceMoveFailureRollsBackWithoutReserved(t *testing.T) {
	defer resetDeps()
	s, slots := newGeneveAttachTestContext(&SwitchConfig{}, true)
	s.meta.PortNetNS = "port-ns"
	writeGeneveOptsFn = func(BPFMap, uint32, *GeneveOptsValue) error { return nil }
	validateAttachMTUFn = func(*switchContext, uint32, PortKind, int) error { return nil }
	netnsGetByName = func(string) (*netns.NetNS, error) { return &netns.NetNS{}, nil }
	wantInnerIP := bpf.IPToUint32(net.ParseIP("10.0.0.1"))
	netnsMoveDevice = func(string, *netns.NetNS, *netns.NetNS) error {
		if got := slots.GetInnerIP(0); got != wantInnerIP || got == InnerIPReserved {
			t.Fatalf("inner IP during device move = %#x, want allocated %#x", got, wantInnerIP)
		}
		if got := slots.GetSlot(0).GeneveOptsLen; got != 0 {
			t.Fatalf("options hint during device move = %d, want 0", got)
		}
		return errors.New("injected move failure")
	}

	_, err := s.Attach(AttachOptions{
		InnerIP:           net.ParseIP("10.0.0.1"),
		ToNetNS:           "sandbox-ns",
		TransitGeneveOpts: []GeneveOption{{Class: 1, Type: 2}},
	})
	if err == nil || !strings.Contains(err.Error(), "injected move failure") {
		t.Fatalf("error = %v", err)
	}
	if slots.GetInnerIP(0) != InnerIPFree || slots.GetSlot(0).GeneveOptsLen != 0 {
		t.Fatalf("rollback state: inner=%#x hint=%d", slots.GetInnerIP(0), slots.GetSlot(0).GeneveOptsLen)
	}
}

func TestValidateAttachMTUErrorDetails(t *testing.T) {
	defer resetDeps()
	s, _ := newGeneveAttachTestContext(&SwitchConfig{GeneveEncapEth: 1}, true)
	s.meta = &SwitchMetadata{SwitchNetNS: "sw-ns", TransitDev: "transit0"}
	netnsGetByName = func(name string) (*netns.NetNS, error) {
		if name != "sw-ns" {
			t.Fatalf("netns name = %q", name)
		}
		return &netns.NetNS{}, nil
	}
	netlinkGetMTUInNs = func(_ connectornetlink.NetNS, name string) (int, error) {
		switch name {
		case "sw0-n1":
			return 1500, nil
		case "transit0":
			return 1570, nil
		default:
			t.Fatalf("MTU lookup for %q", name)
			return 0, nil
		}
	}

	err := validateAttachMTU(s, 0, PortKindVeth, 12)
	if err == nil {
		t.Fatal("expected MTU error")
	}
	for _, fragment := range []string{
		"transit0 MTU 1570", "port sw0-n1", "port MTU 1500",
		"base GENEVE overhead 64", "options overhead 12", "required MTU 1576",
	} {
		if !strings.Contains(err.Error(), fragment) {
			t.Errorf("error %q missing %q", err, fragment)
		}
	}
}

func TestAttachLocatorOutputs(t *testing.T) {
	defer resetDeps()
	validateAttachMTUFn = func(*switchContext, uint32, PortKind, int) error { return nil }
	for _, tt := range []struct {
		name       string
		locator    GeneveLocator
		tlvClass   uint16
		tlvType    uint8
		wantPort   uint16
		wantVNI    uint32
		wantOptLen uint8
	}{
		{name: "port", locator: GeneveLocatorPort, wantPort: 50000, wantVNI: 0x123, wantOptLen: 0},
		{name: "vni", locator: GeneveLocatorVNI, wantPort: GeneveStandardPort, wantVNI: 0x123, wantOptLen: 0},
		{name: "tlv", locator: GeneveLocatorTLV, tlvClass: 0x0102, tlvType: 0x81, wantPort: GeneveStandardPort, wantVNI: 0x123, wantOptLen: 8},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &SwitchConfig{
				GeneveLocator:  uint8(tt.locator),
				GeneveTlvClass: tt.tlvClass,
				GeneveTlvType:  tt.tlvType,
			}
			s, _ := newGeneveAttachTestContext(cfg, true)
			s.meta.TransitDev = "eth0"
			writeGeneveOptsFn = func(BPFMap, uint32, *GeneveOptsValue) error { return nil }
			out, err := s.Attach(AttachOptions{
				InnerIP:          net.ParseIP("10.0.0.1"),
				TransitGatewayIP: net.ParseIP("192.0.2.1"),
				TransitGeneveVNI: 0x123,
				SkipDevice:       true,
			})
			if err != nil {
				t.Fatal(err)
			}
			if out.GeneveLocator != tt.locator.String() || out.GenevePort != tt.wantPort ||
				out.WireGeneveVNI != tt.wantVNI || out.GeneveOptsLen != tt.wantOptLen {
				t.Fatalf("output = %#v", out)
			}
		})
	}
}

func TestAttachTLVLocatorChecksActualMTU(t *testing.T) {
	defer resetDeps()
	s, slots := newGeneveAttachTestContext(&SwitchConfig{
		GeneveLocator:  uint8(GeneveLocatorTLV),
		GeneveTlvClass: 0x0102,
		GeneveTlvType:  0x81,
	}, true)
	writeGeneveOptsFn = func(BPFMap, uint32, *GeneveOptsValue) error { return nil }
	var gotOverhead int
	validateAttachMTUFn = func(_ *switchContext, _ uint32, _ PortKind, overhead int) error {
		gotOverhead = overhead
		return errors.New("fixed locator MTU too small")
	}

	_, err := s.Attach(AttachOptions{InnerIP: net.ParseIP("10.0.0.1"), SkipDevice: true})
	if err == nil || !strings.Contains(err.Error(), "fixed locator MTU too small") {
		t.Fatalf("error = %v", err)
	}
	if gotOverhead != geneveTLVLocatorWireLen {
		t.Fatalf("TLV options overhead = %d", gotOverhead)
	}
	if slots.GetInnerIP(0) != InnerIPFree || slots.GetSlot(0).GeneveOptsLen != 0 {
		t.Fatalf("rollback state: inner=%#x hint=%d", slots.GetInnerIP(0), slots.GetSlot(0).GeneveOptsLen)
	}
}

func TestAttachVNIValidationBeforeCAS(t *testing.T) {
	defer resetDeps()
	s, slots := newGeneveAttachTestContext(&SwitchConfig{GeneveLocator: uint8(GeneveLocatorVNI)}, true)
	_, err := s.Attach(AttachOptions{InnerIP: net.ParseIP("10.0.0.1"), TransitGeneveVNI: 0x1000, SkipDevice: true})
	if err == nil {
		t.Fatal("expected VNI range error")
	}
	if slots.GetInnerIP(0) != 0 {
		t.Fatal("VNI validation happened after CAS")
	}
}

func TestDetachReleasesDirectlyAndClearsHint(t *testing.T) {
	defer resetDeps()
	s, slots := newGeneveAttachTestContext(&SwitchConfig{}, true)
	innerIP := bpf.IPToUint32(net.ParseIP("10.0.0.1"))
	if !slots.TryAllocate(0, innerIP) {
		t.Fatal("allocate slot")
	}
	slots.GetSlot(0).GeneveOptsLen = 12

	if err := s.Detach(DetachOptions{Port: 1, SkipDevice: true}); err != nil {
		t.Fatal(err)
	}
	if slots.GetInnerIP(0) != InnerIPFree || slots.GetSlot(0).GeneveOptsLen != 0 {
		t.Fatalf("detach state: inner=%#x hint=%d", slots.GetInnerIP(0), slots.GetSlot(0).GeneveOptsLen)
	}
}

func TestDetachGeneveControlLockFailurePreservesAttachment(t *testing.T) {
	defer resetDeps()
	s, slots := newGeneveAttachTestContext(&SwitchConfig{}, true)
	innerIP := bpf.IPToUint32(net.ParseIP("10.0.0.1"))
	if !slots.TryAllocate(0, innerIP) {
		t.Fatal("allocate slot")
	}
	slots.GetSlot(0).GeneveOptsLen = 12
	acquireControlLockFn = func(string) (*ControlLock, error) {
		return nil, errors.New("injected lock failure")
	}

	err := s.Detach(DetachOptions{Port: 1, SkipDevice: true})
	if err == nil || !strings.Contains(err.Error(), "injected lock failure") {
		t.Fatalf("error = %v", err)
	}
	if slots.GetInnerIP(0) != innerIP || slots.GetSlot(0).GeneveOptsLen != 12 {
		t.Fatalf("lock failure changed attachment: inner=%#x hint=%d", slots.GetInnerIP(0), slots.GetSlot(0).GeneveOptsLen)
	}
}

func TestDetachGeneveSwitchVerificationFailurePreservesAttachment(t *testing.T) {
	defer resetDeps()
	s, slots := newGeneveAttachTestContext(&SwitchConfig{}, true)
	innerIP := bpf.IPToUint32(net.ParseIP("10.0.0.1"))
	if !slots.TryAllocate(0, innerIP) {
		t.Fatal("allocate slot")
	}
	slots.GetSlot(0).GeneveOptsLen = 12
	verifyCurrentSwitchFn = func(*switchContext) error {
		return errors.New("injected stale switch")
	}

	err := s.Detach(DetachOptions{Port: 1, SkipDevice: true})
	if err == nil || !strings.Contains(err.Error(), "injected stale switch") {
		t.Fatalf("error = %v", err)
	}
	if slots.GetInnerIP(0) != innerIP || slots.GetSlot(0).GeneveOptsLen != 12 {
		t.Fatalf("switch verification failure changed attachment: inner=%#x hint=%d", slots.GetInnerIP(0), slots.GetSlot(0).GeneveOptsLen)
	}
}

func TestReserveGeneveControlLockFailurePreservesFreeSlot(t *testing.T) {
	defer resetDeps()
	s, slots := newGeneveAttachTestContext(&SwitchConfig{}, true)
	acquireControlLockFn = func(string) (*ControlLock, error) {
		return nil, errors.New("injected lock failure")
	}

	_, err := s.Reserve(ReserveOptions{Port: 1})
	if err == nil || !strings.Contains(err.Error(), "injected lock failure") {
		t.Fatalf("error = %v", err)
	}
	if slots.GetInnerIP(0) != InnerIPFree {
		t.Fatalf("lock failure reserved slot: inner=%#x", slots.GetInnerIP(0))
	}
}

func TestReserveGeneveSwitchVerificationFailurePreservesFreeSlot(t *testing.T) {
	defer resetDeps()
	s, slots := newGeneveAttachTestContext(&SwitchConfig{}, true)
	verifyCurrentSwitchFn = func(*switchContext) error {
		return errors.New("injected stale switch")
	}

	_, err := s.Reserve(ReserveOptions{Port: 1, Force: true})
	if err == nil || !strings.Contains(err.Error(), "injected stale switch") {
		t.Fatalf("error = %v", err)
	}
	if slots.GetInnerIP(0) != InnerIPFree {
		t.Fatalf("switch verification failure reserved slot: inner=%#x", slots.GetInnerIP(0))
	}
}

func TestDetachDoesNotUndoConcurrentForceReserve(t *testing.T) {
	defer resetDeps()
	s, slots := newGeneveAttachTestContext(&SwitchConfig{}, true)
	s.meta.PortNetNS = "port-ns"
	innerIP := bpf.IPToUint32(net.ParseIP("10.0.0.1"))
	if !slots.TryAllocate(0, innerIP) {
		t.Fatal("allocate slot")
	}
	slots.GetSlot(0).GeneveOptsLen = 12

	// Simulate force-reserve winning after Detach reads currentIP but before its
	// release CAS. The second load in Detach must observe and preserve Reserved.
	netnsGetByName = func(string) (*netns.NetNS, error) { return &netns.NetNS{}, nil }
	netnsGetLinkInNs = func(*netns.NetNS, string) (vnetlink.Link, error) {
		if !slots.TryReserve(0, innerIP) {
			t.Fatal("simulate concurrent force-reserve")
		}
		return &vnetlink.Dummy{}, nil
	}

	if err := s.Detach(DetachOptions{Port: 1}); err != nil {
		t.Fatal(err)
	}
	if slots.GetInnerIP(0) != InnerIPReserved || slots.GetSlot(0).GeneveOptsLen != 12 {
		t.Fatalf("detach/reserve state: inner=%#x hint=%d", slots.GetInnerIP(0), slots.GetSlot(0).GeneveOptsLen)
	}
}
