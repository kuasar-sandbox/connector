package vswitch

import (
	"errors"
	"fmt"
	"testing"

	"github.com/kuasar-sandbox/sandbox-vswitch/pkg/internal/bpf"
	"github.com/kuasar-sandbox/sandbox-vswitch/pkg/netlink"
	"github.com/kuasar-sandbox/sandbox-vswitch/pkg/netns"
)

// --- ProvisionPorts tests ---

// newProvisionTestSwitch creates a switchContext with test mmap slots for ProvisionPorts tests.
// slotStates defines the InnerIP value for each slot (use InnerIPReserved, InnerIPFree, or an IP).
func newProvisionTestSwitch(name string, slotStates []uint32) *switchContext {
	numSlots := uint32(len(slotStates))
	m := newMmappedSlotsForTest(numSlots)
	for i, state := range slotStates {
		if state != InnerIPFree {
			slot := m.GetSlot(uint32(i))
			slot.InnerIp = state
		}
	}
	cfg := &SwitchConfig{N_ports: numSlots}
	meta := &SwitchMetadata{
		SwitchNetNS: "test_switch_ns",
		PortNetNS:   "test_port_ns",
	}
	return &switchContext{
		name:      name,
		maps:      &bpf.Maps{},
		cfg:       cfg,
		meta:      meta,
		mmapSlots: m,
	}
}

// mockProvisionDeps sets up all deps needed by ProvisionPorts and returns a cleanup function.
// vethErr and tcErr control whether netlinkCreateVethPairs or netlinkAddClsactWithBlock fail.
func mockProvisionDeps(sw *switchContext, vethErr, tcErr error) {
	mockStartControlDeps()
	openSwitchFn = func(switchName string) (Interface, error) {
		return sw, nil
	}
	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	netnsDoFn = func(ns *netns.NetNS, f func() error) error {
		return f()
	}
	netlinkCreateVethPairs = func(specs []netlink.VethSpec) error {
		return vethErr
	}
	netlinkAddClsactWithBlock = func(ifIndex int, blockIndex uint32) error {
		return tcErr
	}
}

func TestProvisionPortsSpecificPort(t *testing.T) {
	defer resetDeps()

	// 4 slots, all Reserved
	sw := newProvisionTestSwitch("sw0", []uint32{
		InnerIPReserved, InnerIPReserved, InnerIPReserved, InnerIPReserved,
	})
	defer sw.mmapSlots.Close()
	mockProvisionDeps(sw, nil, nil)

	// opts.Port=2 means only provision slot index 1 (port numbering is 1-based)
	out, err := ProvisionPorts("sw0", ProvisionOptions{Port: 2})
	if err != nil {
		t.Fatalf("ProvisionPorts: %v", err)
	}
	if out.Provisioned != 1 {
		t.Errorf("Provisioned = %d, want 1", out.Provisioned)
	}
	// Slot 1 should be Free now (provisioned), others still Reserved
	if ip := sw.mmapSlots.GetInnerIP(1); ip != InnerIPFree {
		t.Errorf("slot 1 InnerIP = %#x, want Free", ip)
	}
	if ip := sw.mmapSlots.GetInnerIP(0); ip != InnerIPReserved {
		t.Errorf("slot 0 should still be Reserved, got %#x", ip)
	}
	if ip := sw.mmapSlots.GetInnerIP(2); ip != InnerIPReserved {
		t.Errorf("slot 2 should still be Reserved, got %#x", ip)
	}
}

func TestProvisionPortsSkipFreeSlots(t *testing.T) {
	defer resetDeps()

	// Slots: Free, Reserved, Free, Reserved
	sw := newProvisionTestSwitch("sw0", []uint32{
		InnerIPFree, InnerIPReserved, InnerIPFree, InnerIPReserved,
	})
	defer sw.mmapSlots.Close()
	mockProvisionDeps(sw, nil, nil)

	out, err := ProvisionPorts("sw0", ProvisionOptions{})
	if err != nil {
		t.Fatalf("ProvisionPorts: %v", err)
	}
	// Only 2 Reserved slots should be provisioned
	if out.Provisioned != 2 {
		t.Errorf("Provisioned = %d, want 2", out.Provisioned)
	}
	// All slots should now be Free (Reserved ones got provisioned, Free ones stayed)
	for i := uint32(0); i < 4; i++ {
		if ip := sw.mmapSlots.GetInnerIP(i); ip != InnerIPFree {
			t.Errorf("slot %d InnerIP = %#x, want Free", i, ip)
		}
	}
}

func TestProvisionPortsCount(t *testing.T) {
	defer resetDeps()

	// 4 Reserved slots, but opts.Count=2 should stop after 2
	sw := newProvisionTestSwitch("sw0", []uint32{
		InnerIPReserved, InnerIPReserved, InnerIPReserved, InnerIPReserved,
	})
	defer sw.mmapSlots.Close()
	mockProvisionDeps(sw, nil, nil)

	out, err := ProvisionPorts("sw0", ProvisionOptions{Count: 2})
	if err != nil {
		t.Fatalf("ProvisionPorts: %v", err)
	}
	if out.Provisioned != 2 {
		t.Errorf("Provisioned = %d, want 2", out.Provisioned)
	}
	// First 2 slots provisioned (Free), last 2 still Reserved
	if ip := sw.mmapSlots.GetInnerIP(0); ip != InnerIPFree {
		t.Errorf("slot 0 should be Free, got %#x", ip)
	}
	if ip := sw.mmapSlots.GetInnerIP(1); ip != InnerIPFree {
		t.Errorf("slot 1 should be Free, got %#x", ip)
	}
	if ip := sw.mmapSlots.GetInnerIP(2); ip != InnerIPReserved {
		t.Errorf("slot 2 should still be Reserved, got %#x", ip)
	}
	if ip := sw.mmapSlots.GetInnerIP(3); ip != InnerIPReserved {
		t.Errorf("slot 3 should still be Reserved, got %#x", ip)
	}
}

func TestProvisionPortsVethError(t *testing.T) {
	defer resetDeps()

	sw := newProvisionTestSwitch("sw0", []uint32{InnerIPReserved})
	defer sw.mmapSlots.Close()
	mockProvisionDeps(sw, errors.New("veth creation failed"), nil)

	_, err := ProvisionPorts("sw0", ProvisionOptions{})
	if err == nil {
		t.Fatal("expected error from veth creation, got nil")
	}
	if !containsSubstring(err.Error(), "failed to create veth") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestProvisionPortsTCError(t *testing.T) {
	defer resetDeps()

	sw := newProvisionTestSwitch("sw0", []uint32{InnerIPReserved})
	defer sw.mmapSlots.Close()
	mockProvisionDeps(sw, nil, errors.New("TC attach failed"))

	_, err := ProvisionPorts("sw0", ProvisionOptions{})
	if err == nil {
		t.Fatal("expected error from TC attach, got nil")
	}
	if !containsSubstring(err.Error(), "failed to add clsact") {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- ProvisionPorts idempotent tests ---

func TestProvisionPortsIdempotent(t *testing.T) {
	// When peer veth already exists with matching ifindex and TC attached,
	// veth creation should be skipped and CAS(Reserved→Free) still executes.
	defer resetDeps()

	sw := newProvisionTestSwitch("sw0", []uint32{InnerIPReserved})
	defer sw.mmapSlots.Close()
	// Set existing ifindex in slot to match what netlinkGetLinkIndexInNs returns
	sw.mmapSlots.UpdateSlotFields(0, func(slot *SlotItem) {
		slot.Ifindex = 10
	})
	mockProvisionDeps(sw, nil, nil)

	vethCreated := false
	netlinkCreateVethPairs = func(specs []netlink.VethSpec) error {
		vethCreated = true
		return nil
	}
	// Peer device exists with ifindex=10
	netlinkGetLinkIndexInNs = func(ns netlink.NetNS, name string) (int, error) {
		return 10, nil
	}
	// TC already attached
	netlinkHasTCFilter = func(link netlink.Link, direction netlink.Direction) bool {
		return true
	}

	out, err := ProvisionPorts("sw0", ProvisionOptions{Port: 1})
	if err != nil {
		t.Fatalf("ProvisionPorts: %v", err)
	}
	if out.Provisioned != 1 {
		t.Errorf("Provisioned = %d, want 1", out.Provisioned)
	}
	if vethCreated {
		t.Error("veth should not have been created (peer already exists)")
	}
	// Slot should be Free now
	if ip := sw.mmapSlots.GetInnerIP(0); ip != InnerIPFree {
		t.Errorf("slot 0 InnerIP = %#x, want Free", ip)
	}
}

func TestProvisionPortsIdempotentIfindexMismatch(t *testing.T) {
	// When peer veth exists but ifindex differs from slot, slot should be updated.
	defer resetDeps()

	sw := newProvisionTestSwitch("sw0", []uint32{InnerIPReserved})
	defer sw.mmapSlots.Close()
	// Slot has ifindex=10, but actual device has ifindex=20
	sw.mmapSlots.UpdateSlotFields(0, func(slot *SlotItem) {
		slot.Ifindex = 10
	})
	mockProvisionDeps(sw, nil, nil)

	netlinkCreateVethPairs = func(specs []netlink.VethSpec) error {
		t.Error("veth should not have been created")
		return nil
	}
	netlinkGetLinkIndexInNs = func(ns netlink.NetNS, name string) (int, error) {
		return 20, nil // Different ifindex
	}
	netlinkHasTCFilter = func(link netlink.Link, direction netlink.Direction) bool {
		return true
	}

	out, err := ProvisionPorts("sw0", ProvisionOptions{Port: 1})
	if err != nil {
		t.Fatalf("ProvisionPorts: %v", err)
	}
	if out.Provisioned != 1 {
		t.Errorf("Provisioned = %d, want 1", out.Provisioned)
	}
	// Verify ifindex was updated to 20
	slot := sw.mmapSlots.GetSlot(0)
	if slot.Ifindex != 20 {
		t.Errorf("slot.Ifindex = %d, want 20", slot.Ifindex)
	}
}

func TestProvisionPortsIdempotentTCMissing(t *testing.T) {
	// When peer veth exists but clsact/block is missing, it should be re-attached.
	defer resetDeps()

	sw := newProvisionTestSwitch("sw0", []uint32{InnerIPReserved})
	defer sw.mmapSlots.Close()
	sw.mmapSlots.UpdateSlotFields(0, func(slot *SlotItem) {
		slot.Ifindex = 10
	})
	mockProvisionDeps(sw, nil, nil)

	netlinkCreateVethPairs = func(specs []netlink.VethSpec) error {
		t.Error("veth should not have been created")
		return nil
	}
	netlinkGetLinkIndexInNs = func(ns netlink.NetNS, name string) (int, error) {
		return 10, nil
	}
	clsactAttached := false
	netlinkAddClsactWithBlock = func(ifIndex int, blockIndex uint32) error {
		clsactAttached = true
		return nil
	}

	out, err := ProvisionPorts("sw0", ProvisionOptions{Port: 1})
	if err != nil {
		t.Fatalf("ProvisionPorts: %v", err)
	}
	if out.Provisioned != 1 {
		t.Errorf("Provisioned = %d, want 1", out.Provisioned)
	}
	if !clsactAttached {
		t.Error("clsact with block should have been re-attached")
	}
}

func TestProvisionPortsEnsureBPFFSError(t *testing.T) {
	defer resetDeps()
	// bpfEnsureBPFFS is now called inside AcquireControlLock;
	// test via acquireControlLockFn returning the bpffs error
	acquireControlLockFn = func(name string) (*ControlLock, error) {
		return nil, fmt.Errorf("failed to acquire control lock: %w",
			fmt.Errorf("failed to ensure bpffs: %w", errors.New("bpffs failed")))
	}

	_, err := ProvisionPorts("sw0", ProvisionOptions{})
	if err == nil || !containsSubstring(err.Error(), "failed to ensure bpffs") {
		t.Errorf("expected bpffs error, got: %v", err)
	}
}

func TestProvisionPortsLockError(t *testing.T) {
	defer resetDeps()
	acquireControlLockFn = func(name string) (*ControlLock, error) {
		return nil, errors.New("lock busy")
	}

	_, err := ProvisionPorts("sw0", ProvisionOptions{})
	if err == nil || !containsSubstring(err.Error(), "failed to acquire control lock") {
		t.Errorf("expected lock error, got: %v", err)
	}
}

func TestProvisionPortsNetnsError(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	sw := newProvisionTestSwitch("sw0", []uint32{InnerIPReserved})
	defer sw.mmapSlots.Close()
	openSwitchFn = func(name string) (Interface, error) { return sw, nil }

	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return nil, errors.New("ns not found")
	}

	_, err := ProvisionPorts("sw0", ProvisionOptions{})
	if err == nil || !containsSubstring(err.Error(), "failed to get switch netns") {
		t.Errorf("expected netns error, got: %v", err)
	}
}

func TestProvisionPortsWithMgmtAndTransit(t *testing.T) {
	defer resetDeps()

	sw := newProvisionTestSwitch("sw0", []uint32{InnerIPReserved, InnerIPReserved})
	defer sw.mmapSlots.Close()
	// Add mgmt and transit metadata
	sw.meta = &SwitchMetadata{
		SwitchNetNS:    "test_switch_ns",
		PortNetNS:      "test_port_ns",
		TransitDev:     "transit0",
		TransitDevAddr: "10.0.0.1/24",
		MgmtExtracts: []MgmtExtractMeta{
			{
				NetNS:         "mgmt_ns",
				Dev:           "mgmt0",
				ServiceRoutes: []string{"192.168.0.0/16", "172.16.0.0/12"},
			},
		},
	}
	mockProvisionDeps(sw, nil, nil)

	netlinkGetLinkIndexInNs = func(ns netlink.NetNS, name string) (int, error) {
		switch {
		case containsSubstring(name, "-m"):
			return 100, nil // mgmt device
		case name == "transit0":
			return 200, nil // transit device
		default:
			return 0, errors.New("not found") // port peer not found → create
		}
	}

	out, err := ProvisionPorts("sw0", ProvisionOptions{})
	if err != nil {
		t.Fatalf("ProvisionPorts: %v", err)
	}
	if out.Provisioned != 2 {
		t.Errorf("Provisioned = %d, want 2", out.Provisioned)
	}

	// Verify mgmt CIDRs written to slot
	slot := sw.mmapSlots.GetSlot(0)
	if slot.MgmtCidrCount != 2 {
		t.Errorf("MgmtCidrCount = %d, want 2", slot.MgmtCidrCount)
	}
	// First CIDR in MgmtCidrs0, second in MgmtCidrsExt[0]
	if slot.MgmtCidrs0.Ifindex != 100 {
		t.Errorf("MgmtCidrs0.Ifindex = %d, want 100", slot.MgmtCidrs0.Ifindex)
	}
	if slot.MgmtCidrsExt[0].Ifindex != 100 {
		t.Errorf("MgmtCidrsExt[0].Ifindex = %d, want 100", slot.MgmtCidrsExt[0].Ifindex)
	}

	// Verify transit info written to slot
	if slot.TransitIfindex != 200 {
		t.Errorf("TransitIfindex = %d, want 200", slot.TransitIfindex)
	}
	if slot.TransitIp == 0 {
		t.Error("TransitIp should be non-zero")
	}
}

func TestProvisionPortsTransitMissingAddr(t *testing.T) {
	defer resetDeps()

	sw := newProvisionTestSwitch("sw0", []uint32{InnerIPReserved})
	defer sw.mmapSlots.Close()
	sw.meta = &SwitchMetadata{
		SwitchNetNS: "test_switch_ns",
		PortNetNS:   "test_port_ns",
		TransitDev:  "transit0",
		// TransitDevAddr intentionally empty
	}
	mockProvisionDeps(sw, nil, nil)

	netlinkGetLinkIndexInNs = func(ns netlink.NetNS, name string) (int, error) {
		return 200, nil
	}

	_, err := ProvisionPorts("sw0", ProvisionOptions{})
	if err == nil || !containsSubstring(err.Error(), "transit address missing") {
		t.Errorf("expected transit address error, got: %v", err)
	}
}

func TestProvisionPortsTransitInvalidAddr(t *testing.T) {
	defer resetDeps()

	sw := newProvisionTestSwitch("sw0", []uint32{InnerIPReserved})
	defer sw.mmapSlots.Close()
	sw.meta = &SwitchMetadata{
		SwitchNetNS:    "test_switch_ns",
		PortNetNS:      "test_port_ns",
		TransitDev:     "transit0",
		TransitDevAddr: "not-a-cidr",
	}
	mockProvisionDeps(sw, nil, nil)

	netlinkGetLinkIndexInNs = func(ns netlink.NetNS, name string) (int, error) {
		return 200, nil
	}

	_, err := ProvisionPorts("sw0", ProvisionOptions{})
	if err == nil || !containsSubstring(err.Error(), "failed to parse transit address") {
		t.Errorf("expected parse error, got: %v", err)
	}
}

func TestProvisionPortsTransitIfindexError(t *testing.T) {
	defer resetDeps()

	sw := newProvisionTestSwitch("sw0", []uint32{InnerIPReserved})
	defer sw.mmapSlots.Close()
	sw.meta = &SwitchMetadata{
		SwitchNetNS:    "test_switch_ns",
		PortNetNS:      "test_port_ns",
		TransitDev:     "transit0",
		TransitDevAddr: "10.0.0.1/24",
	}
	mockProvisionDeps(sw, nil, nil)

	netlinkGetLinkIndexInNs = func(ns netlink.NetNS, name string) (int, error) {
		if name == "transit0" {
			return 0, errors.New("device gone")
		}
		return 10, nil
	}

	_, err := ProvisionPorts("sw0", ProvisionOptions{})
	if err == nil || !containsSubstring(err.Error(), "failed to get ifindex for transit") {
		t.Errorf("expected transit ifindex error, got: %v", err)
	}
}

func TestProvisionPortsMgmtIfindexError(t *testing.T) {
	defer resetDeps()

	sw := newProvisionTestSwitch("sw0", []uint32{InnerIPReserved})
	defer sw.mmapSlots.Close()
	sw.meta = &SwitchMetadata{
		SwitchNetNS: "test_switch_ns",
		PortNetNS:   "test_port_ns",
		MgmtExtracts: []MgmtExtractMeta{
			{NetNS: "mgmt_ns", Dev: "mgmt0", ServiceRoutes: []string{"192.168.0.0/16"}},
		},
	}
	mockProvisionDeps(sw, nil, nil)

	netlinkGetLinkIndexInNs = func(ns netlink.NetNS, name string) (int, error) {
		if containsSubstring(name, "-m") {
			return 0, errors.New("mgmt device missing")
		}
		return 10, nil
	}

	_, err := ProvisionPorts("sw0", ProvisionOptions{})
	if err == nil || !containsSubstring(err.Error(), "failed to get ifindex for mgmt") {
		t.Errorf("expected mgmt ifindex error, got: %v", err)
	}
}

func TestProvisionPortsMgmtInvalidRoute(t *testing.T) {
	defer resetDeps()

	sw := newProvisionTestSwitch("sw0", []uint32{InnerIPReserved})
	defer sw.mmapSlots.Close()
	sw.meta = &SwitchMetadata{
		SwitchNetNS: "test_switch_ns",
		PortNetNS:   "test_port_ns",
		MgmtExtracts: []MgmtExtractMeta{
			{NetNS: "mgmt_ns", Dev: "mgmt0", ServiceRoutes: []string{"not-a-cidr"}},
		},
	}
	mockProvisionDeps(sw, nil, nil)

	netlinkGetLinkIndexInNs = func(ns netlink.NetNS, name string) (int, error) {
		return 100, nil
	}

	_, err := ProvisionPorts("sw0", ProvisionOptions{})
	if err == nil || !containsSubstring(err.Error(), "failed to parse mgmt service route") {
		t.Errorf("expected route parse error, got: %v", err)
	}
}
