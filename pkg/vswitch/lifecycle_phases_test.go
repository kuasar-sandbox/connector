package vswitch

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/cilium/ebpf"
	vnl "github.com/vishvananda/netlink"

	"github.com/kuasar-sandbox/sandbox-vswitch/pkg/dhcp"
	"github.com/kuasar-sandbox/sandbox-vswitch/pkg/internal/bpf"
	"github.com/kuasar-sandbox/sandbox-vswitch/pkg/netlink"
	"github.com/kuasar-sandbox/sandbox-vswitch/pkg/netns"
)

// mockBPFMap is a mock implementation of BPFMap for testing.
type mockBPFMap struct {
	data       map[uint32]interface{}
	lookupErr  error
	updateErr  error
	deleteErr  error
	lookupFunc func(key, valueOut interface{}) error
	updateFunc func(key, value interface{}, flags ebpf.MapUpdateFlags) error
}

func newMockBPFMap() *mockBPFMap {
	return &mockBPFMap{
		data: make(map[uint32]interface{}),
	}
}

func (m *mockBPFMap) Lookup(key, valueOut interface{}) error {
	if m.lookupFunc != nil {
		return m.lookupFunc(key, valueOut)
	}
	if m.lookupErr != nil {
		return m.lookupErr
	}
	k := key.(uint32)
	v, ok := m.data[k]
	if !ok {
		return errors.New("key not found")
	}

	// Type switch for different value types
	switch out := valueOut.(type) {
	case *SlotItem:
		if slot, ok := v.(*SlotItem); ok {
			*out = *slot
		}
	case *SlotStats:
		if stats, ok := v.(*SlotStats); ok {
			*out = *stats
		}
	case *[]SlotStats:
		if stats, ok := v.([]SlotStats); ok {
			*out = stats
		}
	case *SwitchConfig:
		if cfg, ok := v.(*SwitchConfig); ok {
			*out = *cfg
		}
	case *uint32:
		if id, ok := v.(uint32); ok {
			*out = id
		}
	}
	return nil
}

func (m *mockBPFMap) Update(key, value interface{}, flags ebpf.MapUpdateFlags) error {
	if m.updateFunc != nil {
		return m.updateFunc(key, value, flags)
	}
	if m.updateErr != nil {
		return m.updateErr
	}
	k := key.(uint32)

	// Deep copy the value to avoid aliasing
	switch v := value.(type) {
	case *SlotItem:
		copied := *v
		m.data[k] = &copied
	case *SlotStats:
		copied := *v
		m.data[k] = &copied
	case []SlotStats:
		copied := make([]SlotStats, len(v))
		copy(copied, v)
		m.data[k] = copied
	case *SwitchConfig:
		copied := *v
		m.data[k] = &copied
	case *uint32:
		copied := *v
		m.data[k] = copied
	default:
		m.data[k] = value
	}
	return nil
}

func (m *mockBPFMap) Delete(key interface{}) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	k := key.(uint32)
	delete(m.data, k)
	return nil
}

// --- validateTransitDeviceEarly tests ---

func TestValidateTransitDeviceEarlyNoTransitDev(t *testing.T) {
	cfg := &Config{
		TransitDev: "",
	}
	err := validateTransitDeviceEarly(cfg)
	if err != nil {
		t.Errorf("expected no error for empty TransitDev, got: %v", err)
	}
}

func TestValidateTransitDeviceEarlyNotDown(t *testing.T) {
	defer resetDeps()

	netlinkIsLinkDown = func(name string) (bool, error) {
		return false, nil // Device is UP, not DOWN
	}

	cfg := &Config{
		TransitDev: "eth0",
	}
	err := validateTransitDeviceEarly(cfg)
	if err == nil {
		t.Fatal("expected error for device not DOWN")
	}
	if !containsSubstring(err.Error(), "must be DOWN") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateTransitDeviceEarlyCheckError(t *testing.T) {
	defer resetDeps()

	netlinkIsLinkDown = func(name string) (bool, error) {
		return false, errors.New("check failed")
	}

	cfg := &Config{
		TransitDev: "eth0",
	}
	err := validateTransitDeviceEarly(cfg)
	if err == nil {
		t.Fatal("expected error when check fails")
	}
	if !containsSubstring(err.Error(), "failed to check transit device state") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateTransitDeviceEarlyNoMTU(t *testing.T) {
	defer resetDeps()

	netlinkIsLinkDown = func(name string) (bool, error) {
		return true, nil // Device is DOWN
	}

	cfg := &Config{
		TransitDev: "eth0",
		MTU:        0, // No MTU specified
	}
	err := validateTransitDeviceEarly(cfg)
	if err != nil {
		t.Errorf("expected no error when MTU=0, got: %v", err)
	}
}

func TestValidateTransitDeviceEarlyMTUAutoMode(t *testing.T) {
	defer resetDeps()

	netlinkIsLinkDown = func(name string) (bool, error) {
		return true, nil
	}

	cfg := &Config{
		TransitDev:        "eth0",
		MTU:               1500,
		TransitDevMTUAuto: true,
	}
	err := validateTransitDeviceEarly(cfg)
	if err != nil {
		t.Errorf("expected no error in auto mode, got: %v", err)
	}
	// Auto mode should calculate TransitDevMTU = MTU + overhead
	expectedMTU := 1500 + GeneveIPOverhead
	if cfg.TransitDevMTU != expectedMTU {
		t.Errorf("expected TransitDevMTU=%d, got %d", expectedMTU, cfg.TransitDevMTU)
	}
}

func TestValidateTransitDeviceEarlyMTUAutoModeEthEncap(t *testing.T) {
	defer resetDeps()

	netlinkIsLinkDown = func(name string) (bool, error) {
		return true, nil
	}

	cfg := &Config{
		TransitDev:        "eth0",
		MTU:               1500,
		TransitDevMTUAuto: true,
		GeneveEncapEth:    true,
	}
	err := validateTransitDeviceEarly(cfg)
	if err != nil {
		t.Errorf("expected no error in auto mode, got: %v", err)
	}
	// Auto mode with Eth encap should use GeneveEthOverhead
	expectedMTU := 1500 + GeneveEthOverhead
	if cfg.TransitDevMTU != expectedMTU {
		t.Errorf("expected TransitDevMTU=%d, got %d", expectedMTU, cfg.TransitDevMTU)
	}
}

func TestValidateTransitDeviceEarlyExplicitMTUSufficient(t *testing.T) {
	defer resetDeps()

	netlinkIsLinkDown = func(name string) (bool, error) {
		return true, nil
	}

	cfg := &Config{
		TransitDev:    "eth0",
		MTU:           1500,
		TransitDevMTU: 1500 + GeneveIPOverhead + 100, // More than enough
	}
	err := validateTransitDeviceEarly(cfg)
	if err != nil {
		t.Errorf("expected no error with sufficient MTU, got: %v", err)
	}
}

func TestValidateTransitDeviceEarlyExplicitMTUTooSmall(t *testing.T) {
	defer resetDeps()

	netlinkIsLinkDown = func(name string) (bool, error) {
		return true, nil
	}

	cfg := &Config{
		TransitDev:    "eth0",
		MTU:           1500,
		TransitDevMTU: 1500, // Too small, missing overhead
	}
	err := validateTransitDeviceEarly(cfg)
	if err == nil {
		t.Fatal("expected error for MTU too small")
	}
	if !containsSubstring(err.Error(), "too small") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateTransitDeviceEarlyExistingDeviceMTU(t *testing.T) {
	defer resetDeps()

	netlinkIsLinkDown = func(name string) (bool, error) {
		return true, nil
	}
	netnsGetCurrent = func() (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	netlinkGetMTUInNs = func(ns netlink.NetNS, name string) (int, error) {
		return 9000, nil // Large MTU
	}

	cfg := &Config{
		TransitDev:    "eth0",
		MTU:           1500,
		TransitDevMTU: 0, // Not setting, validate existing
	}
	err := validateTransitDeviceEarly(cfg)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateTransitDeviceEarlyExistingDeviceMTUTooSmall(t *testing.T) {
	defer resetDeps()

	netlinkIsLinkDown = func(name string) (bool, error) {
		return true, nil
	}
	netnsGetCurrent = func() (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	netlinkGetMTUInNs = func(ns netlink.NetNS, name string) (int, error) {
		return 1500, nil // Too small
	}

	cfg := &Config{
		TransitDev:    "eth0",
		MTU:           1500,
		TransitDevMTU: 0,
	}
	err := validateTransitDeviceEarly(cfg)
	if err == nil {
		t.Fatal("expected error for existing device MTU too small")
	}
	if !containsSubstring(err.Error(), "too small") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateTransitDeviceEarlyGetCurrentNsError(t *testing.T) {
	defer resetDeps()

	netlinkIsLinkDown = func(name string) (bool, error) {
		return true, nil
	}
	netnsGetCurrent = func() (*netns.NetNS, error) {
		return nil, errors.New("get ns failed")
	}

	cfg := &Config{
		TransitDev:    "eth0",
		MTU:           1500,
		TransitDevMTU: 0,
	}
	err := validateTransitDeviceEarly(cfg)
	if err == nil {
		t.Fatal("expected error for get current ns")
	}
	if !containsSubstring(err.Error(), "failed to get current netns") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateTransitDeviceEarlyGetMTUError(t *testing.T) {
	defer resetDeps()

	netlinkIsLinkDown = func(name string) (bool, error) {
		return true, nil
	}
	netnsGetCurrent = func() (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	netlinkGetMTUInNs = func(ns netlink.NetNS, name string) (int, error) {
		return 0, errors.New("get MTU failed")
	}

	cfg := &Config{
		TransitDev:    "eth0",
		MTU:           1500,
		TransitDevMTU: 0,
	}
	err := validateTransitDeviceEarly(cfg)
	if err == nil {
		t.Fatal("expected error for get MTU")
	}
	if !containsSubstring(err.Error(), "failed to get MTU for transit device") {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- initBPFSlotsReserved tests ---

func TestInitBPFSlotsReservedSuccess(t *testing.T) {
	mmapSlots := newMmappedSlotsForTest(4)
	defer mmapSlots.Close()

	err := initBPFSlotsReserved(mmapSlots, 4)
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}

	// Verify all slots are reserved
	for i := uint32(0); i < 4; i++ {
		ip := mmapSlots.GetInnerIP(i)
		if ip != InnerIPReserved {
			t.Errorf("slot %d: expected InnerIP=%#x (reserved), got %#x", i, InnerIPReserved, ip)
		}
	}
}

func TestInitBPFSlotsReservedAlreadyOccupied(t *testing.T) {
	mmapSlots := newMmappedSlotsForTest(4)
	defer mmapSlots.Close()

	// Pre-allocate slot 1 so reserving it will fail
	mmapSlots.TryAllocate(1, 0x0a000001)

	err := initBPFSlotsReserved(mmapSlots, 4)
	if err == nil {
		t.Fatal("expected error when slot is already occupied")
	}
	if !containsSubstring(err.Error(), "failed to reserve slot") {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- buildStartOutput tests ---

func TestBuildStartOutputBasic(t *testing.T) {
	cfg := &Config{
		Name:           "sw0",
		SwitchNetNS:    "switch_ns",
		PortNetNS:      "port_ns",
		NumPorts:       256,
		FloatingIPBase: net.ParseIP("100.100.96.0"),
	}
	mgmtPlanes := []MgmtPlaneInfo{}

	output := buildStartOutput(cfg, mgmtPlanes, "", false)

	if output.Switch != "sw0" {
		t.Errorf("expected Switch=sw0, got %s", output.Switch)
	}
	if output.SwitchNetNS != "switch_ns" {
		t.Errorf("expected SwitchNetNS=switch_ns, got %s", output.SwitchNetNS)
	}
	if output.PortNetNS != "port_ns" {
		t.Errorf("expected PortNetNS=port_ns, got %s", output.PortNetNS)
	}
	if output.Ports != 256 {
		t.Errorf("expected Ports=256, got %d", output.Ports)
	}
	if output.PortsUsed != 0 {
		t.Errorf("expected PortsUsed=0, got %d", output.PortsUsed)
	}
	if output.PortsAvailable != 256 {
		t.Errorf("expected PortsAvailable=256, got %d", output.PortsAvailable)
	}
	if output.FloatingIPBase != "100.100.96.0" {
		t.Errorf("expected FloatingIPBase=100.100.96.0, got %s", output.FloatingIPBase)
	}
	if output.TransitType != "none" {
		t.Errorf("expected TransitType=none, got %s", output.TransitType)
	}
	if output.TransitDev != "" {
		t.Errorf("expected TransitDev empty, got %s", output.TransitDev)
	}
}

func TestBuildStartOutputWithTransit(t *testing.T) {
	cfg := &Config{
		Name:           "sw0",
		SwitchNetNS:    "switch_ns",
		PortNetNS:      "port_ns",
		NumPorts:       256,
		FloatingIPBase: net.ParseIP("100.100.96.0"),
		TransitDev:     "eth0",
		GenevePortBase: 6081,
	}
	mgmtPlanes := []MgmtPlaneInfo{}

	output := buildStartOutput(cfg, mgmtPlanes, "192.168.1.100", false)

	if output.TransitType != "overlay-geneve" {
		t.Errorf("expected TransitType=overlay-geneve, got %s", output.TransitType)
	}
	if output.TransitDev != "eth0" {
		t.Errorf("expected TransitDev=eth0, got %s", output.TransitDev)
	}
	if output.TransitDevIP != "192.168.1.100" {
		t.Errorf("expected TransitDevIP=192.168.1.100, got %s", output.TransitDevIP)
	}
	if output.GenevePortBase != 6081 {
		t.Errorf("expected GenevePortBase=6081, got %d", output.GenevePortBase)
	}
}

func TestBuildStartOutputWithMgmtPlanes(t *testing.T) {
	cfg := &Config{
		Name:           "sw0",
		SwitchNetNS:    "switch_ns",
		PortNetNS:      "port_ns",
		NumPorts:       256,
		FloatingIPBase: net.ParseIP("100.100.96.0"),
	}
	mgmtPlanes := []MgmtPlaneInfo{
		{
			Index:             0,
			MgmtNetNS:         "mgmt_ns",
			MgmtDev:           "mgmt0",
			ServiceRoutes:     []string{"169.254.169.254/32"},
			ReturnRouteMetric: 100,
		},
	}

	output := buildStartOutput(cfg, mgmtPlanes, "", false)

	if len(output.MgmtPlanes) != 1 {
		t.Fatalf("expected 1 mgmt plane, got %d", len(output.MgmtPlanes))
	}
	if output.MgmtPlanes[0].MgmtNetNS != "mgmt_ns" {
		t.Errorf("expected MgmtNetNS=mgmt_ns, got %s", output.MgmtPlanes[0].MgmtNetNS)
	}
	if output.MgmtPlanes[0].MgmtDev != "mgmt0" {
		t.Errorf("expected MgmtDev=mgmt0, got %s", output.MgmtPlanes[0].MgmtDev)
	}
}

func TestBuildStartOutputSwitchMaps(t *testing.T) {
	cfg := &Config{
		Name:           "sw0",
		SwitchNetNS:    "switch_ns",
		PortNetNS:      "port_ns",
		NumPorts:       256,
		FloatingIPBase: net.ParseIP("100.100.96.0"),
	}

	output := buildStartOutput(cfg, []MgmtPlaneInfo{}, "", false)

	// Every pinned map must be reported, so callers can locate all of them.
	wantMaps := []string{"slots", "config", "stats", "ifindex_to_slot", "metadata", "mgmt_svc_fwd", "mgmt_svc_rev"}
	if len(output.SwitchMaps) != len(wantMaps) {
		t.Errorf("switch_maps count: got %d, want %d (%v)", len(output.SwitchMaps), len(wantMaps), output.SwitchMaps)
	}
	for _, m := range wantMaps {
		want := "/sys/fs/bpf/sw0/" + m
		if output.SwitchMaps[m] != want {
			t.Errorf("switch_maps[%s]: got %q, want %q", m, output.SwitchMaps[m], want)
		}
	}
}

// --- validateMTUSlowPath tests ---

func TestValidateMTUSlowPathSkipWhenMTUSet(t *testing.T) {
	cfg := &Config{
		MTU:        1500, // MTU is set, should skip slow path
		TransitDev: "eth0",
	}
	err := validateMTUSlowPath(cfg, nil)
	if err != nil {
		t.Errorf("expected no error when MTU is set, got: %v", err)
	}
}

func TestValidateMTUSlowPathSkipWhenNoTransitDev(t *testing.T) {
	cfg := &Config{
		MTU:        0,
		TransitDev: "", // No transit dev, should skip
	}
	err := validateMTUSlowPath(cfg, nil)
	if err != nil {
		t.Errorf("expected no error when no transit dev, got: %v", err)
	}
}

// --- cleanup tests ---

func TestCleanupWithNothing(t *testing.T) {
	defer resetDeps()

	// No cleanup needed
	cs := &cleanupState{}
	cfg := &Config{Name: "sw0"}

	// Should not panic or error
	cs.cleanup(cfg, nil, nil)
}

func TestCleanupTransitMoveBack(t *testing.T) {
	defer resetDeps()

	moveCalled := false
	netnsMoveDevice = func(devName string, fromNs, toNs *netns.NetNS) error {
		moveCalled = true
		if devName != "eth0" {
			t.Errorf("expected devName eth0, got %s", devName)
		}
		return nil
	}

	cs := &cleanupState{
		transitMoved:   true,
		transitDevName: "eth0",
		callerNs:       &netns.NetNS{}, // Mock netns (Close is no-op)
	}
	cfg := &Config{Name: "sw0"}

	cs.cleanup(cfg, &netns.NetNS{}, nil)

	if !moveCalled {
		t.Error("expected netnsMoveDevice to be called")
	}
}

func TestCleanupTransitMoveBackError(t *testing.T) {
	defer resetDeps()

	netnsMoveDevice = func(devName string, fromNs, toNs *netns.NetNS) error {
		return errors.New("move failed")
	}

	cs := &cleanupState{
		transitMoved:   true,
		transitDevName: "eth0",
		callerNs:       &netns.NetNS{},
	}
	cfg := &Config{Name: "sw0"}

	// Should not panic, just log error
	cs.cleanup(cfg, &netns.NetNS{}, nil)
}

func TestCleanupDeleteMgmtVeths(t *testing.T) {
	defer resetDeps()

	var deletedIfindexes []int
	netlinkDelLinkByIndexInNs = func(ns netlink.NetNS, ifindex int) error {
		deletedIfindexes = append(deletedIfindexes, ifindex)
		return nil
	}

	cs := &cleanupState{
		mgmtIfindexes: []int{200, 201},
	}
	cfg := &Config{Name: "sw0"}

	cs.cleanup(cfg, &netns.NetNS{}, nil)

	if len(deletedIfindexes) != 2 {
		t.Errorf("expected 2 delete calls, got %d", len(deletedIfindexes))
	}
	if len(deletedIfindexes) >= 2 && (deletedIfindexes[0] != 200 || deletedIfindexes[1] != 201) {
		t.Errorf("expected ifindexes [200, 201], got %v", deletedIfindexes)
	}
}

func TestCleanupDeleteVethsError(t *testing.T) {
	defer resetDeps()

	netlinkDelLinkByIndexInNs = func(ns netlink.NetNS, ifindex int) error {
		return errors.New("delete failed")
	}

	cs := &cleanupState{
		mgmtIfindexes: []int{200},
	}
	cfg := &Config{Name: "sw0"}

	// Should not panic, just log errors
	cs.cleanup(cfg, &netns.NetNS{}, nil)
}

func TestCleanupUnpinMaps(t *testing.T) {
	defer resetDeps()

	unpinCalled := false
	bpfUnpinMaps = func(name string) error {
		unpinCalled = true
		if name != "sw0" {
			t.Errorf("expected sw0, got %s", name)
		}
		return nil
	}

	cs := &cleanupState{
		mapsPinned: true,
	}
	cfg := &Config{Name: "sw0"}

	cs.cleanup(cfg, nil, nil)

	if !unpinCalled {
		t.Error("expected bpfUnpinMaps to be called")
	}
}

func TestCleanupUnpinMapsError(t *testing.T) {
	defer resetDeps()

	bpfUnpinMaps = func(name string) error {
		return errors.New("unpin failed")
	}

	cs := &cleanupState{
		mapsPinned: true,
	}
	cfg := &Config{Name: "sw0"}

	// Should not panic, just log error
	cs.cleanup(cfg, nil, nil)
}

func TestCleanupFullScenario(t *testing.T) {
	defer resetDeps()

	var (
		moveDeviceCalled bool
		mgmtDeleteCount  int
		unpinCalled      bool
	)

	netnsMoveDevice = func(devName string, fromNs, toNs *netns.NetNS) error {
		moveDeviceCalled = true
		return nil
	}
	netlinkDelLinkByIndexInNs = func(ns netlink.NetNS, ifindex int) error {
		mgmtDeleteCount++
		return nil
	}
	bpfUnpinMaps = func(name string) error {
		unpinCalled = true
		return nil
	}

	cs := &cleanupState{
		transitMoved:   true,
		transitDevName: "eth0",
		callerNs:       &netns.NetNS{},
		mgmtIfindexes:  []int{200, 201},
		bpfLoaded:      true,
		mapsPinned:     true,
	}
	cfg := &Config{Name: "sw0"}

	cs.cleanup(cfg, &netns.NetNS{}, nil)

	if !moveDeviceCalled {
		t.Error("expected transit device move")
	}
	if mgmtDeleteCount != 2 {
		t.Errorf("expected 2 mgmt delete calls, got %d", mgmtDeleteCount)
	}
	if !unpinCalled {
		t.Error("expected maps unpin")
	}
}

// --- buildVethSpecs tests ---

func TestBuildVethSpecs(t *testing.T) {
	mac := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	cfg := &Config{
		Name:     "sw0",
		NumPorts: 3,
		MACAddr:  mac,
		PortMAC:  PortMACFixed(mac),
		MTU:      1500,
	}

	specs := buildVethSpecs(cfg, 42)

	if len(specs) != 3 {
		t.Fatalf("expected 3 specs, got %d", len(specs))
	}

	for i, spec := range specs {
		expectedName := cfg.PeerDeviceName(i)
		if spec.Name != expectedName {
			t.Errorf("spec %d: expected name %s, got %s", i, expectedName, spec.Name)
		}
		expectedPeerName := cfg.PortDeviceName(i)
		if spec.PeerName != expectedPeerName {
			t.Errorf("spec %d: expected peer name %s, got %s", i, expectedPeerName, spec.PeerName)
		}
		if spec.MTU != 1500 {
			t.Errorf("spec %d: expected MTU 1500, got %d", i, spec.MTU)
		}
		if spec.PeerNsFd != 42 {
			t.Errorf("spec %d: expected PeerNsFd 42, got %d", i, spec.PeerNsFd)
		}
		if spec.Group != PortLinkGroup {
			t.Errorf("spec %d: expected Group %d, got %d", i, PortLinkGroup, spec.Group)
		}
	}
}

func TestBuildVethSpecsPerPortMAC(t *testing.T) {
	mac := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	cfg := &Config{
		Name:     "sw0",
		NumPorts: 2,
		MACAddr:  mac,
		PortMAC:  make(net.HardwareAddr, 6), // per-port mode (all zeros)
		MTU:      9000,
	}

	specs := buildVethSpecs(cfg, 100)

	// Verify different MACs for each port
	if specs[0].PeerMACAddr.String() == specs[1].PeerMACAddr.String() {
		t.Error("expected different MACs for different ports in per-port mode")
	}
}

// --- attachTCToPorts tests ---

func TestAttachTCToPortsSuccess(t *testing.T) {
	defer resetDeps()

	callCount := 0
	netlinkLinkByName = func(name string) (netlink.Link, error) {
		callCount++
		return &vnl.Dummy{LinkAttrs: vnl.LinkAttrs{Name: name, Index: callCount * 10}}, nil
	}
	netlinkAddClsactWithBlock = func(ifIndex int, blockIndex uint32) error {
		return nil
	}

	cfg := &Config{Name: "sw0", NumPorts: 3}
	ifindexes, err := attachTCToPorts(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(ifindexes) != 3 {
		t.Fatalf("expected 3 ifindexes, got %d", len(ifindexes))
	}
	for i, idx := range ifindexes {
		expected := (i + 1) * 10
		if idx != expected {
			t.Errorf("ifindex %d: expected %d, got %d", i, expected, idx)
		}
	}
}

func TestAttachTCToPortsError(t *testing.T) {
	defer resetDeps()

	callCount := 0
	netlinkLinkByName = func(name string) (netlink.Link, error) {
		callCount++
		return &vnl.Dummy{LinkAttrs: vnl.LinkAttrs{Name: name, Index: callCount * 10}}, nil
	}
	netlinkAddClsactWithBlock = func(ifIndex int, blockIndex uint32) error {
		if callCount == 2 {
			return errors.New("clsact add failed")
		}
		return nil
	}

	cfg := &Config{Name: "sw0", NumPorts: 3}
	_, err := attachTCToPorts(cfg)
	if err == nil {
		t.Fatal("expected error")
	}
	if !containsSubstring(err.Error(), "configure") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAttachTCToPortsLinkByNameError(t *testing.T) {
	defer resetDeps()

	netlinkLinkByName = func(name string) (netlink.Link, error) {
		return nil, errors.New("link not found")
	}

	cfg := &Config{Name: "sw0", NumPorts: 1}
	_, err := attachTCToPorts(cfg)
	if err == nil {
		t.Fatal("expected error")
	}
	if !containsSubstring(err.Error(), "get link") {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- validateMTUSlowPath additional tests ---

func TestValidateMTUSlowPathGetMTUError(t *testing.T) {
	// Port veths that don't exist are skipped gracefully (StartReserved context).
	// With no mgmt veths, portMTU stays 0 and validation is skipped.
	defer resetDeps()

	netlinkGetMTUInNs = func(ns netlink.NetNS, name string) (int, error) {
		return 0, errors.New("get MTU failed")
	}

	cfg := &Config{
		Name:       "sw0",
		MTU:        0,
		TransitDev: "eth0",
		NumPorts:   1,
	}

	err := validateMTUSlowPath(cfg, &netns.NetNS{})
	if err != nil {
		t.Fatalf("expected nil (port veth errors should be skipped), got: %v", err)
	}
}

func TestValidateMTUSlowPathMgmtMTUError(t *testing.T) {
	defer resetDeps()

	callCount := 0
	netlinkGetMTUInNs = func(ns netlink.NetNS, name string) (int, error) {
		callCount++
		if callCount > 1 {
			return 0, errors.New("get MTU failed")
		}
		return 1500, nil
	}

	me, _ := ParseMgmtExtract("mgmt-ns:mgmt-dev:10.0.0.1/24")
	cfg := &Config{
		Name:         "sw0",
		MTU:          0,
		TransitDev:   "eth0",
		NumPorts:     1,
		MgmtExtracts: []*MgmtExtract{me},
	}

	err := validateMTUSlowPath(cfg, &netns.NetNS{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !containsSubstring(err.Error(), "failed to get MTU") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateMTUSlowPathGeneveEthOverhead(t *testing.T) {
	defer resetDeps()

	netlinkGetMTUInNs = func(ns netlink.NetNS, name string) (int, error) {
		return 1500, nil
	}

	cfg := &Config{
		Name:              "sw0",
		MTU:               0,
		TransitDev:        "eth0",
		TransitDevMTUAuto: true,
		GeneveEncapEth:    true, // Use Ether-over-GENEVE overhead
		NumPorts:          1,
	}

	err := validateMTUSlowPath(cfg, &netns.NetNS{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedMTU := 1500 + GeneveEthOverhead
	if cfg.TransitDevMTU != expectedMTU {
		t.Errorf("expected TransitDevMTU=%d, got %d", expectedMTU, cfg.TransitDevMTU)
	}
}

// --- configureTransitDevice tests ---

func TestConfigureTransitDeviceNoTransitDev(t *testing.T) {
	cfg := &Config{
		TransitDev: "", // No transit device
	}
	cs := &cleanupState{}

	ip, err := configureTransitDevice(cfg, nil, nil, cs)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if ip != "" {
		t.Errorf("expected empty IP, got %s", ip)
	}
}

func TestConfigureTransitDeviceGetCurrentNsError(t *testing.T) {
	defer resetDeps()

	netnsGetCurrent = func() (*netns.NetNS, error) {
		return nil, errors.New("get current ns failed")
	}

	cfg := &Config{
		TransitDev: "eth0",
	}
	cs := &cleanupState{}

	_, err := configureTransitDevice(cfg, nil, nil, cs)
	if err == nil {
		t.Fatal("expected error")
	}
	if !containsSubstring(err.Error(), "failed to get current netns") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestConfigureTransitDeviceMoveDeviceError(t *testing.T) {
	defer resetDeps()

	netnsGetCurrent = func() (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	netnsMoveDevice = func(devName string, fromNs, toNs *netns.NetNS) error {
		return errors.New("move device failed")
	}

	cfg := &Config{
		TransitDev: "eth0",
	}
	cs := &cleanupState{}

	_, err := configureTransitDevice(cfg, &netns.NetNS{}, nil, cs)
	if err == nil {
		t.Fatal("expected error")
	}
	if !containsSubstring(err.Error(), "failed to move transit device") {
		t.Errorf("unexpected error: %v", err)
	}
	// Verify cleanupState is properly reset
	if cs.callerNs != nil {
		t.Error("expected callerNs to be nil after cleanup")
	}
}

// --- createMgmtPlanes tests ---

func TestCreateMgmtPlanesNoExtracts(t *testing.T) {
	cfg := &Config{
		MgmtExtracts: nil, // No mgmt extracts
	}
	cs := &cleanupState{}

	mgmtPlanes, err := createMgmtPlanes(cfg, nil, nil, cs)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(mgmtPlanes) != 0 {
		t.Errorf("expected 0 mgmt planes, got %d", len(mgmtPlanes))
	}
}

func TestCreateMgmtPlanesGetNsError(t *testing.T) {
	defer resetDeps()

	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return nil, errors.New("ns not found")
	}

	me, _ := ParseMgmtExtract("mgmt-ns:mgmt-dev:10.0.0.1/24")
	cfg := &Config{
		Name:         "sw0",
		MgmtExtracts: []*MgmtExtract{me},
	}
	cs := &cleanupState{}

	_, err := createMgmtPlanes(cfg, nil, nil, cs)
	if err == nil {
		t.Fatal("expected error")
	}
	if !containsSubstring(err.Error(), "failed to get mgmt netns") {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- createPortVethPairs tests ---

// mockBPFObjects creates a mock bpf.Objects with non-nil Programs for testing
func mockBPFObjects() *bpf.Objects {
	return &bpf.Objects{
		Maps: &bpf.Maps{
			// These will be nil ebpf.Map but the struct is non-nil
			// Tests that call functions using these maps must mock the
			// corresponding function variables.
		},
		Programs: &bpf.Programs{
			// These will be nil ebpf.Program but the struct is non-nil
			IngressNX:      nil,
			IngressMX:      nil,
			IngressTransit: nil,
		},
	}
}

func TestCreatePortVethPairsSuccess(t *testing.T) {
	defer resetDeps()

	// Mock netnsDoFn to execute the function directly
	netnsDoFn = func(ns *netns.NetNS, f func() error) error {
		return f()
	}

	// Track veth creation
	var createdSpecs []netlink.VethSpec
	netlinkCreateVethPairs = func(specs []netlink.VethSpec) error {
		createdSpecs = specs
		return nil
	}

	// Mock clsact with block and link lookup
	portIndex := 0
	netlinkLinkByName = func(name string) (netlink.Link, error) {
		idx := 100 + portIndex
		portIndex++
		return &vnl.Dummy{LinkAttrs: vnl.LinkAttrs{Name: name, Index: idx}}, nil
	}
	netlinkAddClsactWithBlock = func(ifIndex int, blockIndex uint32) error {
		return nil
	}

	cfg := &Config{
		Name:     "sw0",
		NumPorts: 3,
		MTU:      1500,
		MACAddr:  net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		PortMAC:  PortMACFixed(net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}),
	}

	// Create mock port ns with Handle() method
	mockPortNs := &netns.NetNS{}

	ifindexes, err := createPortVethPairs(cfg, &netns.NetNS{}, mockPortNs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify veth specs
	if len(createdSpecs) != 3 {
		t.Errorf("expected 3 veth specs, got %d", len(createdSpecs))
	}

	// Verify ifindexes
	if len(ifindexes) != 3 {
		t.Fatalf("expected 3 ifindexes, got %d", len(ifindexes))
	}
	for i, idx := range ifindexes {
		expected := 100 + i
		if idx != expected {
			t.Errorf("ifindex %d: expected %d, got %d", i, expected, idx)
		}
	}
}

func TestCreatePortVethPairsVethCreationError(t *testing.T) {
	defer resetDeps()

	netnsDoFn = func(ns *netns.NetNS, f func() error) error {
		return f()
	}

	netlinkCreateVethPairs = func(specs []netlink.VethSpec) error {
		return errors.New("veth creation failed")
	}

	cfg := &Config{
		Name:     "sw0",
		NumPorts: 3,
		MACAddr:  net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
	}

	_, err := createPortVethPairs(cfg, &netns.NetNS{}, &netns.NetNS{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !containsSubstring(err.Error(), "failed to create veth pairs") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCreatePortVethPairsTCAttachError(t *testing.T) {
	defer resetDeps()

	netnsDoFn = func(ns *netns.NetNS, f func() error) error {
		return f()
	}

	netlinkCreateVethPairs = func(specs []netlink.VethSpec) error {
		return nil
	}

	callCount := 0
	netlinkLinkByName = func(name string) (netlink.Link, error) {
		callCount++
		return &vnl.Dummy{LinkAttrs: vnl.LinkAttrs{Name: name, Index: callCount * 10}}, nil
	}
	netlinkAddClsactWithBlock = func(ifIndex int, blockIndex uint32) error {
		if callCount == 2 {
			return errors.New("clsact add failed")
		}
		return nil
	}

	cfg := &Config{
		Name:     "sw0",
		NumPorts: 3,
		MACAddr:  net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
	}

	_, err := createPortVethPairs(cfg, &netns.NetNS{}, &netns.NetNS{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !containsSubstring(err.Error(), "failed to configure ports") {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- createMgmtPlanes tests ---

func TestCreateMgmtPlanesSuccess(t *testing.T) {
	defer resetDeps()

	// Mock namespace operations
	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	netnsDoFn = func(ns *netns.NetNS, f func() error) error {
		return f()
	}

	// Track CreateVethPairs call
	var createdSpecs []netlink.VethSpec
	netlinkCreateVethPairs = func(specs []netlink.VethSpec) error {
		createdSpecs = append(createdSpecs, specs...)
		return nil
	}
	netlinkAttachTC = func(name string, prog *ebpf.Program, dir netlink.Direction) error {
		return nil
	}
	netlinkSetLinkUp = func(name string) error {
		return nil
	}
	netlinkAddAddr = func(name string, addr *net.IPNet) error {
		return nil
	}
	netlinkAddDeviceRoute = func(name string, dst *net.IPNet, metric int) error {
		return nil
	}
	netlinkGetLinkIndexInNs = func(ns netlink.NetNS, name string) (int, error) {
		return 300, nil
	}

	// Setup config with mgmt extracts
	me, _ := ParseMgmtExtract("mgmt-ns:mgmt-dev:169.254.169.254/32")
	cfg := &Config{
		Name:         "sw0",
		NumPorts:     4,
		MTU:          1500,
		MACAddr:      net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		MgmtExtracts: []*MgmtExtract{me},
	}

	cs := &cleanupState{}

	mgmtPlanes, err := createMgmtPlanes(cfg, &netns.NetNS{}, mockBPFObjects(), cs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify mgmt planes
	if len(mgmtPlanes) != 1 {
		t.Fatalf("expected 1 mgmt plane, got %d", len(mgmtPlanes))
	}
	if mgmtPlanes[0].MgmtNetNS != "mgmt-ns" {
		t.Errorf("expected MgmtNetNS=mgmt-ns, got %s", mgmtPlanes[0].MgmtNetNS)
	}
	if mgmtPlanes[0].MgmtDev != "mgmt-dev" {
		t.Errorf("expected MgmtDev=mgmt-dev, got %s", mgmtPlanes[0].MgmtDev)
	}

	// Verify CreateVethPairs was called with correct spec
	if len(createdSpecs) != 1 {
		t.Fatalf("expected 1 veth spec, got %d", len(createdSpecs))
	}
	if createdSpecs[0].MTU != 1500 {
		t.Errorf("expected MTU 1500, got %d", createdSpecs[0].MTU)
	}
	if createdSpecs[0].Group != MgmtLinkGroup {
		t.Errorf("expected group %d, got %d", MgmtLinkGroup, createdSpecs[0].Group)
	}

	// Verify cleanup state tracks mgmt ifindexes
	if len(cs.mgmtIfindexes) != 1 {
		t.Errorf("expected 1 mgmt ifindex, got %d", len(cs.mgmtIfindexes))
	}
	if len(cs.mgmtIfindexes) > 0 && cs.mgmtIfindexes[0] != 300 {
		t.Errorf("expected mgmt ifindex 300, got %d", cs.mgmtIfindexes[0])
	}
}

func TestCreateMgmtPlanesCreateVethError(t *testing.T) {
	defer resetDeps()

	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	netnsDoFn = func(ns *netns.NetNS, f func() error) error {
		return f()
	}
	netlinkCreateVethPairs = func(specs []netlink.VethSpec) error {
		return errors.New("create veth failed")
	}

	me, _ := ParseMgmtExtract("mgmt-ns:mgmt-dev:10.0.0.1/24")
	cfg := &Config{
		Name:         "sw0",
		MACAddr:      net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		MgmtExtracts: []*MgmtExtract{me},
	}
	cs := &cleanupState{}

	_, err := createMgmtPlanes(cfg, &netns.NetNS{}, nil, cs)
	if err == nil {
		t.Fatal("expected error")
	}
	if !containsSubstring(err.Error(), "failed to create mgmt veth pair") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCreateMgmtPlanesAttachTCError(t *testing.T) {
	defer resetDeps()

	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	netnsDoFn = func(ns *netns.NetNS, f func() error) error {
		return f()
	}
	netlinkCreateVethPairs = func(specs []netlink.VethSpec) error {
		return nil
	}
	netlinkGetLinkIndexInNs = func(ns netlink.NetNS, name string) (int, error) {
		return 300, nil
	}
	netlinkAttachTC = func(name string, prog *ebpf.Program, dir netlink.Direction) error {
		return errors.New("TC attach failed")
	}

	me, _ := ParseMgmtExtract("mgmt-ns:mgmt-dev:10.0.0.1/24")
	cfg := &Config{
		Name:         "sw0",
		MTU:          1500,
		MACAddr:      net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		MgmtExtracts: []*MgmtExtract{me},
	}
	cs := &cleanupState{}

	_, err := createMgmtPlanes(cfg, &netns.NetNS{}, mockBPFObjects(), cs)
	if err == nil {
		t.Fatal("expected error")
	}
	if !containsSubstring(err.Error(), "failed to attach TC") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCreateMgmtPlanesConfigureDeviceError(t *testing.T) {
	defer resetDeps()

	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	netnsDoFn = func(ns *netns.NetNS, f func() error) error {
		return f()
	}
	netlinkCreateVethPairs = func(specs []netlink.VethSpec) error {
		return nil
	}
	netlinkGetLinkIndexInNs = func(ns netlink.NetNS, name string) (int, error) {
		return 300, nil
	}
	netlinkAttachTC = func(name string, prog *ebpf.Program, dir netlink.Direction) error {
		return nil
	}
	netlinkSetLinkUp = func(name string) error {
		return errors.New("bring up failed")
	}

	me, _ := ParseMgmtExtract("mgmt-ns:mgmt-dev:10.0.0.1/24")
	cfg := &Config{
		Name:         "sw0",
		MTU:          1500,
		MACAddr:      net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		MgmtExtracts: []*MgmtExtract{me},
	}
	cs := &cleanupState{}

	_, err := createMgmtPlanes(cfg, &netns.NetNS{}, mockBPFObjects(), cs)
	if err == nil {
		t.Fatal("expected error")
	}
	if !containsSubstring(err.Error(), "failed to configure") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCreateMgmtPlanesNoMTU(t *testing.T) {
	defer resetDeps()

	// Test path where MTU is 0 (VethSpec.MTU = 0, CreateVethPairs uses default)
	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	netnsDoFn = func(ns *netns.NetNS, f func() error) error {
		return f()
	}

	var createdMTU int
	netlinkCreateVethPairs = func(specs []netlink.VethSpec) error {
		if len(specs) > 0 {
			createdMTU = specs[0].MTU
		}
		return nil
	}
	netlinkAttachTC = func(name string, prog *ebpf.Program, dir netlink.Direction) error {
		return nil
	}
	netlinkSetLinkUp = func(name string) error {
		return nil
	}
	netlinkAddAddr = func(name string, addr *net.IPNet) error {
		return nil
	}
	netlinkAddDeviceRoute = func(name string, dst *net.IPNet, metric int) error {
		return nil
	}
	netlinkGetLinkIndexInNs = func(ns netlink.NetNS, name string) (int, error) {
		return 300, nil
	}

	me, _ := ParseMgmtExtract("mgmt-ns:mgmt-dev:10.0.0.1/24")
	cfg := &Config{
		Name:         "sw0",
		NumPorts:     1,
		MTU:          0, // No MTU
		MACAddr:      net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		MgmtExtracts: []*MgmtExtract{me},
	}
	cs := &cleanupState{}

	_, err := createMgmtPlanes(cfg, &netns.NetNS{}, mockBPFObjects(), cs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if createdMTU != 0 {
		t.Errorf("expected MTU 0 in VethSpec when cfg.MTU is 0, got %d", createdMTU)
	}
}

// --- configureTransitDevice tests ---

func TestConfigureTransitDeviceSuccess(t *testing.T) {
	defer resetDeps()

	netnsGetCurrent = func() (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	netnsMoveDevice = func(devName string, fromNs, toNs *netns.NetNS) error {
		return nil
	}
	netnsDoFn = func(ns *netns.NetNS, f func() error) error {
		return f()
	}
	netlinkSetMTU = func(name string, mtu int) error {
		return nil
	}
	netlinkSetLinkUp = func(name string) error {
		return nil
	}
	netlinkAddAddr = func(name string, addr *net.IPNet) error {
		return nil
	}
	netlinkAttachTC = func(name string, prog *ebpf.Program, dir netlink.Direction) error {
		return nil
	}
	netlinkGetLinkIndexInNs = func(ns netlink.NetNS, name string) (int, error) {
		return 300, nil
	}

	cfg := &Config{
		Name:          "sw0",
		NumPorts:      2,
		TransitDev:    "eth0",
		TransitDevMTU: 9000,
		TransitAddr:   &net.IPNet{IP: net.ParseIP("192.168.1.100"), Mask: net.CIDRMask(24, 32)},
	}
	cs := &cleanupState{}

	transitIP, err := configureTransitDevice(cfg, &netns.NetNS{}, mockBPFObjects(), cs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify transit IP returned
	if transitIP != "192.168.1.100" {
		t.Errorf("expected transit IP 192.168.1.100, got %s", transitIP)
	}

	// Verify cleanup state
	if !cs.transitMoved {
		t.Error("expected transitMoved to be true")
	}
	if cs.transitDevName != "eth0" {
		t.Errorf("expected transitDevName eth0, got %s", cs.transitDevName)
	}
}

func TestConfigureTransitDeviceSetMTUError(t *testing.T) {
	defer resetDeps()

	netnsGetCurrent = func() (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	netnsMoveDevice = func(devName string, fromNs, toNs *netns.NetNS) error {
		return nil
	}
	netnsDoFn = func(ns *netns.NetNS, f func() error) error {
		return f()
	}
	netlinkSetMTU = func(name string, mtu int) error {
		return errors.New("set MTU failed")
	}

	cfg := &Config{
		TransitDev:    "eth0",
		TransitDevMTU: 9000,
	}
	cs := &cleanupState{}

	_, err := configureTransitDevice(cfg, &netns.NetNS{}, mockBPFObjects(), cs)
	if err == nil {
		t.Fatal("expected error")
	}
	if !containsSubstring(err.Error(), "failed to configure transit device") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestConfigureTransitDeviceSetLinkUpError(t *testing.T) {
	defer resetDeps()

	netnsGetCurrent = func() (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	netnsMoveDevice = func(devName string, fromNs, toNs *netns.NetNS) error {
		return nil
	}
	netnsDoFn = func(ns *netns.NetNS, f func() error) error {
		return f()
	}
	netlinkSetMTU = func(name string, mtu int) error {
		return nil
	}
	netlinkSetLinkUp = func(name string) error {
		return errors.New("link up failed")
	}

	cfg := &Config{
		TransitDev:    "eth0",
		TransitDevMTU: 9000,
	}
	cs := &cleanupState{}

	_, err := configureTransitDevice(cfg, &netns.NetNS{}, mockBPFObjects(), cs)
	if err == nil {
		t.Fatal("expected error")
	}
	if !containsSubstring(err.Error(), "failed to configure transit device") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestConfigureTransitDeviceAttachTCError(t *testing.T) {
	defer resetDeps()

	netnsGetCurrent = func() (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	netnsMoveDevice = func(devName string, fromNs, toNs *netns.NetNS) error {
		return nil
	}
	netnsDoFn = func(ns *netns.NetNS, f func() error) error {
		return f()
	}
	netlinkSetMTU = func(name string, mtu int) error {
		return nil
	}
	netlinkSetLinkUp = func(name string) error {
		return nil
	}
	netlinkAttachTC = func(name string, prog *ebpf.Program, dir netlink.Direction) error {
		return errors.New("TC attach failed")
	}

	cfg := &Config{
		TransitDev:    "eth0",
		TransitDevMTU: 9000,
	}
	cs := &cleanupState{}

	_, err := configureTransitDevice(cfg, &netns.NetNS{}, mockBPFObjects(), cs)
	if err == nil {
		t.Fatal("expected error")
	}
	if !containsSubstring(err.Error(), "failed to configure transit device") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestConfigureTransitDeviceNoMTU(t *testing.T) {
	defer resetDeps()

	// Test path where TransitDevMTU is 0 (skip MTU setting)
	mtuCalled := false
	netnsGetCurrent = func() (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	netnsMoveDevice = func(devName string, fromNs, toNs *netns.NetNS) error {
		return nil
	}
	netnsDoFn = func(ns *netns.NetNS, f func() error) error {
		return f()
	}
	netlinkSetMTU = func(name string, mtu int) error {
		mtuCalled = true
		return nil
	}
	netlinkSetLinkUp = func(name string) error {
		return nil
	}
	netlinkAttachTC = func(name string, prog *ebpf.Program, dir netlink.Direction) error {
		return nil
	}
	netlinkGetLinkIndexInNs = func(ns netlink.NetNS, name string) (int, error) {
		return 300, nil
	}

	cfg := &Config{
		Name:          "sw0",
		NumPorts:      1,
		TransitDev:    "eth0",
		TransitDevMTU: 0, // No MTU
	}
	cs := &cleanupState{}

	_, err := configureTransitDevice(cfg, &netns.NetNS{}, mockBPFObjects(), cs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if mtuCalled {
		t.Error("MTU should not be set when TransitDevMTU is 0")
	}
}

func TestConfigureTransitDeviceNoAddress(t *testing.T) {
	defer resetDeps()

	// Test path where TransitAddr is nil
	netnsGetCurrent = func() (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	netnsMoveDevice = func(devName string, fromNs, toNs *netns.NetNS) error {
		return nil
	}
	netnsDoFn = func(ns *netns.NetNS, f func() error) error {
		return f()
	}
	netlinkSetLinkUp = func(name string) error {
		return nil
	}
	netlinkAttachTC = func(name string, prog *ebpf.Program, dir netlink.Direction) error {
		return nil
	}
	netlinkGetLinkIndexInNs = func(ns netlink.NetNS, name string) (int, error) {
		return 300, nil
	}

	cfg := &Config{
		Name:        "sw0",
		NumPorts:    1,
		TransitDev:  "eth0",
		TransitAddr: nil, // No address
	}
	cs := &cleanupState{}

	transitIP, err := configureTransitDevice(cfg, &netns.NetNS{}, mockBPFObjects(), cs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should return empty IP when no address configured
	if transitIP != "" {
		t.Errorf("expected empty transit IP, got %s", transitIP)
	}
}

// --- validateMTUSlowPath additional tests ---

func TestValidateMTUSlowPathAutoMode(t *testing.T) {
	defer resetDeps()

	netlinkGetMTUInNs = func(ns netlink.NetNS, name string) (int, error) {
		return 1500, nil
	}

	cfg := &Config{
		Name:              "sw0",
		MTU:               0, // Trigger slow path
		TransitDev:        "eth0",
		TransitDevMTUAuto: true, // Auto mode
		NumPorts:          2,
	}

	err := validateMTUSlowPath(cfg, &netns.NetNS{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Auto mode should calculate TransitDevMTU = portMTU + overhead
	expectedMTU := 1500 + GeneveIPOverhead
	if cfg.TransitDevMTU != expectedMTU {
		t.Errorf("expected TransitDevMTU=%d, got %d", expectedMTU, cfg.TransitDevMTU)
	}
}

func TestValidateMTUSlowPathExplicitMTUSufficient(t *testing.T) {
	defer resetDeps()

	netlinkGetMTUInNs = func(ns netlink.NetNS, name string) (int, error) {
		return 1500, nil
	}

	cfg := &Config{
		Name:          "sw0",
		MTU:           0,
		TransitDev:    "eth0",
		TransitDevMTU: 1500 + GeneveIPOverhead + 100, // Sufficient
		NumPorts:      2,
	}

	err := validateMTUSlowPath(cfg, &netns.NetNS{})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateMTUSlowPathExplicitMTUTooSmall(t *testing.T) {
	defer resetDeps()

	netlinkGetMTUInNs = func(ns netlink.NetNS, name string) (int, error) {
		return 1500, nil
	}

	cfg := &Config{
		Name:          "sw0",
		MTU:           0,
		TransitDev:    "eth0",
		TransitDevMTU: 1500, // Too small - missing overhead
		NumPorts:      2,
	}

	err := validateMTUSlowPath(cfg, &netns.NetNS{})
	if err == nil {
		t.Fatal("expected error for explicit MTU too small")
	}
	if !containsSubstring(err.Error(), "too small") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateMTUSlowPathValidateExistingMTU(t *testing.T) {
	defer resetDeps()

	netlinkGetMTUInNs = func(ns netlink.NetNS, name string) (int, error) {
		return 1500, nil
	}
	netnsGetCurrent = func() (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}

	cfg := &Config{
		Name:          "sw0",
		MTU:           0,
		TransitDev:    "eth0",
		TransitDevMTU: 0, // Not setting - validate existing
		NumPorts:      2,
	}

	err := validateMTUSlowPath(cfg, &netns.NetNS{})
	if err == nil {
		t.Fatal("expected error for existing MTU too small")
	}
	if !containsSubstring(err.Error(), "too small") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateMTUSlowPathValidateExistingMTUSufficient(t *testing.T) {
	defer resetDeps()

	// Port MTU = 1500
	netlinkGetMTUInNs = func(ns netlink.NetNS, name string) (int, error) {
		return 1500, nil
	}
	netnsGetCurrent = func() (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}

	// Mock getTransitDeviceMTU calls - need to return sufficient MTU
	mtuCallCount := 0
	origNetlinkGetMTUInNs := netlinkGetMTUInNs
	netlinkGetMTUInNs = func(ns netlink.NetNS, name string) (int, error) {
		mtuCallCount++
		// Calls 1-2 are for port devices (return 1500)
		// Call 3+ would be for transit device in getTransitDeviceMTU
		if mtuCallCount <= 2 {
			return 1500, nil
		}
		// Transit device has sufficient MTU
		return 1500 + GeneveIPOverhead + 100, nil
	}
	defer func() { netlinkGetMTUInNs = origNetlinkGetMTUInNs }()

	cfg := &Config{
		Name:          "sw0",
		MTU:           0,
		TransitDev:    "eth0",
		TransitDevMTU: 0, // Not setting - validate existing
		NumPorts:      2,
	}

	err := validateMTUSlowPath(cfg, &netns.NetNS{})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateMTUSlowPathGetTransitMTUError(t *testing.T) {
	defer resetDeps()

	callCount := 0
	netlinkGetMTUInNs = func(ns netlink.NetNS, name string) (int, error) {
		callCount++
		// Port device calls succeed
		if callCount <= 2 {
			return 1500, nil
		}
		// Transit device MTU lookup fails
		return 0, errors.New("get transit MTU failed")
	}
	netnsGetCurrent = func() (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}

	cfg := &Config{
		Name:          "sw0",
		MTU:           0,
		TransitDev:    "eth0",
		TransitDevMTU: 0, // Not setting - validate existing
		NumPorts:      2,
	}

	err := validateMTUSlowPath(cfg, &netns.NetNS{})
	if err == nil {
		t.Fatal("expected error for get transit MTU failure")
	}
	if !containsSubstring(err.Error(), "failed to get MTU") {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- configureTransitDevice DHCP tests ---

func TestConfigureTransitDeviceDHCPError(t *testing.T) {
	defer resetDeps()

	netnsGetCurrent = func() (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	netnsMoveDevice = func(devName string, fromNs, toNs *netns.NetNS) error {
		return nil
	}
	netnsDoFn = func(ns *netns.NetNS, f func() error) error {
		return f()
	}
	netlinkSetLinkUp = func(name string) error {
		return nil
	}
	dhcpRequest = func(ctx context.Context, opts dhcp.RequestOptions) (*dhcp.Lease, error) {
		return nil, errors.New("DHCP request failed")
	}

	cfg := &Config{
		Name:            "sw0",
		NumPorts:        1,
		TransitDev:      "eth0",
		TransitAddrAuto: true, // Trigger DHCP path
	}
	cs := &cleanupState{}

	_, err := configureTransitDevice(cfg, &netns.NetNS{}, mockBPFObjects(), cs)
	if err == nil {
		t.Fatal("expected error for DHCP failure")
	}
	if !containsSubstring(err.Error(), "DHCP failed") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestConfigureTransitDeviceDHCPSuccess(t *testing.T) {
	defer resetDeps()

	netnsGetCurrent = func() (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	netnsMoveDevice = func(devName string, fromNs, toNs *netns.NetNS) error {
		return nil
	}
	netnsDoFn = func(ns *netns.NetNS, f func() error) error {
		return f()
	}
	netlinkSetLinkUp = func(name string) error {
		return nil
	}
	dhcpRequest = func(ctx context.Context, opts dhcp.RequestOptions) (*dhcp.Lease, error) {
		return &dhcp.Lease{
			IP:        net.ParseIP("192.168.1.100"),
			Netmask:   net.CIDRMask(24, 32),
			PrefixLen: 24,
			Gateway:   net.ParseIP("192.168.1.1"),
		}, nil
	}
	netlinkAddAddr = func(name string, addr *net.IPNet) error {
		return nil
	}
	netlinkAttachTC = func(name string, prog *ebpf.Program, dir netlink.Direction) error {
		return nil
	}
	netlinkGetLinkIndexInNs = func(ns netlink.NetNS, name string) (int, error) {
		return 300, nil
	}
	updateSwitchConfigFieldsFn = func(configMap BPFMap, update func(*SwitchConfig)) error {
		return nil
	}
	updateSwitchMetadataFieldsFn = func(metadataMap BPFMap, update func(*SwitchMetadata)) error {
		return nil
	}

	cfg := &Config{
		Name:            "sw0",
		NumPorts:        1,
		TransitDev:      "eth0",
		TransitAddrAuto: true, // Trigger DHCP path
	}
	cs := &cleanupState{}

	transitIP, err := configureTransitDevice(cfg, &netns.NetNS{}, mockBPFObjects(), cs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify DHCP address was applied
	if transitIP != "192.168.1.100" {
		t.Errorf("expected transit IP 192.168.1.100, got %s", transitIP)
	}
	if cfg.TransitAddr == nil {
		t.Error("expected TransitAddr to be set from DHCP")
	}
	if cfg.TransitNexthop == nil {
		t.Error("expected TransitNexthop to be set from DHCP")
	}
}

func TestConfigureTransitDeviceAddAddrError(t *testing.T) {
	defer resetDeps()

	netnsGetCurrent = func() (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	netnsMoveDevice = func(devName string, fromNs, toNs *netns.NetNS) error {
		return nil
	}
	netnsDoFn = func(ns *netns.NetNS, f func() error) error {
		return f()
	}
	netlinkSetLinkUp = func(name string) error {
		return nil
	}
	// AddAddr fails - should be ignored (EEXIST or similar)
	netlinkAddAddr = func(name string, addr *net.IPNet) error {
		return errors.New("address already exists")
	}
	netlinkAttachTC = func(name string, prog *ebpf.Program, dir netlink.Direction) error {
		return nil
	}
	netlinkGetLinkIndexInNs = func(ns netlink.NetNS, name string) (int, error) {
		return 300, nil
	}

	cfg := &Config{
		Name:        "sw0",
		NumPorts:    1,
		TransitDev:  "eth0",
		TransitAddr: &net.IPNet{IP: net.ParseIP("192.168.1.100"), Mask: net.CIDRMask(24, 32)},
	}
	cs := &cleanupState{}

	// Should succeed even though AddAddr failed (error is ignored)
	transitIP, err := configureTransitDevice(cfg, &netns.NetNS{}, mockBPFObjects(), cs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if transitIP != "192.168.1.100" {
		t.Errorf("expected transit IP 192.168.1.100, got %s", transitIP)
	}
}

// --- createMgmtPlanes additional tests ---

func TestCreateMgmtPlanesBringUpError(t *testing.T) {
	defer resetDeps()

	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	netnsDoFn = func(ns *netns.NetNS, f func() error) error {
		return f()
	}
	netlinkCreateVethPairs = func(specs []netlink.VethSpec) error {
		return nil
	}
	netlinkGetLinkIndexInNs = func(ns netlink.NetNS, name string) (int, error) {
		return 300, nil
	}
	netlinkAttachTC = func(name string, prog *ebpf.Program, dir netlink.Direction) error {
		return nil
	}
	netlinkSetLinkUp = func(name string) error {
		return errors.New("bring up failed")
	}

	me, _ := ParseMgmtExtract("mgmt-ns:mgmt-dev:10.0.0.1/24")
	cfg := &Config{
		Name:         "sw0",
		MTU:          1500,
		MACAddr:      net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		MgmtExtracts: []*MgmtExtract{me},
	}
	cs := &cleanupState{}

	_, err := createMgmtPlanes(cfg, &netns.NetNS{}, mockBPFObjects(), cs)
	if err == nil {
		t.Fatal("expected error for bring up failure")
	}
	if !containsSubstring(err.Error(), "bring up") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCreateMgmtPlanesAddAddrError(t *testing.T) {
	defer resetDeps()

	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	netnsDoFn = func(ns *netns.NetNS, f func() error) error {
		return f()
	}
	netlinkCreateVethPairs = func(specs []netlink.VethSpec) error {
		return nil
	}
	netlinkGetLinkIndexInNs = func(ns netlink.NetNS, name string) (int, error) {
		return 300, nil
	}
	netlinkAttachTC = func(name string, prog *ebpf.Program, dir netlink.Direction) error {
		return nil
	}
	netlinkSetLinkUp = func(name string) error {
		return nil
	}
	netlinkAddAddr = func(name string, addr *net.IPNet) error {
		return errors.New("add addr failed")
	}

	me, _ := ParseMgmtExtract("mgmt-ns:mgmt-dev:10.0.0.1/24")
	cfg := &Config{
		Name:         "sw0",
		MTU:          1500,
		MACAddr:      net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		MgmtExtracts: []*MgmtExtract{me},
	}
	cs := &cleanupState{}

	_, err := createMgmtPlanes(cfg, &netns.NetNS{}, mockBPFObjects(), cs)
	if err == nil {
		t.Fatal("expected error for add addr failure")
	}
	if !containsSubstring(err.Error(), "add addr") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCreateMgmtPlanesAddReturnRouteError(t *testing.T) {
	defer resetDeps()

	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	netnsDoFn = func(ns *netns.NetNS, f func() error) error {
		return f()
	}
	netlinkCreateVethPairs = func(specs []netlink.VethSpec) error {
		return nil
	}
	netlinkGetLinkIndexInNs = func(ns netlink.NetNS, name string) (int, error) {
		return 300, nil
	}
	netlinkAttachTC = func(name string, prog *ebpf.Program, dir netlink.Direction) error {
		return nil
	}
	netlinkSetLinkUp = func(name string) error {
		return nil
	}
	netlinkAddAddr = func(name string, addr *net.IPNet) error {
		return nil
	}
	netlinkAddDeviceRoute = func(name string, dst *net.IPNet, metric int) error {
		return errors.New("route add failed")
	}

	me, _ := ParseMgmtExtract("mgmt-ns:mgmt-dev:10.0.0.1/24")
	cfg := &Config{
		Name:           "sw0",
		MTU:            1500,
		MACAddr:        net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		FloatingIPBase: net.ParseIP("100.100.96.0"),
		MgmtExtracts:   []*MgmtExtract{me},
	}
	cs := &cleanupState{}

	_, err := createMgmtPlanes(cfg, &netns.NetNS{}, mockBPFObjects(), cs)
	if err == nil {
		t.Fatal("expected error for add return route failure")
	}
	if !containsSubstring(err.Error(), "add return route") {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- floatingReturnNets tests ---

func TestFloatingReturnNets(t *testing.T) {
	tests := []struct {
		name string
		base net.IP
		want []string
	}{
		{"nil base", nil, nil},
		{"ipv6 base", net.ParseIP("fd00::1"), nil},
		{"aligned", net.ParseIP("100.100.96.0"), []string{"100.100.96.0/20"}},
		{"unaligned spans two /20", net.ParseIP("100.100.97.5"), []string{"100.100.96.0/20", "100.100.112.0/20"}},
		{"straddle block boundary", net.ParseIP("100.100.95.255"), []string{"100.100.80.0/20", "100.100.96.0/20"}},
		{"overflow near top of space", net.ParseIP("255.255.255.0"), []string{"255.255.240.0/20"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := floatingReturnNets(tt.base)
			if len(got) != len(tt.want) {
				t.Fatalf("got %d nets %v, want %d %v", len(got), got, len(tt.want), tt.want)
			}
			for i, n := range got {
				if n.String() != tt.want[i] {
					t.Errorf("net[%d] = %s, want %s", i, n.String(), tt.want[i])
				}
			}
		})
	}
}

// --- resolveTransitMTU tests ---

func TestResolveTransitMTUAuto(t *testing.T) {
	cfg := &Config{
		TransitDev:        "eth0",
		TransitDevMTUAuto: true,
	}
	err := resolveTransitMTU(cfg, 1500)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := 1500 + GeneveIPOverhead
	if cfg.TransitDevMTU != expected {
		t.Errorf("TransitDevMTU = %d, want %d", cfg.TransitDevMTU, expected)
	}
}

func TestResolveTransitMTUAutoEthEncap(t *testing.T) {
	cfg := &Config{
		TransitDev:        "eth0",
		TransitDevMTUAuto: true,
		GeneveEncapEth:    true,
	}
	err := resolveTransitMTU(cfg, 1500)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := 1500 + GeneveEthOverhead
	if cfg.TransitDevMTU != expected {
		t.Errorf("TransitDevMTU = %d, want %d", cfg.TransitDevMTU, expected)
	}
}

func TestResolveTransitMTUExplicitOK(t *testing.T) {
	cfg := &Config{
		TransitDev:    "eth0",
		TransitDevMTU: 9000,
	}
	err := resolveTransitMTU(cfg, 1500)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.TransitDevMTU != 9000 {
		t.Errorf("TransitDevMTU should stay 9000, got %d", cfg.TransitDevMTU)
	}
}

func TestResolveTransitMTUExplicitTooSmall(t *testing.T) {
	cfg := &Config{
		TransitDev:    "eth0",
		TransitDevMTU: 100,
	}
	err := resolveTransitMTU(cfg, 1500)
	if err == nil {
		t.Fatal("expected error for too small transit MTU")
	}
	if !containsSubstring(err.Error(), "too small") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestResolveTransitMTUValidateExisting(t *testing.T) {
	defer resetDeps()
	netnsGetCurrent = func() (*netns.NetNS, error) { return &netns.NetNS{}, nil }
	netlinkGetMTUInNs = func(ns netlink.NetNS, name string) (int, error) {
		return 9000, nil
	}

	cfg := &Config{
		TransitDev: "eth0",
	}
	err := resolveTransitMTU(cfg, 1500)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveTransitMTUValidateExistingTooSmall(t *testing.T) {
	defer resetDeps()
	netnsGetCurrent = func() (*netns.NetNS, error) { return &netns.NetNS{}, nil }
	netlinkGetMTUInNs = func(ns netlink.NetNS, name string) (int, error) {
		return 1400, nil
	}

	cfg := &Config{
		TransitDev: "eth0",
	}
	err := resolveTransitMTU(cfg, 1500)
	if err == nil {
		t.Fatal("expected error for existing MTU too small")
	}
	if !containsSubstring(err.Error(), "too small") {
		t.Errorf("unexpected error: %v", err)
	}
}
