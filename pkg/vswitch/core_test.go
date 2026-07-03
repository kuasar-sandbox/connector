package vswitch

import (
	"errors"
	"net"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
	vnetlink "github.com/vishvananda/netlink"

	"github.com/kuasar-sandbox/connector/pkg/internal/bpf"
	"github.com/kuasar-sandbox/connector/pkg/netlink"
	"github.com/kuasar-sandbox/connector/pkg/netns"
)

// mockBPFMapWithError is a mock BPFMap that returns an error on Lookup
type mockBPFMapWithError struct {
	err error
}

func (m *mockBPFMapWithError) Lookup(key, valueOut interface{}) error {
	return m.err
}

func (m *mockBPFMapWithError) Update(key, value interface{}, flags ebpf.MapUpdateFlags) error {
	return m.err
}

func (m *mockBPFMapWithError) Delete(key interface{}) error {
	return m.err
}

// mockBPFMapWithSlot is a mock BPFMap that returns zero slot data (empty slots)
type mockBPFMapWithSlot struct{}

func (m *mockBPFMapWithSlot) Lookup(key, valueOut interface{}) error {
	// Leave valueOut as zero value (empty slot)
	return nil
}

func (m *mockBPFMapWithSlot) Update(key, value interface{}, flags ebpf.MapUpdateFlags) error {
	return nil
}

func (m *mockBPFMapWithSlot) Delete(key interface{}) error {
	return nil
}

// mockBPFArrayMapForTest is a mock BPFArrayMap for testing NewMmappedSlots.
type mockBPFArrayMapForTest struct{}

func (m *mockBPFArrayMapForTest) FD() int            { return 0 }
func (m *mockBPFArrayMapForTest) ValueSize() uint32  { return 256 }
func (m *mockBPFArrayMapForTest) MaxEntries() uint32 { return 256 }

// mockStatsMap is a mock BPFMap that returns slot stats.
type mockStatsMap struct {
	stats map[uint32]*SlotStats
}

func newMockStatsMap() *mockStatsMap {
	return &mockStatsMap{stats: make(map[uint32]*SlotStats)}
}

func (m *mockStatsMap) Lookup(key, valueOut interface{}) error {
	slotID := key.(uint32)
	if s, ok := m.stats[slotID]; ok {
		if out, ok := valueOut.(*SlotStats); ok {
			*out = *s
			return nil
		}
	}
	return syscall.ENOENT // standard error for missing key
}

func (m *mockStatsMap) Update(key, value interface{}, flags ebpf.MapUpdateFlags) error {
	return nil
}

func (m *mockStatsMap) Delete(key interface{}) error {
	return nil
}

// mockStartControlDeps sets up the bpfEnsureBPFFS, acquireControlLockFn,
// and shared block mocks that are needed by Start/StartReserved/Stop/ProvisionPorts.
func mockStartControlDeps() {
	bpfEnsureBPFFS = func() error { return nil }
	acquireControlLockFn = func(switchName string) (*ControlLock, error) {
		return &ControlLock{}, nil
	}
	netnsDoFn = func(ns *netns.NetNS, f func() error) error { return f() }
	netlinkCreateDummyLink = func(name string) error { return nil }
	netlinkAddClsactWithBlock = func(ifIndex int, blockIndex uint32) error { return nil }
	netlinkAddBlockFilter = func(blockIndex uint32, prog *ebpf.Program) error { return nil }
	netlinkDeleteLinkByNameInNs = func(ns netlink.NetNS, name string) error { return nil }
	netlinkLinkByName = func(name string) (netlink.Link, error) {
		return &vnetlink.Dummy{LinkAttrs: vnetlink.LinkAttrs{Index: 100}}, nil
	}
}

// Start/StartReserved function tests are in start_test.go
// Stop function tests are in stop_test.go

// --- Status function tests ---

func TestStatusSwitchNotExist(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return false, nil
	}

	_, err := Status("sw0")
	if err == nil {
		t.Fatal("expected error for non-existent switch")
	}
	if !IsNotExist(err) {
		t.Errorf("expected ErrSwitchNotExist, got: %v", err)
	}
}

func TestStatusLoadPinnedMapsError(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return nil, errors.New("load pinned maps failed")
	}

	_, err := Status("sw0")
	if err == nil {
		t.Fatal("expected error from LoadPinnedMaps")
	}
	if !containsSubstring(err.Error(), "failed to load pinned maps") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStatusSuccess(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: 4}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{}, nil
	}
	// Mock MmappedSlots with empty slots (CountAllocatedSlots returns 0)
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return newMmappedSlotsForTest(numSlots), nil
	}

	output, err := Status("sw0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output.Ports != 4 {
		t.Errorf("expected 4 ports, got %d", output.Ports)
	}
	if output.PortsUsed != 0 {
		t.Errorf("expected 0 used ports, got %d", output.PortsUsed)
	}
	if output.PortsAvailable != 4 {
		t.Errorf("expected 4 available ports, got %d", output.PortsAvailable)
	}
}

func TestInterfaceNameAndConfig(t *testing.T) {
	defer resetDeps()

	expectedCfg := &SwitchConfig{N_ports: 8}
	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return expectedCfg, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{}, nil
	}
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return newMmappedSlotsForTest(numSlots), nil
	}

	sw, err := Open("test-switch")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer sw.Close()

	// Test Name() method
	if name := sw.Name(); name != "test-switch" {
		t.Errorf("Name() = %q, want %q", name, "test-switch")
	}

	// Test Config() method
	cfg := sw.Config()
	if cfg != expectedCfg {
		t.Errorf("Config() returned unexpected config")
	}
	if cfg.N_ports != 8 {
		t.Errorf("Config().NPorts = %d, want 8", cfg.N_ports)
	}
}

func TestStatusWithNetNSCheckConditions(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: 2}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{SwitchNetNS: "switch_ns"}, nil
	}
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return newMmappedSlotsForTest(numSlots), nil
	}
	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	// Mock checkConditions dependencies
	netnsDoFn = func(ns *netns.NetNS, f func() error) error { return f() }
	netlinkLinkList = func() ([]netlink.Link, error) {
		return []netlink.Link{}, nil
	}
	netlinkHasTCFilter = func(link netlink.Link, direction netlink.Direction) bool { return true }

	output, err := Status("sw0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should have conditions from checkConditions
	if len(output.Conditions) == 0 {
		t.Error("expected conditions to be set")
	}
	// First condition should be Ready
	if output.Conditions[0].Type != ConditionReady {
		t.Errorf("first condition type = %s, want Ready", output.Conditions[0].Type)
	}
}

func TestStatusEmptyNetNS(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		// Empty SwitchNetNS
		return &SwitchConfig{N_ports: 4}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		// Empty SwitchNetNS in metadata
		return &SwitchMetadata{}, nil
	}
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return newMmappedSlotsForTest(numSlots), nil
	}

	output, err := Status("sw0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output.State != "running" {
		t.Errorf("expected state 'running', got %s", output.State)
	}
	if output.Ports != 4 {
		t.Errorf("expected 4 ports, got %d", output.Ports)
	}
	// No conditions should be set when namespace is empty
	if len(output.Conditions) != 0 {
		t.Errorf("expected no conditions, got %d", len(output.Conditions))
	}
}

func TestStatusNetNSNotFound(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: 4}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{SwitchNetNS: "test_ns"}, nil
	}
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return newMmappedSlotsForTest(numSlots), nil
	}
	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return nil, errors.New("ns not found")
	}

	output, err := Status("sw0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should have Unknown condition
	if len(output.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(output.Conditions))
	}
	if output.Conditions[0].Status != ConditionUnknown {
		t.Errorf("expected Unknown status, got %s", output.Conditions[0].Status)
	}
	if output.Conditions[0].Reason != "NamespaceNotFound" {
		t.Errorf("expected reason NamespaceNotFound, got %s", output.Conditions[0].Reason)
	}
}

// --- Attach function tests ---

func TestAttachSwitchNotExist(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return false, nil
	}

	opts := AttachOptions{
		InnerIP: net.ParseIP("10.0.0.1"),
	}
	_, err := Attach("sw0", opts)
	if err == nil {
		t.Fatal("expected error for non-existent switch")
	}
	if !containsSubstring(err.Error(), "does not exist") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAttachLoadPinnedMapsError(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return nil, errors.New("load pinned maps failed")
	}

	opts := AttachOptions{
		InnerIP: net.ParseIP("10.0.0.1"),
	}
	_, err := Attach("sw0", opts)
	if err == nil {
		t.Fatal("expected error from LoadPinnedMaps")
	}
	if !containsSubstring(err.Error(), "failed to load pinned maps") {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- Detach function tests ---

func TestDetachSwitchNotExist(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return false, nil
	}

	err := Detach("sw0", DetachOptions{Port: 1})
	if err == nil {
		t.Fatal("expected error for non-existent switch")
	}
	if !containsSubstring(err.Error(), "does not exist") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDetachInvalidPort(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: 4}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{}, nil
	}
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return newMmappedSlotsForTest(numSlots), nil
	}
	newStatsManagerFn = func(statsMap BPFMap, numPorts uint32) *StatsManager {
		return NewStatsManager(&mockBPFMapWithSlot{}, numPorts)
	}

	err := Detach("sw0", DetachOptions{Port: 0}) // Port 0 is invalid
	if err == nil {
		t.Fatal("expected error for invalid port")
	}
	if !containsSubstring(err.Error(), "port number is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDetachLoadPinnedMapsError(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return nil, errors.New("load pinned maps failed")
	}

	err := Detach("sw0", DetachOptions{Port: 1})
	if err == nil {
		t.Fatal("expected error from LoadPinnedMaps")
	}
	if !containsSubstring(err.Error(), "failed to load pinned maps") {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- Stats function tests ---

func TestStatsSwitchNotExist(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return false, nil
	}

	_, err := Stats("sw0", nil)
	if err == nil {
		t.Fatal("expected error for non-existent switch")
	}
	if !IsNotExist(err) {
		t.Errorf("expected ErrSwitchNotExist, got: %v", err)
	}
}

func TestStatsLoadPinnedMapsError(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return nil, errors.New("load pinned maps failed")
	}

	_, err := Stats("sw0", nil)
	if err == nil {
		t.Fatal("expected error from LoadPinnedMaps")
	}
	if !containsSubstring(err.Error(), "failed to load pinned maps") {
		t.Errorf("unexpected error: %v", err)
	}
}

// getExistingSwitch / StartReserved tests are in start_test.go

// --- Attach additional tests using function variable mocks ---

func TestAttachZeroInnerIP(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: 256}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{}, nil
	}
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return newMmappedSlotsForTest(numSlots), nil
	}
	newStatsManagerFn = func(statsMap BPFMap, numPorts uint32) *StatsManager {
		return NewStatsManager(&mockBPFMapWithSlot{}, numPorts)
	}

	opts := AttachOptions{
		InnerIP: net.ParseIP("0.0.0.0"), // Zero IP
	}
	_, err := Attach("sw0", opts)
	if err == nil {
		t.Fatal("expected error for zero inner-ip")
	}
	if !containsSubstring(err.Error(), "inner-ip cannot be 0.0.0.0") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAttachGetSwitchConfigError(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return nil, errors.New("config read failed")
	}

	opts := AttachOptions{
		InnerIP: net.ParseIP("10.0.0.1"),
	}
	_, err := Attach("sw0", opts)
	if err == nil {
		t.Fatal("expected error from GetSwitchConfig")
	}
	if !containsSubstring(err.Error(), "failed to get switch config") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAttachMmapSlotsError(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: 4}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{}, nil
	}
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return nil, errors.New("mmap failed")
	}

	opts := AttachOptions{
		InnerIP: net.ParseIP("10.0.0.1"),
	}
	_, err := Attach("sw0", opts)
	if err == nil {
		t.Fatal("expected error from NewMmappedSlots")
	}
	if !containsSubstring(err.Error(), "failed to mmap slots") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAttachPortOutOfRange(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: 4}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{}, nil
	}
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return newMmappedSlotsForTest(numSlots), nil
	}
	newStatsManagerFn = func(statsMap BPFMap, numPorts uint32) *StatsManager {
		return NewStatsManager(&mockBPFMapWithSlot{}, numPorts)
	}

	opts := AttachOptions{
		InnerIP: net.ParseIP("10.0.0.1"),
		Port:    10, // > NPorts 4
	}
	_, err := Attach("sw0", opts)
	if err == nil {
		t.Fatal("expected error for port out of range")
	}
	if !IsPortOutOfRange(err) {
		t.Errorf("expected ErrPortOutOfRange, got: %v", err)
	}
}

func TestAttachPortAlreadyAllocated(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: 4}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{}, nil
	}
	// Create slots with slot 0 already allocated
	testSlots := newMmappedSlotsForTest(4)
	testSlots.TryAllocate(0, 0x0A000001) // Pre-allocate slot 0
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return testSlots, nil
	}

	opts := AttachOptions{
		InnerIP: net.ParseIP("10.0.0.2"),
		Port:    1, // Slot 0 (1-indexed)
	}
	_, err := Attach("sw0", opts)
	if err == nil {
		t.Fatal("expected error for already allocated port")
	}
	if !IsPortAllocated(err) {
		t.Errorf("expected ErrPortAllocated, got: %v", err)
	}
}

func TestAttachNoFreeSlotsAvailable(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: 2}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{}, nil
	}
	// Create slots with all slots allocated
	testSlots := newMmappedSlotsForTest(2)
	testSlots.TryAllocate(0, 0x0A000001)
	testSlots.TryAllocate(1, 0x0A000002)
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return testSlots, nil
	}

	opts := AttachOptions{
		InnerIP: net.ParseIP("10.0.0.3"),
		// Port 0 = auto-allocate
	}
	_, err := Attach("sw0", opts)
	if err == nil {
		t.Fatal("expected error for no free slots")
	}
	if !containsSubstring(err.Error(), "no free slots available") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAttachSuccessWithoutNamespace(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		cfg := &SwitchConfig{N_ports: 4, FloatingIpBase: 0x64646000} // 100.100.96.0
		return cfg, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{}, nil
	}
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return newMmappedSlotsForTest(numSlots), nil
	}
	newStatsManagerFn = func(statsMap BPFMap, numPorts uint32) *StatsManager {
		return NewStatsManager(&mockBPFMapWithSlot{}, numPorts)
	}

	opts := AttachOptions{
		InnerIP: net.ParseIP("10.0.0.1"),
		// No ToNetNS - skip namespace move
	}
	output, err := Attach("sw0", opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output.Port != 1 {
		t.Errorf("expected port 1, got %d", output.Port)
	}
	if output.InnerIP != "10.0.0.1" {
		t.Errorf("expected inner IP 10.0.0.1, got %s", output.InnerIP)
	}
	if output.TransitType != "none" {
		t.Errorf("expected transit type none, got %s", output.TransitType)
	}
}

func TestAttachSuccessWithTransit(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: 4, FloatingIpBase: 0x64646000, GenevePortBase: 6080}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{TransitDev: "eth0"}, nil
	}
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return newMmappedSlotsForTest(numSlots), nil
	}
	newStatsManagerFn = func(statsMap BPFMap, numPorts uint32) *StatsManager {
		return NewStatsManager(&mockBPFMapWithSlot{}, numPorts)
	}

	opts := AttachOptions{
		InnerIP:          net.ParseIP("10.0.0.1"),
		TransitGatewayIP: net.ParseIP("192.168.1.1"),
		TransitGeneveVNI: 12345,
	}
	output, err := Attach("sw0", opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output.TransitType != "overlay-geneve" {
		t.Errorf("expected transit type overlay-geneve, got %s", output.TransitType)
	}
	if output.TransitGatewayIP != "192.168.1.1" {
		t.Errorf("expected transit gateway 192.168.1.1, got %s", output.TransitGatewayIP)
	}
	if output.TransitGeneveVNI != 12345 {
		t.Errorf("expected VNI 12345, got %d", output.TransitGeneveVNI)
	}
}

func TestAttachWithToNetNSPortNsError(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: 4}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{PortNetNS: "port_ns"}, nil
	}
	testSlots := newMmappedSlotsForTest(4)
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return testSlots, nil
	}
	newStatsManagerFn = func(statsMap BPFMap, numPorts uint32) *StatsManager {
		return NewStatsManager(&mockBPFMapWithSlot{}, numPorts)
	}
	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return nil, errors.New("ns not found")
	}

	opts := AttachOptions{
		InnerIP: net.ParseIP("10.0.0.1"),
		ToNetNS: "sandbox_ns",
	}
	_, err := Attach("sw0", opts)
	if err == nil {
		t.Fatal("expected error for port ns not found")
	}
	if !containsSubstring(err.Error(), "failed to get port netns") {
		t.Errorf("unexpected error: %v", err)
	}
	// Verify slot was released (rollback)
	if testSlots.GetInnerIP(0) != 0 {
		t.Error("expected slot to be released on rollback")
	}
}

func TestAttachWithToNetNSTargetNsError(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: 4}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{PortNetNS: "port_ns"}, nil
	}
	testSlots := newMmappedSlotsForTest(4)
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return testSlots, nil
	}
	newStatsManagerFn = func(statsMap BPFMap, numPorts uint32) *StatsManager {
		return NewStatsManager(&mockBPFMapWithSlot{}, numPorts)
	}
	callCount := 0
	netnsGetByName = func(name string) (*netns.NetNS, error) {
		callCount++
		if callCount == 1 {
			return &netns.NetNS{}, nil // port_ns succeeds
		}
		return nil, errors.New("target ns not found")
	}

	opts := AttachOptions{
		InnerIP: net.ParseIP("10.0.0.1"),
		ToNetNS: "sandbox_ns",
	}
	_, err := Attach("sw0", opts)
	if err == nil {
		t.Fatal("expected error for target ns not found")
	}
	if !containsSubstring(err.Error(), "failed to get target netns") {
		t.Errorf("unexpected error: %v", err)
	}
	// Verify slot was released (rollback)
	if testSlots.GetInnerIP(0) != 0 {
		t.Error("expected slot to be released on rollback")
	}
}

func TestAttachWithToNetNSMoveDeviceError(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: 4}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{PortNetNS: "port_ns"}, nil
	}
	testSlots := newMmappedSlotsForTest(4)
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return testSlots, nil
	}
	newStatsManagerFn = func(statsMap BPFMap, numPorts uint32) *StatsManager {
		return NewStatsManager(&mockBPFMapWithSlot{}, numPorts)
	}
	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	netnsMoveDevice = func(devName string, fromNs, toNs *netns.NetNS) error {
		return errors.New("move failed")
	}

	opts := AttachOptions{
		InnerIP: net.ParseIP("10.0.0.1"),
		ToNetNS: "sandbox_ns",
	}
	_, err := Attach("sw0", opts)
	if err == nil {
		t.Fatal("expected error for move device failed")
	}
	if !containsSubstring(err.Error(), "failed to move") {
		t.Errorf("unexpected error: %v", err)
	}
	// Verify slot was released (rollback)
	if testSlots.GetInnerIP(0) != 0 {
		t.Error("expected slot to be released on rollback")
	}
}

func TestAttachWithToNetNSSuccess(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: 4, FloatingIpBase: 0x64646000}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{PortNetNS: "port_ns"}, nil
	}
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return newMmappedSlotsForTest(numSlots), nil
	}
	newStatsManagerFn = func(statsMap BPFMap, numPorts uint32) *StatsManager {
		return NewStatsManager(&mockBPFMapWithSlot{}, numPorts)
	}
	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	netnsMoveDevice = func(devName string, fromNs, toNs *netns.NetNS) error {
		return nil
	}

	opts := AttachOptions{
		InnerIP: net.ParseIP("10.0.0.1"),
		ToNetNS: "sandbox_ns",
	}
	output, err := Attach("sw0", opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output.PortNetNS != "sandbox_ns" {
		t.Errorf("expected port netns sandbox_ns, got %s", output.PortNetNS)
	}
}

// --- Detach additional tests using function variable mocks ---

func TestDetachGetSwitchConfigError(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return nil, errors.New("config read failed")
	}

	err := Detach("sw0", DetachOptions{Port: 1})
	if err == nil {
		t.Fatal("expected error from GetSwitchConfig")
	}
	if !containsSubstring(err.Error(), "failed to get switch config") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDetachPortOutOfRange(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: 4}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{}, nil
	}
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return newMmappedSlotsForTest(numSlots), nil
	}
	newStatsManagerFn = func(statsMap BPFMap, numPorts uint32) *StatsManager {
		return NewStatsManager(&mockBPFMapWithSlot{}, numPorts)
	}

	// Port 10 > NPorts 4
	err := Detach("sw0", DetachOptions{Port: 10})
	if err == nil {
		t.Fatal("expected error for port out of range")
	}
	if !IsPortOutOfRange(err) {
		t.Errorf("expected ErrPortOutOfRange, got: %v", err)
	}
}

func TestDetachMmapSlotsError(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: 4}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{}, nil
	}
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return nil, errors.New("mmap failed")
	}

	err := Detach("sw0", DetachOptions{Port: 1})
	if err == nil {
		t.Fatal("expected error from NewMmappedSlots")
	}
	if !containsSubstring(err.Error(), "failed to mmap slots") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDetachPortNotAttached(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: 4}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{}, nil
	}
	// Empty slots (InnerIP = 0)
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return newMmappedSlotsForTest(numSlots), nil
	}

	err := Detach("sw0", DetachOptions{Port: 1})
	if err == nil {
		t.Fatal("expected error for port not attached")
	}
	if !IsPortNotAttached(err) {
		t.Errorf("expected ErrPortNotAttached, got: %v", err)
	}
}

func TestDetachGetPortNsError(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: 4}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{PortNetNS: "port_ns"}, nil
	}
	// Slot 0 is allocated
	testSlots := newMmappedSlotsForTest(4)
	testSlots.TryAllocate(0, 0x0A000001)
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return testSlots, nil
	}
	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return nil, errors.New("ns not found")
	}

	err := Detach("sw0", DetachOptions{Port: 1})
	if err == nil {
		t.Fatal("expected error from netnsGetByName")
	}
	if !containsSubstring(err.Error(), "failed to get port netns") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDetachDeviceNotInPortNsNoFromNetNS(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: 4}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{PortNetNS: "port_ns"}, nil
	}
	testSlots := newMmappedSlotsForTest(4)
	testSlots.TryAllocate(0, 0x0A000001)
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return testSlots, nil
	}
	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	// Device not found in port namespace
	netnsGetLinkInNs = func(ns *netns.NetNS, name string) (vnetlink.Link, error) {
		return nil, errors.New("device not found")
	}

	// No fromNetNS provided
	err := Detach("sw0", DetachOptions{Port: 1})
	if err == nil {
		t.Fatal("expected error for device not in port ns")
	}
	if !containsSubstring(err.Error(), "not found in") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDetachDeviceNotInPortNsFromNetNSError(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: 4}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{PortNetNS: "port_ns"}, nil
	}
	testSlots := newMmappedSlotsForTest(4)
	testSlots.TryAllocate(0, 0x0A000001)
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return testSlots, nil
	}
	callCount := 0
	netnsGetByName = func(name string) (*netns.NetNS, error) {
		callCount++
		if callCount == 1 {
			// First call for port_ns succeeds
			return &netns.NetNS{}, nil
		}
		// Second call for fromNetNS fails
		return nil, errors.New("from ns not found")
	}
	netnsGetLinkInNs = func(ns *netns.NetNS, name string) (vnetlink.Link, error) {
		return nil, errors.New("device not found")
	}

	err := Detach("sw0", DetachOptions{Port: 1, FromNetNS: "sandbox_ns"})
	if err == nil {
		t.Fatal("expected error for from netns not found")
	}
	if !containsSubstring(err.Error(), "failed to get source netns") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDetachMoveDeviceBackError(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: 4}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{PortNetNS: "port_ns"}, nil
	}
	testSlots := newMmappedSlotsForTest(4)
	testSlots.TryAllocate(0, 0x0A000001)
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return testSlots, nil
	}
	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	netnsGetLinkInNs = func(ns *netns.NetNS, name string) (vnetlink.Link, error) {
		return nil, errors.New("device not found")
	}
	netnsMoveDevice = func(devName string, fromNs, toNs *netns.NetNS) error {
		return errors.New("move failed")
	}

	err := Detach("sw0", DetachOptions{Port: 1, FromNetNS: "sandbox_ns"})
	if err == nil {
		t.Fatal("expected error for move device failed")
	}
	if !containsSubstring(err.Error(), "failed to move") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDetachSuccessDeviceAlreadyInPortNs(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: 4}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{PortNetNS: "port_ns"}, nil
	}
	testSlots := newMmappedSlotsForTest(4)
	testSlots.TryAllocate(0, 0x0A000001)
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return testSlots, nil
	}
	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	// Device found in port namespace (no error)
	netnsGetLinkInNs = func(ns *netns.NetNS, name string) (vnetlink.Link, error) {
		return &vnetlink.Dummy{}, nil
	}

	err := Detach("sw0", DetachOptions{Port: 1})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Verify slot was released
	if testSlots.GetInnerIP(0) != 0 {
		t.Error("expected slot to be released (InnerIP = 0)")
	}
}

func TestDetachWithFromNetNSMoveSuccess(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: 4}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{PortNetNS: "port_ns"}, nil
	}
	testSlots := newMmappedSlotsForTest(4)
	testSlots.TryAllocate(0, 0x0A000001)
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return testSlots, nil
	}
	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	// Device NOT in port namespace - triggers fromNetNS path
	netnsGetLinkInNs = func(ns *netns.NetNS, name string) (vnetlink.Link, error) {
		return nil, errors.New("device not in port ns")
	}
	netnsMoveDevice = func(devName string, fromNs, toNs *netns.NetNS) error {
		return nil // Move succeeds
	}

	// Detach with fromNetNS specified should succeed
	err := Detach("sw0", DetachOptions{Port: 1, FromNetNS: "source_ns"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Verify slot was released
	if testSlots.GetInnerIP(0) != 0 {
		t.Error("expected slot to be released (InnerIP = 0)")
	}
}

func TestDetachCASFailSlotAlreadyFree(t *testing.T) {
	// Test CAS failure path when slot is already free
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: 4}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{PortNetNS: "port_ns"}, nil
	}
	testSlots := newMmappedSlotsForTest(4)
	testSlots.TryAllocate(0, 0x0A000001)
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return testSlots, nil
	}
	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	netnsGetLinkInNs = func(ns *netns.NetNS, name string) (vnetlink.Link, error) {
		// Simulate slot being freed by another process during detach
		// This happens after device check but before CAS
		testSlots.TryRelease(0, 0x0A000001)
		return &vnetlink.Dummy{}, nil
	}

	// Should succeed because slot is already free
	err := Detach("sw0", DetachOptions{Port: 1})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDetachCASFailSlotReattached(t *testing.T) {
	// Test CAS failure path when slot was reattached
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: 4}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{PortNetNS: "port_ns"}, nil
	}
	testSlots := newMmappedSlotsForTest(4)
	testSlots.TryAllocate(0, 0x0A000001)
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return testSlots, nil
	}
	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	netnsGetLinkInNs = func(ns *netns.NetNS, name string) (vnetlink.Link, error) {
		// Simulate slot being freed and reattached by another process
		testSlots.TryRelease(0, 0x0A000001)
		testSlots.TryAllocate(0, 0x0A000002) // Different IP
		return &vnetlink.Dummy{}, nil
	}

	err := Detach("sw0", DetachOptions{Port: 1})
	if err == nil {
		t.Fatal("expected error for concurrent reattach")
	}
	if !containsSubstring(err.Error(), "was reattached by another process") {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- Status additional tests using function variable mocks ---

func TestStatusGetSwitchConfigError(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return nil, errors.New("config read failed")
	}

	_, err := Status("sw0")
	if err == nil {
		t.Fatal("expected error from GetSwitchConfig")
	}
	if !containsSubstring(err.Error(), "failed to get switch config") {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- Stats additional tests using function variable mocks ---

func TestStatsGetSwitchConfigError(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return nil, errors.New("config read failed")
	}

	_, err := Stats("sw0", nil)
	if err == nil {
		t.Fatal("expected error from GetSwitchConfig")
	}
	if !containsSubstring(err.Error(), "failed to get switch config") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStatsPortOutOfRange(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: 4}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{}, nil
	}
	// Mock MmappedSlots and StatsManager
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return newMmappedSlotsForTest(numSlots), nil
	}
	newStatsManagerFn = func(statsMap BPFMap, numPorts uint32) *StatsManager {
		return NewStatsManager(&mockBPFMapWithSlot{}, numPorts)
	}

	// Port 10 > NPorts 4
	_, err := Stats("sw0", []int{10})
	if err == nil {
		t.Fatal("expected error for port out of range")
	}
	if !containsSubstring(err.Error(), "port 10 out of range") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStatsEmptyPortsNoAllocatedSlots(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: 4}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{}, nil
	}
	// Mock with all empty slots (InnerIP = 0)
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return newMmappedSlotsForTest(numSlots), nil
	}
	newStatsManagerFn = func(statsMap BPFMap, numPorts uint32) *StatsManager {
		return NewStatsManager(&mockBPFMapWithSlot{}, numPorts)
	}

	// No ports specified - should discover allocated slots (none in this case)
	output, err := Stats("sw0", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output.Switch != "sw0" {
		t.Errorf("expected switch name sw0, got %s", output.Switch)
	}
	if len(output.Ports) != 0 {
		t.Errorf("expected 0 ports, got %d", len(output.Ports))
	}
}

func TestStatsSpecificPorts(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: 4}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{}, nil
	}
	// Mock slot and stats data
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return newMmappedSlotsForTest(numSlots), nil
	}
	newStatsManagerFn = func(statsMap BPFMap, numPorts uint32) *StatsManager {
		return NewStatsManager(&mockBPFMapWithSlot{}, numPorts)
	}

	// Query specific ports 1 and 2
	output, err := Stats("sw0", []int{1, 2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output.Switch != "sw0" {
		t.Errorf("expected switch name sw0, got %s", output.Switch)
	}
	if len(output.Ports) != 2 {
		t.Errorf("expected 2 ports, got %d", len(output.Ports))
	}
}

// Start integration tests, getExistingSwitch tests, retryCleanup tests are in start_test.go

// --- attachReserve tests ---

// ProvisionPorts tests are in provision_test.go

// --- Attach/Detach SkipDevice tests ---

func TestAttachSkipDevice(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) { return true, nil }
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: 4, FloatingIpBase: 0x64646000}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{PortNetNS: "port_ns"}, nil
	}
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return newMmappedSlotsForTest(numSlots), nil
	}
	newStatsManagerFn = func(statsMap BPFMap, numPorts uint32) *StatsManager {
		return NewStatsManager(&mockBPFMapWithSlot{}, numPorts)
	}
	moveDeviceCalled := false
	netnsMoveDevice = func(devName string, fromNs, toNs *netns.NetNS) error {
		moveDeviceCalled = true
		return nil
	}

	opts := AttachOptions{
		Port:       1,
		InnerIP:    net.ParseIP("10.0.0.1"),
		ToNetNS:    "sandbox1",
		SkipDevice: true,
	}
	output, err := Attach("sw0", opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output.Port != 1 {
		t.Errorf("expected port 1, got %d", output.Port)
	}
	if moveDeviceCalled {
		t.Error("netnsMoveDevice should not be called with SkipDevice=true")
	}
}

func TestDetachSkipDevice(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) { return true, nil }
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: 4}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{PortNetNS: "port_ns"}, nil
	}
	testSlots := newMmappedSlotsForTest(4)
	testSlots.TryAllocate(0, 0x0A000001)
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return testSlots, nil
	}
	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	getLinkCalled := false
	netnsGetLinkInNs = func(ns *netns.NetNS, name string) (vnetlink.Link, error) {
		getLinkCalled = true
		return nil, errors.New("not found")
	}
	moveDeviceCalled := false
	netnsMoveDevice = func(devName string, fromNs, toNs *netns.NetNS) error {
		moveDeviceCalled = true
		return nil
	}

	err := Detach("sw0", DetachOptions{Port: 1, SkipDevice: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Verify slot was released
	if testSlots.GetInnerIP(0) != 0 {
		t.Error("expected slot to be released (InnerIP = 0)")
	}
	// Verify no device operations were performed
	if getLinkCalled {
		t.Error("netnsGetLinkInNs should not be called with SkipDevice=true")
	}
	if moveDeviceCalled {
		t.Error("netnsMoveDevice should not be called with SkipDevice=true")
	}
}

// StartReserved/Stop error path tests are in start_test.go and stop_test.go
