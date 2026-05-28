package vswitch

import (
	"errors"
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/kuasar-sandbox/sandbox-vswitch/pkg/internal/bpf"
	"github.com/kuasar-sandbox/sandbox-vswitch/pkg/netlink"
	"github.com/kuasar-sandbox/sandbox-vswitch/pkg/netns"
)

// --- Start function tests ---

func TestStartValidationError(t *testing.T) {
	// Empty config should fail validation
	cfg := &Config{}
	_, err := Start(cfg)
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
}

func TestStartValidationEmptyName(t *testing.T) {
	cfg := &Config{
		SwitchNetNS:    "sandbox_switch",
		PortNetNS:      "sandbox_port",
		NumPorts:       256,
		MACAddr:        net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		FloatingIPBase: net.ParseIP("100.100.96.0"),
	}
	_, err := Start(cfg)
	if err == nil {
		t.Fatal("expected validation error for empty name")
	}
	if !containsSubstring(err.Error(), "switch name is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStartSwitchAlreadyExists(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	// Mock osMkdir to return os.ErrExist (existing switch)
	osMkdir = func(name string, perm os.FileMode) error { return os.ErrExist }
	// openSwitch (called by getExistingSwitch) still uses bpfPinPathExists
	bpfPinPathExists = func(name string) (bool, error) { return true, nil }

	// Mock bpfLoadPinnedMaps to return an error
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return nil, errors.New("mock load pinned maps error")
	}

	cfg := &Config{
		Name:           "sw0",
		SwitchNetNS:    "sandbox_switch",
		PortNetNS:      "sandbox_port",
		NumPorts:       256,
		MACAddr:        net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		FloatingIPBase: net.ParseIP("100.100.96.0"),
	}

	_, err := Start(cfg)
	if err == nil {
		t.Fatal("expected error from getExistingSwitch")
	}
	if !containsSubstring(err.Error(), "mock load pinned maps error") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStartSwitchNetNSNotFound(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	// Mock osMkdir to return nil (new switch, directory created)
	osMkdir = func(name string, perm os.FileMode) error { return nil }

	// Mock netnsGetByName to return error
	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return nil, errors.New("namespace not found")
	}

	cfg := &Config{
		Name:           "sw0",
		SwitchNetNS:    "sandbox_switch",
		PortNetNS:      "sandbox_port",
		NumPorts:       256,
		MACAddr:        net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		FloatingIPBase: net.ParseIP("100.100.96.0"),
	}

	_, err := Start(cfg)
	if err == nil {
		t.Fatal("expected error for missing switch netns")
	}
	if !containsSubstring(err.Error(), "failed to get switch netns") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStartPortNetNSNotFound(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	// In the new flow, StartReserved does not check port netns.
	// Port netns is checked in ProvisionPorts, which is called after StartReserved succeeds.
	// So we need StartReserved to succeed, then ProvisionPorts to fail at port netns.
	osMkdir = func(name string, perm os.FileMode) error { return nil }
	bpfLoadObjects = func() (*bpf.Objects, error) {
		return &bpf.Objects{
			Maps:     &bpf.Maps{},
			Programs: &bpf.Programs{},
		}, nil
	}
	bpfObjectsPinMaps = func(objects *bpf.Objects, name string) error {
		return nil
	}
	updateSwitchConfigFn = func(configMap BPFMap, cfg *Config) error {
		return nil
	}
	updateSwitchMetadataFn = func(metadataMap BPFMap, cfg *Config) error {
		return nil
	}
	// Share the mmap between StartReserved (sets slots Reserved) and ProvisionPorts
	// (reads slot state) so the lazy port-netns lookup is actually triggered.
	sharedMmap := newMmappedSlotsForTest(256)
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return sharedMmap, nil
	}

	// ProvisionPorts opens the switch via Open, which uses bpfPinPathExists.
	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: 256, FloatingIpBase: 0x64646000}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{
			SwitchNetNS: "sandbox_switch",
			PortNetNS:   "sandbox_port",
		}, nil
	}
	newStatsManagerFn = func(statsMap BPFMap, numPorts uint32) *StatsManager {
		return &StatsManager{}
	}
	// netnsGetByName: switch ns succeeds, port ns fails
	netnsGetByName = func(name string) (*netns.NetNS, error) {
		if name == "sandbox_port" {
			return nil, errors.New("port namespace not found")
		}
		return &netns.NetNS{}, nil
	}

	bpfUnpinMaps = func(name string) error {
		return nil
	}

	cfg := &Config{
		Name:           "sw0",
		SwitchNetNS:    "sandbox_switch",
		PortNetNS:      "sandbox_port",
		NumPorts:       256,
		MACAddr:        net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		FloatingIPBase: net.ParseIP("100.100.96.0"),
	}

	_, err := Start(cfg)
	if err == nil {
		t.Fatal("expected error for missing port netns")
	}
	if !containsSubstring(err.Error(), "failed to get port netns") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStartValidateTransitDeviceError(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	osMkdir = func(name string, perm os.FileMode) error { return nil }
	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	netlinkIsLinkDown = func(name string) (bool, error) {
		return false, nil // Device is UP, not DOWN - should fail
	}

	cfg := &Config{
		Name:           "sw0",
		SwitchNetNS:    "sandbox_switch",
		PortNetNS:      "sandbox_port",
		NumPorts:       256,
		MACAddr:        net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		FloatingIPBase: net.ParseIP("100.100.96.0"),
		TransitDev:     "eth0",
	}

	_, err := Start(cfg)
	if err == nil {
		t.Fatal("expected error for transit device not DOWN")
	}
	if !containsSubstring(err.Error(), "must be DOWN") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStartBPFLoadError(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	osMkdir = func(name string, perm os.FileMode) error { return nil }
	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	bpfLoadObjects = func() (*bpf.Objects, error) {
		return nil, errors.New("bpf load failed")
	}

	cfg := &Config{
		Name:           "sw0",
		SwitchNetNS:    "sandbox_switch",
		PortNetNS:      "sandbox_port",
		NumPorts:       256,
		MACAddr:        net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		FloatingIPBase: net.ParseIP("100.100.96.0"),
	}

	_, err := Start(cfg)
	if err == nil {
		t.Fatal("expected error for BPF load failure")
	}
	if !containsSubstring(err.Error(), "failed to load BPF objects") {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- getExistingSwitch tests ---

func TestGetExistingSwitchLoadPinnedMapsError(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return nil, errors.New("load failed")
	}

	cfg := &Config{}
	_, err := getExistingSwitch("sw0", cfg)
	if err == nil {
		t.Fatal("expected error")
	}
	if !containsSubstring(err.Error(), "failed to load pinned maps") {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- StartReserved/Stop error path tests ---

func TestStartReservedEnsureBPFFSError(t *testing.T) {
	defer resetDeps()

	bpfEnsureBPFFS = func() error { return errors.New("bpffs not mounted") }

	cfg := &Config{
		Name:           "sw0",
		SwitchNetNS:    "sw_ns",
		PortNetNS:      "port_ns",
		NumPorts:       4,
		MACAddr:        net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		FloatingIPBase: net.ParseIP("100.100.96.0"),
	}

	_, err := StartReserved(cfg)
	if err == nil {
		t.Fatal("expected error")
	}
	if !containsSubstring(err.Error(), "failed to ensure bpffs") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStartReservedAcquireLockError(t *testing.T) {
	defer resetDeps()

	bpfEnsureBPFFS = func() error { return nil }
	osMkdir = func(name string, perm os.FileMode) error { return nil }
	acquireControlLockFn = func(name string) (*ControlLock, error) {
		return nil, errors.New("lock busy")
	}

	cfg := &Config{
		Name:           "sw0",
		SwitchNetNS:    "sw_ns",
		PortNetNS:      "port_ns",
		NumPorts:       4,
		MACAddr:        net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		FloatingIPBase: net.ParseIP("100.100.96.0"),
	}

	_, err := StartReserved(cfg)
	if err == nil {
		t.Fatal("expected error")
	}
	if !containsSubstring(err.Error(), "failed to acquire control lock") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStartReservedNetnsError(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	osMkdir = func(name string, perm os.FileMode) error { return nil }
	unpinCalled := false
	bpfUnpinMaps = func(name string) error {
		unpinCalled = true
		return nil
	}
	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return nil, errors.New("netns not found")
	}

	cfg := &Config{
		Name:           "sw0",
		SwitchNetNS:    "sw_ns",
		PortNetNS:      "port_ns",
		NumPorts:       4,
		MACAddr:        net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		FloatingIPBase: net.ParseIP("100.100.96.0"),
	}

	_, err := StartReserved(cfg)
	if err == nil {
		t.Fatal("expected error")
	}
	if !containsSubstring(err.Error(), "failed to get switch netns") {
		t.Errorf("unexpected error: %v", err)
	}
	if !unpinCalled {
		t.Error("expected cleanup to unpin maps / remove pin directory")
	}
}

func TestStartReservedValidateTransitError(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	osMkdir = func(name string, perm os.FileMode) error { return nil }
	unpinCalled := false
	bpfUnpinMaps = func(name string) error {
		unpinCalled = true
		return nil
	}
	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	netlinkIsLinkDown = func(name string) (bool, error) {
		return false, nil // device is UP → validation fails
	}

	cfg := &Config{
		Name:           "sw0",
		SwitchNetNS:    "sw_ns",
		PortNetNS:      "port_ns",
		NumPorts:       4,
		MACAddr:        net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		FloatingIPBase: net.ParseIP("100.100.96.0"),
		TransitDev:     "eth0",
	}

	_, err := StartReserved(cfg)
	if err == nil {
		t.Fatal("expected error")
	}
	if !containsSubstring(err.Error(), "must be DOWN") {
		t.Errorf("unexpected error: %v", err)
	}
	if !unpinCalled {
		t.Error("expected cleanup to unpin maps / remove pin directory")
	}
}

func TestStartReservedBpfLoadError(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	osMkdir = func(name string, perm os.FileMode) error { return nil }
	unpinCalled := false
	bpfUnpinMaps = func(name string) error {
		unpinCalled = true
		return nil
	}
	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	bpfLoadObjects = func() (*bpf.Objects, error) {
		return nil, errors.New("bpf load failed")
	}

	cfg := &Config{
		Name:           "sw0",
		SwitchNetNS:    "sw_ns",
		PortNetNS:      "port_ns",
		NumPorts:       4,
		MACAddr:        net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		FloatingIPBase: net.ParseIP("100.100.96.0"),
	}

	_, err := StartReserved(cfg)
	if err == nil {
		t.Fatal("expected error")
	}
	if !containsSubstring(err.Error(), "failed to load BPF objects") {
		t.Errorf("unexpected error: %v", err)
	}
	if !unpinCalled {
		t.Error("expected cleanup to unpin maps / remove pin directory")
	}
}

func TestStartReservedDummyDeviceError(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	osMkdir = func(name string, perm os.FileMode) error { return nil }
	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	bpfLoadObjects = func() (*bpf.Objects, error) {
		return &bpf.Objects{}, nil
	}
	bpfObjectsPinMaps = func(objects *bpf.Objects, name string) error { return nil }
	bpfUnpinMaps = func(name string) error { return nil }

	// Make dummy link creation fail
	netlinkCreateDummyLink = func(name string) error {
		return errors.New("dummy create failed")
	}

	cfg := &Config{
		Name:           "sw0",
		SwitchNetNS:    "sw_ns",
		PortNetNS:      "port_ns",
		NumPorts:       4,
		MACAddr:        net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		FloatingIPBase: net.ParseIP("100.100.96.0"),
	}

	_, err := StartReserved(cfg)
	if err == nil {
		t.Fatal("expected error")
	}
	if !containsSubstring(err.Error(), "create block anchor device") {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- getExistingSwitch additional tests ---

func TestGetExistingSwitchConfigError(t *testing.T) {
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

	cfg := &Config{}
	_, err := getExistingSwitch("sw0", cfg)
	if err == nil {
		t.Fatal("expected error")
	}
	if !containsSubstring(err.Error(), "failed to get switch config") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestGetExistingSwitchConfigMismatch(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: 256, FloatingIpBase: 0x64646000}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{}, nil
	}
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return newMmappedSlotsForTest(numSlots), nil
	}
	newStatsManagerFn = func(statsMap BPFMap, numPorts uint32) *StatsManager {
		return &StatsManager{}
	}

	// Requested config has different ports
	cfg := &Config{
		Name:           "sw0",
		NumPorts:       128, // Different from existing 256
		FloatingIPBase: net.ParseIP("100.100.96.0"),
	}
	_, err := getExistingSwitch("sw0", cfg)
	if err == nil {
		t.Fatal("expected error for config mismatch")
	}
	if !IsConfigMismatch(err) {
		t.Errorf("expected ErrConfigMismatch, got: %v", err)
	}
}

func TestGetExistingSwitchSuccess(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: 256, FloatingIpBase: 0x64646000}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{
			SwitchNetNS: "switch_ns",
			PortNetNS:   "port_ns",
		}, nil
	}
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return newMmappedSlotsForTest(numSlots), nil
	}
	newStatsManagerFn = func(statsMap BPFMap, numPorts uint32) *StatsManager {
		return &StatsManager{}
	}

	cfg := &Config{
		Name:           "sw0",
		NumPorts:       256,
		FloatingIPBase: net.ParseIP("100.100.96.0"),
		SwitchNetNS:    "switch_ns",
		PortNetNS:      "port_ns",
	}
	output, err := getExistingSwitch("sw0", cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output.Switch != "sw0" {
		t.Errorf("expected switch sw0, got %s", output.Switch)
	}
	if output.Ports != 256 {
		t.Errorf("expected 256 ports, got %d", output.Ports)
	}
	if output.SwitchNetNS != "switch_ns" {
		t.Errorf("expected switch_ns, got %s", output.SwitchNetNS)
	}
}

// --- Start function additional tests ---

func TestStartPinMapsError(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	osMkdir = func(name string, perm os.FileMode) error { return nil }
	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	bpfLoadObjects = func() (*bpf.Objects, error) {
		return &bpf.Objects{}, nil
	}
	bpfObjectsPinMaps = func(objects *bpf.Objects, name string) error {
		return errors.New("pin maps failed")
	}
	// Cleanup should try to unpin (but won't panic with nil maps)
	bpfUnpinMaps = func(name string) error {
		return nil
	}

	cfg := &Config{
		Name:           "sw0",
		SwitchNetNS:    "sandbox_switch",
		PortNetNS:      "sandbox_port",
		NumPorts:       256,
		MACAddr:        net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		FloatingIPBase: net.ParseIP("100.100.96.0"),
	}

	_, err := Start(cfg)
	if err == nil {
		t.Fatal("expected error for pin maps failure")
	}
	if !containsSubstring(err.Error(), "failed to pin maps") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStartUpdateSwitchConfigError(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	osMkdir = func(name string, perm os.FileMode) error { return nil }
	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	bpfLoadObjects = func() (*bpf.Objects, error) {
		return &bpf.Objects{
			Maps:     &bpf.Maps{},
			Programs: &bpf.Programs{},
		}, nil
	}
	bpfObjectsPinMaps = func(objects *bpf.Objects, name string) error {
		return nil
	}
	updateSwitchConfigFn = func(configMap BPFMap, cfg *Config) error {
		return errors.New("update config failed")
	}
	bpfUnpinMaps = func(name string) error {
		return nil
	}

	cfg := &Config{
		Name:           "sw0",
		SwitchNetNS:    "sandbox_switch",
		PortNetNS:      "sandbox_port",
		NumPorts:       256,
		MACAddr:        net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		FloatingIPBase: net.ParseIP("100.100.96.0"),
	}

	_, err := Start(cfg)
	if err == nil {
		t.Fatal("expected error for update config failure")
	}
	if !containsSubstring(err.Error(), "update config failed") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStartCreatePortVethPairsError(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	// In the new flow, veth creation is in ProvisionPorts (called by Start after StartReserved).
	// StartReserved must succeed, then ProvisionPorts must reach veth creation and fail.
	osMkdir = func(name string, perm os.FileMode) error { return nil }
	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	bpfLoadObjects = func() (*bpf.Objects, error) {
		return &bpf.Objects{
			Maps:     &bpf.Maps{},
			Programs: &bpf.Programs{},
		}, nil
	}
	bpfObjectsPinMaps = func(objects *bpf.Objects, name string) error {
		return nil
	}
	updateSwitchConfigFn = func(configMap BPFMap, cfg *Config) error {
		return nil
	}
	updateSwitchMetadataFn = func(metadataMap BPFMap, cfg *Config) error {
		return nil
	}
	// ProvisionPorts opens the switch via Open, which uses bpfPinPathExists.
	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	// ProvisionPorts needs slots in Reserved state to trigger veth creation.
	// During StartReserved, initBPFSlotsReserved sets slots to Reserved via CAS.
	// During ProvisionPorts (Open), newMmappedSlotsFn must return Reserved slots.
	mmapCallCount := 0
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		mmapCallCount++
		slots := newMmappedSlotsForTest(numSlots)
		if mmapCallCount > 1 {
			// Calls after StartReserved (ProvisionPorts via Open) - slots should be Reserved
			for i := uint32(0); i < numSlots; i++ {
				slots.TryAllocate(i, InnerIPReserved)
			}
		}
		return slots, nil
	}
	// ProvisionPorts opens the switch via Open
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: 2, FloatingIpBase: 0x64646000}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{
			SwitchNetNS: "sandbox_switch",
			PortNetNS:   "sandbox_port",
		}, nil
	}
	newStatsManagerFn = func(statsMap BPFMap, numPorts uint32) *StatsManager {
		return &StatsManager{}
	}
	netnsDoFn = func(ns *netns.NetNS, f func() error) error {
		return f()
	}
	netlinkCreateVethPairs = func(specs []netlink.VethSpec) error {
		return errors.New("veth creation failed")
	}
	bpfUnpinMaps = func(name string) error {
		return nil
	}

	cfg := &Config{
		Name:           "sw0",
		SwitchNetNS:    "sandbox_switch",
		PortNetNS:      "sandbox_port",
		NumPorts:       2,
		MACAddr:        net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		FloatingIPBase: net.ParseIP("100.100.96.0"),
	}

	_, err := Start(cfg)
	if err == nil {
		t.Fatal("expected error for create veth failure")
	}
	if !containsSubstring(err.Error(), "failed to create veth") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStartInitBPFSlotsError(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	osMkdir = func(name string, perm os.FileMode) error { return nil }
	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	bpfLoadObjects = func() (*bpf.Objects, error) {
		return &bpf.Objects{
			Maps:     &bpf.Maps{},
			Programs: &bpf.Programs{},
		}, nil
	}
	bpfObjectsPinMaps = func(objects *bpf.Objects, name string) error {
		return nil
	}
	updateSwitchConfigFn = func(configMap BPFMap, cfg *Config) error {
		return nil
	}
	updateSwitchMetadataFn = func(metadataMap BPFMap, cfg *Config) error {
		return nil
	}
	// Return slots where slot 0 is already non-Free (pre-allocated), causing initBPFSlotsReserved to fail
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		slots := newMmappedSlotsForTest(numSlots)
		slots.TryAllocate(0, 0x0A000001) // Make slot 0 non-Free
		return slots, nil
	}
	bpfUnpinMaps = func(name string) error {
		return nil
	}
	netlinkDeleteVethPairInNs = func(ns netlink.NetNS, name string) error {
		return nil
	}

	cfg := &Config{
		Name:           "sw0",
		SwitchNetNS:    "sandbox_switch",
		PortNetNS:      "sandbox_port",
		NumPorts:       2,
		MACAddr:        net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		FloatingIPBase: net.ParseIP("100.100.96.0"),
	}

	_, err := Start(cfg)
	if err == nil {
		t.Fatal("expected error for init BPF slots failure")
	}
	if !containsSubstring(err.Error(), "failed to reserve slot") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStartCreateMgmtPlanesError(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	osMkdir = func(name string, perm os.FileMode) error { return nil }
	netnsGetByName = func(name string) (*netns.NetNS, error) {
		if name == "mgmt_ns" {
			return nil, errors.New("mgmt ns not found")
		}
		return &netns.NetNS{}, nil
	}
	bpfLoadObjects = func() (*bpf.Objects, error) {
		return &bpf.Objects{
			Maps:     &bpf.Maps{},
			Programs: &bpf.Programs{},
		}, nil
	}
	bpfObjectsPinMaps = func(objects *bpf.Objects, name string) error {
		return nil
	}
	updateSwitchConfigFn = func(configMap BPFMap, cfg *Config) error {
		return nil
	}
	updateSwitchMetadataFn = func(metadataMap BPFMap, cfg *Config) error {
		return nil
	}
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return newMmappedSlotsForTest(numSlots), nil
	}
	netnsDoFn = func(ns *netns.NetNS, f func() error) error {
		return f()
	}
	netlinkCreateVethPairs = func(specs []netlink.VethSpec) error {
		return nil
	}
	netlinkSetLinkUp = func(name string) error {
		return nil
	}
	bpfUnpinMaps = func(name string) error {
		return nil
	}
	netlinkDeleteVethPairInNs = func(ns netlink.NetNS, name string) error {
		return nil
	}

	me, _ := ParseMgmtExtract("mgmt_ns:mgmt0:10.0.0.1/24")
	cfg := &Config{
		Name:           "sw0",
		SwitchNetNS:    "sandbox_switch",
		PortNetNS:      "sandbox_port",
		NumPorts:       2,
		MACAddr:        net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		FloatingIPBase: net.ParseIP("100.100.96.0"),
		MgmtExtracts:   []*MgmtExtract{me},
	}

	_, err := Start(cfg)
	if err == nil {
		t.Fatal("expected error for create mgmt planes failure")
	}
	if !containsSubstring(err.Error(), "failed to get mgmt netns") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStartValidateMTUSlowPathError(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	osMkdir = func(name string, perm os.FileMode) error { return nil }
	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	bpfLoadObjects = func() (*bpf.Objects, error) {
		return &bpf.Objects{
			Maps:     &bpf.Maps{},
			Programs: &bpf.Programs{},
		}, nil
	}
	bpfObjectsPinMaps = func(objects *bpf.Objects, name string) error {
		return nil
	}
	updateSwitchConfigFn = func(configMap BPFMap, cfg *Config) error {
		return nil
	}
	updateSwitchMetadataFn = func(metadataMap BPFMap, cfg *Config) error {
		return nil
	}
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return newMmappedSlotsForTest(numSlots), nil
	}
	netnsDoFn = func(ns *netns.NetNS, f func() error) error {
		return f()
	}
	netlinkCreateVethPairs = func(specs []netlink.VethSpec) error {
		return nil
	}
	netlinkSetLinkUp = func(name string) error {
		return nil
	}
	// In the new flow, configureTransitDevice moves the device first, then configures.
	// Test that a transit device MTU set failure is caught.
	netlinkIsLinkDown = func(name string) (bool, error) {
		return true, nil
	}
	netnsGetCurrent = func() (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	netnsMoveDevice = func(devName string, fromNs, toNs *netns.NetNS) error {
		return nil
	}
	netlinkSetMTU = func(name string, mtu int) error {
		return errors.New("set MTU failed")
	}
	bpfUnpinMaps = func(name string) error {
		return nil
	}
	netlinkDeleteVethPairInNs = func(ns netlink.NetNS, name string) error {
		return nil
	}

	cfg := &Config{
		Name:           "sw0",
		SwitchNetNS:    "sandbox_switch",
		PortNetNS:      "sandbox_port",
		NumPorts:       2,
		MACAddr:        net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		FloatingIPBase: net.ParseIP("100.100.96.0"),
		MTU:            1500,
		TransitDev:     "eth0",
		TransitDevMTU:  9000, // Trigger MTU set path
	}

	_, err := Start(cfg)
	if err == nil {
		t.Fatal("expected error for transit device MTU set failure")
	}
	if !containsSubstring(err.Error(), "set transit MTU") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStartConfigureTransitDeviceError(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	osMkdir = func(name string, perm os.FileMode) error { return nil }
	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	bpfLoadObjects = func() (*bpf.Objects, error) {
		return &bpf.Objects{
			Maps:     &bpf.Maps{},
			Programs: &bpf.Programs{},
		}, nil
	}
	bpfObjectsPinMaps = func(objects *bpf.Objects, name string) error {
		return nil
	}
	updateSwitchConfigFn = func(configMap BPFMap, cfg *Config) error {
		return nil
	}
	updateSwitchMetadataFn = func(metadataMap BPFMap, cfg *Config) error {
		return nil
	}
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return newMmappedSlotsForTest(numSlots), nil
	}
	netnsDoFn = func(ns *netns.NetNS, f func() error) error {
		return f()
	}
	netlinkCreateVethPairs = func(specs []netlink.VethSpec) error {
		return nil
	}
	netlinkSetLinkUp = func(name string) error {
		return nil
	}
	netlinkIsLinkDown = func(name string) (bool, error) {
		return true, nil
	}
	// configureTransitDevice will fail getting current netns
	netnsGetCurrent = func() (*netns.NetNS, error) {
		return nil, errors.New("get current ns failed")
	}
	bpfUnpinMaps = func(name string) error {
		return nil
	}
	netlinkDeleteVethPairInNs = func(ns netlink.NetNS, name string) error {
		return nil
	}

	cfg := &Config{
		Name:           "sw0",
		SwitchNetNS:    "sandbox_switch",
		PortNetNS:      "sandbox_port",
		NumPorts:       2,
		MACAddr:        net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		FloatingIPBase: net.ParseIP("100.100.96.0"),
		MTU:            1500, // Set MTU to skip slow path
		TransitDev:     "eth0",
	}

	_, err := Start(cfg)
	if err == nil {
		t.Fatal("expected error for configure transit device failure")
	}
	if !containsSubstring(err.Error(), "failed to get current netns") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStartSuccess(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	// In the new flow, Start = StartReserved + ProvisionPorts.
	// osMkdir returns nil (new switch), bpfPinPathExists returns true for ProvisionPorts/Open.
	osMkdir = func(name string, perm os.FileMode) error { return nil }
	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	bpfLoadObjects = func() (*bpf.Objects, error) {
		return &bpf.Objects{
			Maps:     &bpf.Maps{},
			Programs: &bpf.Programs{},
		}, nil
	}
	bpfObjectsPinMaps = func(objects *bpf.Objects, name string) error {
		return nil
	}
	updateSwitchConfigFn = func(configMap BPFMap, cfg *Config) error {
		return nil
	}
	updateSwitchMetadataFn = func(metadataMap BPFMap, cfg *Config) error {
		return nil
	}
	// ProvisionPorts needs slots in Reserved state to trigger veth creation.
	mmapCallCount := 0
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		mmapCallCount++
		slots := newMmappedSlotsForTest(numSlots)
		if mmapCallCount > 1 {
			for i := uint32(0); i < numSlots; i++ {
				slots.TryAllocate(i, InnerIPReserved)
			}
		}
		return slots, nil
	}
	// ProvisionPorts mocks
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: 2, FloatingIpBase: 0x64646000}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{
			SwitchNetNS: "sandbox_switch",
			PortNetNS:   "sandbox_port",
		}, nil
	}
	newStatsManagerFn = func(statsMap BPFMap, numPorts uint32) *StatsManager {
		return &StatsManager{}
	}
	netnsDoFn = func(ns *netns.NetNS, f func() error) error {
		return f()
	}
	netlinkCreateVethPairs = func(specs []netlink.VethSpec) error {
		return nil
	}
	netlinkSetLinkUp = func(name string) error {
		return nil
	}

	cfg := &Config{
		Name:           "sw0",
		SwitchNetNS:    "sandbox_switch",
		PortNetNS:      "sandbox_port",
		NumPorts:       2,
		MACAddr:        net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		FloatingIPBase: net.ParseIP("100.100.96.0"),
		MTU:            1500,
	}

	output, err := Start(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output.Switch != "sw0" {
		t.Errorf("expected switch sw0, got %s", output.Switch)
	}
	if output.Ports != 2 {
		t.Errorf("expected 2 ports, got %d", output.Ports)
	}
	if output.SwitchNetNS != "sandbox_switch" {
		t.Errorf("expected sandbox_switch, got %s", output.SwitchNetNS)
	}
	if output.PortNetNS != "sandbox_port" {
		t.Errorf("expected sandbox_port, got %s", output.PortNetNS)
	}
	if output.TransitType != "none" {
		t.Errorf("expected transit type none, got %s", output.TransitType)
	}
}

func TestStartSuccessWithTransit(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	// In the new flow, Start = StartReserved + ProvisionPorts.
	// osMkdir returns nil (new switch), bpfPinPathExists returns true for ProvisionPorts/Open.
	osMkdir = func(name string, perm os.FileMode) error { return nil }
	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	bpfLoadObjects = func() (*bpf.Objects, error) {
		return &bpf.Objects{
			Maps:     &bpf.Maps{},
			Programs: &bpf.Programs{},
		}, nil
	}
	bpfObjectsPinMaps = func(objects *bpf.Objects, name string) error {
		return nil
	}
	updateSwitchConfigFn = func(configMap BPFMap, cfg *Config) error {
		return nil
	}
	updateSwitchMetadataFn = func(metadataMap BPFMap, cfg *Config) error {
		return nil
	}
	// ProvisionPorts needs slots in Reserved state to trigger veth creation.
	mmapCallCount := 0
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		mmapCallCount++
		slots := newMmappedSlotsForTest(numSlots)
		if mmapCallCount > 1 {
			for i := uint32(0); i < numSlots; i++ {
				slots.TryAllocate(i, InnerIPReserved)
			}
		}
		return slots, nil
	}
	// ProvisionPorts mocks
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: 2, FloatingIpBase: 0x64646000, GenevePortBase: 6081}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{
			SwitchNetNS:    "sandbox_switch",
			PortNetNS:      "sandbox_port",
			TransitDev:     "eth0",
			TransitDevAddr: "192.168.1.100/24",
		}, nil
	}
	newStatsManagerFn = func(statsMap BPFMap, numPorts uint32) *StatsManager {
		return &StatsManager{}
	}
	netnsDoFn = func(ns *netns.NetNS, f func() error) error {
		return f()
	}
	netlinkCreateVethPairs = func(specs []netlink.VethSpec) error {
		return nil
	}
	netlinkSetLinkUp = func(name string) error {
		return nil
	}
	netlinkIsLinkDown = func(name string) (bool, error) {
		return true, nil
	}
	netnsGetCurrent = func() (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	netnsMoveDevice = func(devName string, fromNs, toNs *netns.NetNS) error {
		return nil
	}
	netlinkSetMTU = func(name string, mtu int) error {
		return nil
	}
	netlinkAttachTC = func(name string, prog *ebpf.Program, dir netlink.Direction) error {
		return nil
	}
	netlinkGetLinkIndexInNs = func(ns netlink.NetNS, name string) (int, error) {
		return 300, nil
	}
	netlinkAddAddr = func(name string, addr *net.IPNet) error {
		return nil
	}

	cfg := &Config{
		Name:           "sw0",
		SwitchNetNS:    "sandbox_switch",
		PortNetNS:      "sandbox_port",
		NumPorts:       2,
		MACAddr:        net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		FloatingIPBase: net.ParseIP("100.100.96.0"),
		MTU:            1500,
		TransitDev:     "eth0",
		TransitDevMTU:  9000,
		TransitAddr:    &net.IPNet{IP: net.ParseIP("192.168.1.100"), Mask: net.CIDRMask(24, 32)},
		GenevePortBase: 6081,
	}

	output, err := Start(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output.TransitType != "overlay-geneve" {
		t.Errorf("expected transit type overlay-geneve, got %s", output.TransitType)
	}
	if output.TransitDev != "eth0" {
		t.Errorf("expected transit dev eth0, got %s", output.TransitDev)
	}
	if output.TransitDevIP != "192.168.1.100" {
		t.Errorf("expected transit dev IP 192.168.1.100, got %s", output.TransitDevIP)
	}
	if output.GenevePortBase != 6081 {
		t.Errorf("expected geneve port base 6081, got %d", output.GenevePortBase)
	}
}

// containsSubstring is a helper for checking if a string contains a substring.
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(s) > 0 && containsSubstringImpl(s, substr)))
}

func containsSubstringImpl(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// --- retryCleanup ---

func TestRetryCleanup(t *testing.T) {
	tests := []struct {
		name        string
		failCount   int // Number of times to fail before success (cleanupMaxRetries = always fail)
		expectErr   bool
		expectCalls int
	}{
		{"success first try", 0, false, 1},
		{"success after retry", 1, false, 2},
		{"success on last retry", cleanupMaxRetries - 1, false, cleanupMaxRetries},
		{"all failed", cleanupMaxRetries, true, cleanupMaxRetries},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			callCount := 0
			err := retryCleanup(func() error {
				callCount++
				if callCount <= tt.failCount {
					return errors.New("temporary error")
				}
				return nil
			})
			if (err != nil) != tt.expectErr {
				t.Errorf("error = %v, expectErr = %v", err, tt.expectErr)
			}
			if callCount != tt.expectCalls {
				t.Errorf("calls = %d, want %d", callCount, tt.expectCalls)
			}
		})
	}
}

// Stop tests (TestStopEnsureBPFFSError, TestStopAcquireLockError, TestStopSafe*,
// TestStopForce*, mockStopSwitch) moved to stop_test.go

func TestRetryCleanupReturnsLastError(t *testing.T) {
	callCount := 0
	err := retryCleanup(func() error {
		callCount++
		return fmt.Errorf("error %d", callCount)
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	expected := fmt.Sprintf("error %d", cleanupMaxRetries)
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestStartReservedTransitDevMTUAutoResolved(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	osMkdir = func(name string, perm os.FileMode) error { return nil }
	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	netlinkIsLinkDown = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadObjects = func() (*bpf.Objects, error) {
		return &bpf.Objects{
			Maps:     &bpf.Maps{},
			Programs: &bpf.Programs{},
		}, nil
	}
	bpfObjectsPinMaps = func(objects *bpf.Objects, name string) error { return nil }
	updateSwitchConfigFn = func(configMap BPFMap, cfg *Config) error { return nil }
	updateSwitchMetadataFn = func(metadataMap BPFMap, cfg *Config) error { return nil }
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return newMmappedSlotsForTest(numSlots), nil
	}
	bpfUnpinMaps = func(name string) error { return nil }
	netlinkCreateVethPairs = func(specs []netlink.VethSpec) error { return nil }
	netlinkSetLinkUp = func(name string) error { return nil }

	// Mock veth MTU read: port veths don't exist yet, but mgmt veths do.
	// Port veths return error (skipped), mgmt veth returns 1500.
	netlinkGetMTUInNs = func(ns netlink.NetNS, name string) (int, error) {
		if name == "sw0-m0" {
			return 1500, nil
		}
		return 0, errors.New("device not found")
	}

	// Track transit device MTU set call
	var mtuSetValue int
	netnsGetCurrent = func() (*netns.NetNS, error) { return &netns.NetNS{}, nil }
	netnsMoveDevice = func(devName string, fromNs, toNs *netns.NetNS) error { return nil }
	netlinkSetMTU = func(name string, mtu int) error {
		mtuSetValue = mtu
		return nil
	}
	netlinkSetLinkUp = func(name string) error { return nil }
	netlinkAttachTC = func(name string, prog *ebpf.Program, dir netlink.Direction) error {
		return nil
	}
	netlinkGetLinkIndexInNs = func(ns netlink.NetNS, name string) (int, error) {
		return 100, nil
	}
	netlinkAddAddr = func(name string, addr *net.IPNet) error { return nil }
	netlinkAddDeviceRoute = func(name string, dst *net.IPNet, metric int) error { return nil }

	me, _ := ParseMgmtExtract("mgmt_ns:mgmt0:10.0.0.1/24")
	cfg := &Config{
		Name:              "sw0",
		SwitchNetNS:       "sw_ns",
		PortNetNS:         "port_ns",
		NumPorts:          2,
		MACAddr:           net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		FloatingIPBase:    net.ParseIP("100.100.96.0"),
		TransitDev:        "eth0",
		TransitDevMTUAuto: true,
		GeneveEncapEth:    true,
		TransitAddr:       &net.IPNet{IP: net.ParseIP("192.168.1.100"), Mask: net.CIDRMask(24, 32)},
		MgmtExtracts:      []*MgmtExtract{me},
		// MTU intentionally 0 (not specified) — triggers slow path
	}

	_, err := StartReserved(cfg)
	if err != nil {
		t.Fatalf("StartReserved: %v", err)
	}

	expectedMTU := 1500 + GeneveEthOverhead
	if cfg.TransitDevMTU != expectedMTU {
		t.Errorf("TransitDevMTU = %d, want %d (auto resolved)", cfg.TransitDevMTU, expectedMTU)
	}
	if mtuSetValue != expectedMTU {
		t.Errorf("netlinkSetMTU called with %d, want %d", mtuSetValue, expectedMTU)
	}
}
