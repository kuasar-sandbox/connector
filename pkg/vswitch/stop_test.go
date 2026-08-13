package vswitch

import (
	"errors"
	"fmt"
	"syscall"
	"testing"

	"github.com/kuasar-sandbox/connector/pkg/internal/bpf"
	"github.com/kuasar-sandbox/connector/pkg/netlink"
	"github.com/kuasar-sandbox/connector/pkg/netns"
)

// mockStopSwitch sets up common mocks for stop tests with configurable slot state.
// allocatedIPs is a map of slotID -> innerIP for Allocated slots; all others start Free.
// Returns the shared MmappedSlots instance used across all Open calls.
func mockStopSwitch(nPorts uint32, allocatedIPs map[uint32]uint32) *MmappedSlots {
	bpfPinPathExists = func(name string) (bool, error) { return true, nil }
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) { return &bpf.Maps{}, nil }
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: nPorts}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{}, nil
	}
	slots := newMmappedSlotsForTest(nPorts)
	for slotID, ip := range allocatedIPs {
		slots.TryAllocate(slotID, ip)
		slots.UpdateSlotFields(slotID, func(s *SlotItem) {
			s.Ifindex = 100 + slotID
		})
	}
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return slots, nil
	}
	newStatsManagerFn = func(statsMap BPFMap, numPorts uint32) *StatsManager {
		return &StatsManager{}
	}
	bpfUnpinMaps = func(name string) error { return nil }
	return slots
}

// mockStopSwitchWithMeta is like mockStopSwitch but with custom metadata and slot setup.
func mockStopSwitchWithMeta(nPorts uint32, meta *SwitchMetadata, setupSlots func(*MmappedSlots)) *MmappedSlots {
	bpfPinPathExists = func(name string) (bool, error) { return true, nil }
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) { return &bpf.Maps{}, nil }
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: nPorts}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return meta, nil
	}
	slots := newMmappedSlotsForTest(nPorts)
	if setupSlots != nil {
		setupSlots(slots)
	}
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return slots, nil
	}
	newStatsManagerFn = func(statsMap BPFMap, numPorts uint32) *StatsManager {
		return &StatsManager{}
	}
	bpfUnpinMaps = func(name string) error { return nil }
	return slots
}

// --- Stop wrapper tests (existing, moved from core_test.go) ---

func TestStopSwitchNotExist(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return false, nil
	}

	err := Stop("sw0", StopOptions{})
	if err == nil {
		t.Fatal("expected error for non-existent switch")
	}
	if !IsNotExist(err) {
		t.Errorf("expected ErrSwitchNotExist, got: %v", err)
	}
}

func TestStopLoadPinnedMapsError(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return nil, errors.New("load pinned maps failed")
	}

	err := Stop("sw0", StopOptions{})
	if err == nil {
		t.Fatal("expected error from LoadPinnedMaps")
	}
	if !IsSwitchCorrupted(err) {
		t.Errorf("expected ErrSwitchCorrupted, got: %v", err)
	}
}

func TestStopGetSwitchConfigError(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	bpfPinPathExists = func(name string) (bool, error) {
		return true, nil
	}
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return nil, errors.New("config read failed")
	}

	err := Stop("sw0", StopOptions{})
	if err == nil {
		t.Fatal("expected error from GetSwitchConfig")
	}
	if !IsSwitchCorrupted(err) {
		t.Errorf("expected ErrSwitchCorrupted, got: %v", err)
	}
}

func TestStopNetNSNotFound(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	mockStopSwitchWithMeta(4, &SwitchMetadata{
		SwitchNetNS: "test_ns",
		TransitDev:  "eth0",
	}, nil)

	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return nil, netns.ErrNotExist
	}
	unpinCalled := false
	bpfUnpinMaps = func(name string) error {
		unpinCalled = true
		return nil
	}

	err := Stop("sw0", StopOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !unpinCalled {
		t.Error("expected bpfUnpinMaps to be called")
	}
}

func TestStopNetNSError(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	mockStopSwitchWithMeta(4, &SwitchMetadata{
		SwitchNetNS: "test_ns",
		TransitDev:  "eth0",
	}, nil)

	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return nil, errors.New("permission denied")
	}

	err := Stop("sw0", StopOptions{})
	if err == nil {
		t.Fatal("expected error from netnsGetByName")
	}
	if !containsSubstring(err.Error(), "get switch netns") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStopUnpinMapsError(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	mockStopSwitchWithMeta(4, &SwitchMetadata{}, nil)

	bpfUnpinMaps = func(name string) error {
		return errors.New("unpin failed")
	}

	err := Stop("sw0", StopOptions{})
	if err == nil {
		t.Fatal("expected error from bpfUnpinMaps")
	}
	if !containsSubstring(err.Error(), "unpin failed") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStopGetCurrentNSFailure(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	mockStopSwitchWithMeta(2, &SwitchMetadata{
		SwitchNetNS:  "test_ns",
		TransitDev:   "eth0",
		MgmtExtracts: []MgmtExtractMeta{{}},
	}, nil)

	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return nil, netns.ErrNotExist
	}
	bpfUnpinMaps = func(name string) error {
		return nil
	}

	// When namespace doesn't exist, Stop should succeed and jump to unpin maps
	err := Stop("sw0", StopOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestStopSuccessWithDevices(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	mockStopSwitchWithMeta(4, &SwitchMetadata{
		SwitchNetNS:  "switch_ns",
		TransitDev:   "eth0",
		MgmtExtracts: []MgmtExtractMeta{{}, {}},
	}, func(slots *MmappedSlots) {
		for i := uint32(0); i < 4; i++ {
			slots.UpdateSlotFields(i, func(s *SlotItem) {
				s.Ifindex = 100 + i
				s.MgmtCidrCount = 1
				s.MgmtCidrs0.Ifindex = 200 + (i % 2)
			})
		}
	})

	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	netnsGetCurrent = func() (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	netnsMoveDevice = func(devName string, fromNs, toNs *netns.NetNS) error {
		return nil
	}
	var deletedIfindexes []int
	netlinkDelLinkByIndexInNs = func(ns netlink.NetNS, ifindex int) error {
		deletedIfindexes = append(deletedIfindexes, ifindex)
		return nil
	}

	err := Stop("sw0", StopOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Port ifindexes (100-103) + mgmt ifindexes (200, 201) should be deleted individually
	// 4 ports + 2 deduplicated mgmt = 6 total
	if len(deletedIfindexes) != 6 {
		t.Errorf("expected 6 delete calls, got %d: %v", len(deletedIfindexes), deletedIfindexes)
	}
}

func TestStopEmptySwitchNetNS(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	mockStopSwitchWithMeta(4, &SwitchMetadata{}, nil)

	unpinCalled := false
	bpfUnpinMaps = func(name string) error {
		unpinCalled = true
		return nil
	}

	err := Stop("sw0", StopOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !unpinCalled {
		t.Error("expected bpfUnpinMaps to be called")
	}
}

func TestStopTransitDeviceMoveError(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	mockStopSwitchWithMeta(4, &SwitchMetadata{
		SwitchNetNS: "switch_ns",
		TransitDev:  "eth0",
	}, nil)

	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	netnsGetCurrent = func() (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	netnsMoveDevice = func(devName string, fromNs, toNs *netns.NetNS) error {
		return errors.New("move failed")
	}
	netlinkDelLinkByIndexInNs = func(ns netlink.NetNS, ifindex int) error {
		return nil
	}

	err := Stop("sw0", StopOptions{})
	if err == nil {
		t.Fatal("expected error from netnsMoveDevice")
	}
	if !containsSubstring(err.Error(), "move transit device") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStopTransitDeviceMoveEEXIST(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	mockStopSwitchWithMeta(2, &SwitchMetadata{
		SwitchNetNS: "switch_ns",
		TransitDev:  "eth0",
	}, nil)

	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	netnsGetCurrent = func() (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	netnsMoveDevice = func(devName string, fromNs, toNs *netns.NetNS) error {
		return fmt.Errorf("failed to move device %s to netns: %w", devName, syscall.EEXIST)
	}
	netlinkDelLinkByIndexInNs = func(ns netlink.NetNS, ifindex int) error {
		return nil
	}

	err := Stop("sw0", StopOptions{})
	if err != nil {
		t.Fatalf("EEXIST should be tolerated, got: %v", err)
	}
}

func TestStopVethDeletionError(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	mockStopSwitchWithMeta(2, &SwitchMetadata{
		SwitchNetNS:  "switch_ns",
		MgmtExtracts: []MgmtExtractMeta{{}},
	}, func(slots *MmappedSlots) {
		for i := uint32(0); i < 2; i++ {
			slots.UpdateSlotFields(i, func(s *SlotItem) {
				s.Ifindex = 100 + i
			})
		}
	})

	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	netlinkDelLinkByIndexInNs = func(ns netlink.NetNS, ifindex int) error {
		return errors.New("delete failed")
	}

	err := Stop("sw0", StopOptions{})
	if err == nil {
		t.Fatal("expected error from netlinkDelLinkByIndexInNs")
	}
	if !containsSubstring(err.Error(), "delete port veth ifindex") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStopMgmtVethDeletionError(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	mockStopSwitchWithMeta(2, &SwitchMetadata{SwitchNetNS: "switch_ns"}, func(slots *MmappedSlots) {
		for i := uint32(0); i < 2; i++ {
			slots.UpdateSlotFields(i, func(s *SlotItem) {
				s.Ifindex = 0
				s.MgmtCidrCount = 1
				s.MgmtCidrs0.Ifindex = 200
			})
		}
	})

	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	netlinkDelLinkByIndexInNs = func(ns netlink.NetNS, ifindex int) error {
		if ifindex == 200 {
			return errors.New("mgmt delete failed")
		}
		return nil
	}

	err := Stop("sw0", StopOptions{})
	if err == nil {
		t.Fatal("expected error from mgmt link deletion")
	}
	if !containsSubstring(err.Error(), "delete mgmt veth ifindex") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStopWithMgmtCIDRsExt(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	mockStopSwitchWithMeta(2, &SwitchMetadata{}, func(slots *MmappedSlots) {
		for i := uint32(0); i < 2; i++ {
			slots.UpdateSlotFields(i, func(s *SlotItem) {
				s.MgmtCidrCount = 2
				s.MgmtCidrs0.Ifindex = 200
				s.MgmtCidrsExt[0].Ifindex = 201
			})
		}
	})

	var deletedIfindexes []int
	netlinkDelLinkByIndex = func(ifindex int) error {
		deletedIfindexes = append(deletedIfindexes, ifindex)
		return nil
	}

	err := Stop("sw0", StopOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deletedIfindexes) != 2 {
		t.Errorf("expected 2 mgmt delete calls, got %d: %v", len(deletedIfindexes), deletedIfindexes)
	}
}

func TestStopGetCurrentNSError(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	mockStopSwitchWithMeta(2, &SwitchMetadata{
		SwitchNetNS: "switch_ns",
		TransitDev:  "eth0",
	}, nil)

	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	netnsGetCurrent = func() (*netns.NetNS, error) {
		return nil, errors.New("get current ns failed")
	}

	err := Stop("sw0", StopOptions{})
	if err == nil {
		t.Fatal("expected error from netnsGetCurrent")
	}
	if !containsSubstring(err.Error(), "get current netns") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStopEnsureBPFFSError(t *testing.T) {
	defer resetDeps()

	// bpfEnsureBPFFS is now called inside AcquireControlLock;
	// test via acquireControlLockFn returning the bpffs error
	acquireControlLockFn = func(name string) (*ControlLock, error) {
		return nil, fmt.Errorf("failed to acquire control lock: %w",
			fmt.Errorf("failed to ensure bpffs: %w", errors.New("bpffs not mounted")))
	}

	err := Stop("sw0", StopOptions{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !containsSubstring(err.Error(), "failed to ensure bpffs") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStopAcquireLockError(t *testing.T) {
	defer resetDeps()

	acquireControlLockFn = func(name string) (*ControlLock, error) {
		return nil, errors.New("lock busy")
	}

	err := Stop("sw0", StopOptions{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !containsSubstring(err.Error(), "failed to acquire control lock") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStopSafeWithUsedPorts(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	slots := mockStopSwitch(4, map[uint32]uint32{
		2: 0x0A000001,
		3: 0x0A000002,
	})

	err := Stop("sw0", StopOptions{Force: false})
	if err == nil {
		t.Fatal("expected error for used ports")
	}
	if !IsPortsInUse(err) {
		t.Errorf("expected ErrPortsInUse, got: %v", err)
	}

	// Used ports should remain Allocated (no side effects)
	if slots.GetInnerIP(2) != 0x0A000001 {
		t.Errorf("slot 2 should still be allocated, got %#x", slots.GetInnerIP(2))
	}
	if slots.GetInnerIP(3) != 0x0A000002 {
		t.Errorf("slot 3 should still be allocated, got %#x", slots.GetInnerIP(3))
	}
}

func TestStopLegacySwitchWithoutGeneveOptsMap(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	mockStopSwitch(4, map[uint32]uint32{})

	err := Stop("sw0", StopOptions{Force: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestStopForceWithUsedPorts(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	slots := mockStopSwitch(4, map[uint32]uint32{
		1: 0x0A000001,
	})

	var deletedIfindexes []int
	netlinkDelLinkByIndex = func(ifindex int) error {
		deletedIfindexes = append(deletedIfindexes, ifindex)
		return nil
	}

	err := Stop("sw0", StopOptions{Force: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// All slots should be reserved after force stop
	for i := uint32(0); i < 4; i++ {
		if slots.GetInnerIP(i) != InnerIPReserved {
			t.Errorf("slot %d: expected InnerIPReserved, got %#x", i, slots.GetInnerIP(i))
		}
	}

	// The used port's ifindex (101) should have been deleted
	found := false
	for _, idx := range deletedIfindexes {
		if idx == 101 {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected ifindex 101 to be deleted, deleted: %v", deletedIfindexes)
	}
}

// --- ReleasePorts tests ---

func TestReleasePorts_SafeNoAllocated(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	slots := mockStopSwitchWithMeta(4, &SwitchMetadata{}, func(s *MmappedSlots) {
		// All Free, with ifindexes set (devices exist)
		for i := uint32(0); i < 4; i++ {
			s.UpdateSlotFields(i, func(slot *SlotItem) {
				slot.Ifindex = 100 + i
			})
		}
	})

	var deletedIfindexes []int
	netlinkDelLinkByIndex = func(ifindex int) error {
		deletedIfindexes = append(deletedIfindexes, ifindex)
		return nil
	}

	out, err := ReleasePorts("sw0", ReleaseOptions{Force: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Released != 4 {
		t.Errorf("expected Released=4, got %d", out.Released)
	}
	if out.Total != 4 {
		t.Errorf("expected Total=4, got %d", out.Total)
	}
	if out.Remaining != 0 {
		t.Errorf("expected Remaining=0, got %d", out.Remaining)
	}

	// All slots should be reserved with ifindex=0
	for i := uint32(0); i < 4; i++ {
		if slots.GetInnerIP(i) != InnerIPReserved {
			t.Errorf("slot %d: expected InnerIPReserved, got %#x", i, slots.GetInnerIP(i))
		}
		if slots.GetSlot(i).Ifindex != 0 {
			t.Errorf("slot %d: expected ifindex=0, got %d", i, slots.GetSlot(i).Ifindex)
		}
	}
	if len(deletedIfindexes) != 4 {
		t.Errorf("expected 4 deletes, got %d", len(deletedIfindexes))
	}
}

func TestReleasePorts_SafeWithAllocated(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	mockStopSwitch(4, map[uint32]uint32{
		1: 0x0A000001,
	})

	_, err := ReleasePorts("sw0", ReleaseOptions{Force: false})
	if err == nil {
		t.Fatal("expected error for allocated ports")
	}
	if !IsPortsInUse(err) {
		t.Errorf("expected ErrPortsInUse, got: %v", err)
	}
}

func TestReleasePorts_Force(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	slots := mockStopSwitch(4, map[uint32]uint32{
		1: 0x0A000001,
		3: 0x0A000002,
	})

	var deletedIfindexes []int
	netlinkDelLinkByIndex = func(ifindex int) error {
		deletedIfindexes = append(deletedIfindexes, ifindex)
		return nil
	}

	out, err := ReleasePorts("sw0", ReleaseOptions{Force: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Released != 2 {
		t.Errorf("expected Released=2, got %d", out.Released)
	}
	if out.Remaining != 0 {
		t.Errorf("expected Remaining=0, got %d", out.Remaining)
	}

	// All slots should be reserved with ifindex=0
	for i := uint32(0); i < 4; i++ {
		if slots.GetInnerIP(i) != InnerIPReserved {
			t.Errorf("slot %d: expected InnerIPReserved, got %#x", i, slots.GetInnerIP(i))
		}
	}
}

func TestReleasePorts_Idempotent(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	mockStopSwitchWithMeta(4, &SwitchMetadata{}, func(s *MmappedSlots) {
		for i := uint32(0); i < 4; i++ {
			s.UpdateSlotFields(i, func(slot *SlotItem) {
				slot.Ifindex = 100 + i
			})
		}
	})

	netlinkDelLinkByIndex = func(ifindex int) error { return nil }

	out1, err := ReleasePorts("sw0", ReleaseOptions{Force: false})
	if err != nil {
		t.Fatalf("first call: unexpected error: %v", err)
	}
	if out1.Released != 4 {
		t.Errorf("first call: expected Released=4, got %d", out1.Released)
	}

	// Second call: all already reserved, no devices to delete
	out2, err := ReleasePorts("sw0", ReleaseOptions{Force: false})
	if err != nil {
		t.Fatalf("second call: unexpected error: %v", err)
	}
	if out2.Released != 0 {
		t.Errorf("second call: expected Released=0, got %d", out2.Released)
	}
}

func TestReleasePorts_DeletePortError(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	mockStopSwitchWithMeta(2, &SwitchMetadata{SwitchNetNS: "switch_ns"}, func(s *MmappedSlots) {
		for i := uint32(0); i < 2; i++ {
			s.UpdateSlotFields(i, func(slot *SlotItem) {
				slot.Ifindex = 100 + i
			})
		}
	})

	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	netlinkDelLinkByIndexInNs = func(ns netlink.NetNS, ifindex int) error {
		return errors.New("device busy")
	}

	_, err := ReleasePorts("sw0", ReleaseOptions{Force: false})
	if err == nil {
		t.Fatal("expected error from port deletion")
	}
	if !containsSubstring(err.Error(), "delete port veth ifindex") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestReleasePorts_SwitchNotExist(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	bpfPinPathExists = func(name string) (bool, error) { return false, nil }

	_, err := ReleasePorts("sw0", ReleaseOptions{})
	if err == nil {
		t.Fatal("expected error for non-existent switch")
	}
	if !IsNotExist(err) {
		t.Errorf("expected ErrSwitchNotExist, got: %v", err)
	}
}

// --- StopReleased tests ---

func TestStopReleased_Success(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	// All slots Reserved with ifindex=0 (already released)
	mockStopSwitchWithMeta(4, &SwitchMetadata{}, func(s *MmappedSlots) {
		for i := uint32(0); i < 4; i++ {
			s.TryReserve(i, InnerIPFree)
		}
	})

	unpinCalled := false
	bpfUnpinMaps = func(name string) error {
		unpinCalled = true
		return nil
	}

	err := StopReleased("sw0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !unpinCalled {
		t.Error("expected bpfUnpinMaps to be called")
	}
}

func TestStopReleased_PortsNotReleased_Ifindex(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	// Slots are Reserved but have ifindex != 0
	mockStopSwitchWithMeta(4, &SwitchMetadata{}, func(s *MmappedSlots) {
		for i := uint32(0); i < 4; i++ {
			s.TryReserve(i, InnerIPFree)
		}
		s.UpdateSlotFields(0, func(slot *SlotItem) {
			slot.Ifindex = 100 // device still present
		})
	})

	err := StopReleased("sw0")
	if err == nil {
		t.Fatal("expected error for unreleased ports")
	}
	if !IsPortsNotReleased(err) {
		t.Errorf("expected ErrPortsNotReleased, got: %v", err)
	}
}

func TestStopReleased_PortsNotReleased_Allocated(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	// Slot 1 is Allocated (not Reserved) — set innerIP directly via UpdateSlotFields
	mockStopSwitchWithMeta(4, &SwitchMetadata{}, func(s *MmappedSlots) {
		for i := uint32(0); i < 4; i++ {
			s.TryReserve(i, InnerIPFree)
		}
		// Override slot 1 to Allocated by writing innerIP directly
		s.UpdateSlotFields(1, func(slot *SlotItem) {
			slot.InnerIp = 0x0A000001
		})
	})

	err := StopReleased("sw0")
	if err == nil {
		t.Fatal("expected error for allocated ports")
	}
	if !IsPortsNotReleased(err) {
		t.Errorf("expected ErrPortsNotReleased, got: %v", err)
	}
}

func TestStopReleased_UnpinError(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	mockStopSwitchWithMeta(2, &SwitchMetadata{}, func(s *MmappedSlots) {
		for i := uint32(0); i < 2; i++ {
			s.TryReserve(i, InnerIPFree)
		}
	})

	bpfUnpinMaps = func(name string) error {
		return errors.New("unpin failed")
	}

	err := StopReleased("sw0")
	if err == nil {
		t.Fatal("expected error from bpfUnpinMaps")
	}
	if !containsSubstring(err.Error(), "unpin failed") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStopReleased_MgmtDeleteError(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()

	mockStopSwitchWithMeta(2, &SwitchMetadata{SwitchNetNS: "switch_ns"}, func(s *MmappedSlots) {
		for i := uint32(0); i < 2; i++ {
			s.TryReserve(i, InnerIPFree)
			s.UpdateSlotFields(i, func(slot *SlotItem) {
				slot.Ifindex = 0 // port device already deleted
				slot.MgmtCidrCount = 1
				slot.MgmtCidrs0.Ifindex = 200
			})
		}
	})

	netnsGetByName = func(name string) (*netns.NetNS, error) {
		return &netns.NetNS{}, nil
	}
	netlinkDelLinkByIndexInNs = func(ns netlink.NetNS, ifindex int) error {
		if ifindex == 200 {
			return errors.New("mgmt delete failed")
		}
		return nil
	}

	err := StopReleased("sw0")
	if err == nil {
		t.Fatal("expected error from mgmt deletion")
	}
	if !containsSubstring(err.Error(), "delete mgmt veth ifindex") {
		t.Errorf("unexpected error: %v", err)
	}
}
