package vswitch

import (
	"errors"
	"net"
	"testing"

	"github.com/fullof-work/sandbox-vswitch/pkg/internal/bpf"
)

// stubMmapAttachTest builds a MmappedSlots backed by ordinary memory with the
// given per-slot (innerIP, mode, ifindex) so attach paths can be exercised
// without a real BPF map.
func stubMmapAttachTest(t *testing.T, numSlots uint32, init func(*MmappedSlots)) *MmappedSlots {
	t.Helper()
	m := newMmappedSlotsForTest(numSlots)
	if init != nil {
		init(m)
	}
	return m
}

// TestAttachTapUnprovisioned: attach on a tap-mode slot whose ifindex is 0
// must refuse with ErrPortNotProvisioned, leaving the slot Free (no leak).
func TestAttachTapUnprovisioned(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) { return true, nil }
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) { return &bpf.Maps{}, nil }
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: 4, FloatingIpBase: 0x64646000}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{SwitchNetNS: "sw_ns"}, nil
	}
	mmap := stubMmapAttachTest(t, 4, func(m *MmappedSlots) {
		// Slot 0: Free, mode=tap, ifindex=0 → unprovisioned
		m.UpdateSlotFields(0, func(s *SlotItem) { s.Mode = uint8(PortKindTap) })
	})
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return mmap, nil
	}
	newStatsManagerFn = func(statsMap BPFMap, numPorts uint32) *StatsManager {
		return NewStatsManager(&mockBPFMapWithSlot{}, numPorts)
	}

	_, err := Attach("sw0", AttachOptions{
		Port:    1,
		InnerIP: net.ParseIP("169.254.1.1"),
	})
	if err == nil {
		t.Fatal("expected ErrPortNotProvisioned, got nil")
	}
	if !errors.Is(err, ErrPortNotProvisioned) {
		t.Errorf("expected ErrPortNotProvisioned, got: %v", err)
	}
	// Slot must be back to Free (CAS rolled back).
	if got := mmap.GetInnerIP(0); got != InnerIPFree {
		t.Errorf("slot 0 leaked: innerIP=%#x, want Free (0)", got)
	}
}

// TestAttachTapProvisionedSkipsDeviceMove: a tap slot with valid ifindex
// allocates without attempting to look up port-netns (since tap never moves).
// We assert this by NOT mocking netnsGetByName — if attach tried to use it,
// the unset hook would panic / return zero netns.
func TestAttachTapProvisionedSkipsDeviceMove(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) { return true, nil }
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) { return &bpf.Maps{}, nil }
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: 4, FloatingIpBase: 0x64646000, SwitchMac: [6]uint8{2, 0, 0, 0, 0, 1}}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{SwitchNetNS: "sw_ns"}, nil
	}
	mmap := stubMmapAttachTest(t, 4, func(m *MmappedSlots) {
		m.UpdateSlotFields(0, func(s *SlotItem) {
			s.Mode = uint8(PortKindTap)
			s.Ifindex = 99 // simulate provisioned
		})
	})
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return mmap, nil
	}
	newStatsManagerFn = func(statsMap BPFMap, numPorts uint32) *StatsManager {
		return NewStatsManager(&mockBPFMapWithSlot{}, numPorts)
	}

	out, err := Attach("sw0", AttachOptions{
		Port:    1,
		ToNetNS: "sandbox1", // would normally trigger netns move; tap should skip
		InnerIP: net.ParseIP("169.254.1.1"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Mode != "tap" {
		t.Errorf("output.Mode = %q, want %q", out.Mode, "tap")
	}
	// Output should reference the switch netns, not the requested ToNetNS.
	if out.PortNetNS != "sw_ns" {
		t.Errorf("output.PortNetNS = %q, want %q (tap stays in switch-netns)", out.PortNetNS, "sw_ns")
	}
	// Port device should be the tap name, not the veth port name.
	if out.PortDev != "sw0-t1" {
		t.Errorf("output.PortDev = %q, want %q", out.PortDev, "sw0-t1")
	}
}

// TestDetachTapSkipsDeviceMove: detaching a tap slot is a pure slot operation
// and must not touch port-netns even when SkipDevice is false.
func TestDetachTapSkipsDeviceMove(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) { return true, nil }
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) { return &bpf.Maps{}, nil }
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: 4}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{SwitchNetNS: "sw_ns"}, nil
	}
	mmap := stubMmapAttachTest(t, 4, func(m *MmappedSlots) {
		m.UpdateSlotFields(0, func(s *SlotItem) {
			s.Mode = uint8(PortKindTap)
			s.Ifindex = 99
		})
		// Mark slot allocated (any non-Free/Reserved value)
		_ = m.TryAllocate(0, 0xa9fe0101)
	})
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return mmap, nil
	}
	newStatsManagerFn = func(statsMap BPFMap, numPorts uint32) *StatsManager {
		return NewStatsManager(&mockBPFMapWithSlot{}, numPorts)
	}

	// Detach without SkipDevice — tap branch should still skip netns ops.
	if err := Detach("sw0", DetachOptions{Port: 1, FromNetNS: "sandbox1"}); err != nil {
		t.Fatalf("unexpected detach error: %v", err)
	}
	if got := mmap.GetInnerIP(0); got != InnerIPFree {
		t.Errorf("slot 0 not freed: innerIP=%#x", got)
	}
}
