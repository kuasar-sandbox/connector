package vswitch

import (
	"testing"

	"github.com/kuasar-sandbox/sandbox-vswitch/pkg/internal/bpf"
)

func TestReserveRequiresPort(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) { return true, nil }
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

	opts := ReserveOptions{
		// Port is 0 (not set)
	}
	_, err := Reserve("sw0", opts)
	if err == nil {
		t.Fatal("expected error for reserve without port")
	}
	if !containsSubstring(err.Error(), "--port is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestReserveSuccess(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) { return true, nil }
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

	opts := ReserveOptions{
		Port: 2,
	}
	output, err := Reserve("sw0", opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output.Port != 2 {
		t.Errorf("expected port 2, got %d", output.Port)
	}
	if output.Status != "reserved" {
		t.Errorf("expected Status 'reserved', got %s", output.Status)
	}
}

func TestReserveAlreadyAllocated(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) { return true, nil }
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: 4}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{}, nil
	}
	testSlots := newMmappedSlotsForTest(4)
	testSlots.TryAllocate(1, 0x0A000001) // Pre-allocate slot 1 (port 2)
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return testSlots, nil
	}
	newStatsManagerFn = func(statsMap BPFMap, numPorts uint32) *StatsManager {
		return NewStatsManager(&mockBPFMapWithSlot{}, numPorts)
	}

	opts := ReserveOptions{
		Port: 2, // slot 1, already allocated
	}
	_, err := Reserve("sw0", opts)
	if err == nil {
		t.Fatal("expected error for reserve on allocated slot")
	}
	if !IsPortAllocated(err) {
		t.Errorf("expected ErrPortAllocated, got: %v", err)
	}
}

func TestReserveAlreadyReserved(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) { return true, nil }
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: 4}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{}, nil
	}
	testSlots := newMmappedSlotsForTest(4)
	testSlots.TryAllocate(1, InnerIPReserved) // Pre-reserve slot 1 (port 2)
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return testSlots, nil
	}
	newStatsManagerFn = func(statsMap BPFMap, numPorts uint32) *StatsManager {
		return NewStatsManager(&mockBPFMapWithSlot{}, numPorts)
	}

	opts := ReserveOptions{
		Port: 2,
	}
	_, err := Reserve("sw0", opts)
	if err == nil {
		t.Fatal("expected error for reserve on already reserved slot")
	}
	if !containsSubstring(err.Error(), "already reserved") {
		t.Errorf("expected 'already reserved' error, got: %v", err)
	}
}

func TestReservePortOutOfRange(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) { return true, nil }
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

	opts := ReserveOptions{
		Port: 10, // > N_ports 4
	}
	_, err := Reserve("sw0", opts)
	if err == nil {
		t.Fatal("expected error for port out of range")
	}
	if !IsPortOutOfRange(err) {
		t.Errorf("expected ErrPortOutOfRange, got: %v", err)
	}
}

func TestForceReserveSuccess(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) { return true, nil }
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: 4}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{}, nil
	}
	testSlots := newMmappedSlotsForTest(4)
	testSlots.TryAllocate(1, 0x0A000001) // Pre-allocate slot 1 (port 2)
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return testSlots, nil
	}
	newStatsManagerFn = func(statsMap BPFMap, numPorts uint32) *StatsManager {
		return NewStatsManager(&mockBPFMapWithSlot{}, numPorts)
	}

	opts := ReserveOptions{
		Force: true,
		Port:  2, // slot 1, currently allocated
	}
	output, err := Reserve("sw0", opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output.Port != 2 {
		t.Errorf("expected port 2, got %d", output.Port)
	}
	if output.Status != "reserved" {
		t.Errorf("expected Status 'reserved', got %s", output.Status)
	}
}

func TestForceReserveAlreadyReserved(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) { return true, nil }
	bpfLoadPinnedMaps = func(name string) (*bpf.Maps, error) {
		return &bpf.Maps{}, nil
	}
	getSwitchConfigFn = func(configMap BPFMap) (*SwitchConfig, error) {
		return &SwitchConfig{N_ports: 4}, nil
	}
	getSwitchMetadataFn = func(metadataMap BPFMap) (*SwitchMetadata, error) {
		return &SwitchMetadata{}, nil
	}
	testSlots := newMmappedSlotsForTest(4)
	testSlots.TryAllocate(1, InnerIPReserved) // Pre-reserve slot 1 (port 2)
	newMmappedSlotsFn = func(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
		return testSlots, nil
	}
	newStatsManagerFn = func(statsMap BPFMap, numPorts uint32) *StatsManager {
		return NewStatsManager(&mockBPFMapWithSlot{}, numPorts)
	}

	opts := ReserveOptions{
		Force: true,
		Port:  2,
	}
	output, err := Reserve("sw0", opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output.Port != 2 {
		t.Errorf("expected port 2, got %d", output.Port)
	}
	if output.Status != "already_reserved" {
		t.Errorf("expected Status 'already_reserved', got %s", output.Status)
	}
}

func TestForceReserveFreeSlot(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) { return true, nil }
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

	opts := ReserveOptions{
		Force: true,
		Port:  1, // slot 0, free
	}
	output, err := Reserve("sw0", opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output.Port != 1 {
		t.Errorf("expected port 1, got %d", output.Port)
	}
	if output.Status != "reserved" {
		t.Errorf("expected Status 'reserved', got %s", output.Status)
	}
}
