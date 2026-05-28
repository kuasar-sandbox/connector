package vswitch

import (
	"fmt"

	"github.com/kuasar-sandbox/sandbox-vswitch/pkg/internal/bpf"
)

// switchContext is the internal implementation of Interface.
type switchContext struct {
	name      string
	maps      *bpf.Maps
	cfg       *SwitchConfig
	meta      *SwitchMetadata // Userspace-only metadata (new)
	mmapSlots *MmappedSlots
	statsMgr  *StatsManager
}

// Ensure switchContext implements Interface.
var _ Interface = (*switchContext)(nil)

// Open opens an existing switch and loads its state.
// Returns an Interface for operating on the switch.
func Open(switchName string) (Interface, error) {
	return openSwitchFn(switchName)
}

// openSwitch is the actual implementation of Open.
func openSwitch(switchName string) (_ Interface, err error) {
	exists, err := bpfPinPathExists(switchName)
	if err != nil {
		return nil, fmt.Errorf("check switch %s: %w", switchName, err)
	}
	if !exists {
		return nil, fmt.Errorf("switch %s: %w", switchName, ErrSwitchNotExist)
	}

	// Past this point, pin path exists — any error means corrupted state
	var maps *bpf.Maps
	defer func() {
		if err != nil {
			err = newSwitchCorruptedError(switchName, err)
			if maps != nil {
				maps.Close()
			}
		}
	}()

	maps, err = bpfLoadPinnedMaps(switchName)
	if err != nil {
		return nil, fmt.Errorf("failed to load pinned maps: %w", err)
	}

	cfg, err := getSwitchConfigFn(maps.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to get switch config: %w", err)
	}

	meta, err := getSwitchMetadataFn(maps.Metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to get switch metadata: %w", err)
	}

	mmapSlots, err := newMmappedSlotsFn(maps.Slots, cfg.N_ports)
	if err != nil {
		return nil, fmt.Errorf("failed to mmap slots: %w", err)
	}

	return &switchContext{
		name:      switchName,
		maps:      maps,
		cfg:       cfg,
		meta:      meta,
		mmapSlots: mmapSlots,
		statsMgr:  newStatsManagerFn(maps.Stats, cfg.N_ports),
	}, nil
}

// Close releases all resources.
func (s *switchContext) Close() error {
	if s.mmapSlots != nil {
		s.mmapSlots.Close()
	}
	if s.maps != nil {
		s.maps.Close()
	}
	return nil
}

// Name returns the switch name.
func (s *switchContext) Name() string { return s.name }

// Config returns the switch configuration.
func (s *switchContext) Config() *SwitchConfig { return s.cfg }

// Metadata returns the switch metadata (userspace-only fields).
func (s *switchContext) Metadata() *SwitchMetadata { return s.meta }

// Maps returns the underlying BPF maps.
func (s *switchContext) Maps() *bpf.Maps { return s.maps }

// MmapSlots returns the mmapped slots for direct access.
func (s *switchContext) MmapSlots() *MmappedSlots { return s.mmapSlots }

// Ports returns port slot information.
// If allocatedOnly is true, returns only allocated ports.
func (s *switchContext) Ports(allocatedOnly bool) []PortSlot {
	var result []PortSlot
	for i := uint32(0); i < s.cfg.N_ports; i++ {
		slot := s.mmapSlots.GetSlot(i)
		if slot == nil {
			continue
		}
		allocated := IsSlotAllocated(slot.InnerIp)
		if allocatedOnly && !allocated {
			continue
		}
		result = append(result, PortSlot{
			SlotItem:  *slot,
			Port:      int(i) + 1,
			Allocated: allocated,
		})
	}
	return result
}
