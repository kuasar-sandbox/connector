package bpfmap

import (
	"fmt"
	"math"

	"github.com/cilium/ebpf"
)

// StatsManager reads and resets the kernel-locked per-slot counter map.
// Ownership changes serialize through the existing switch control flock.
type StatsManager struct {
	statsMap BPFMap
	numPorts uint32
}

func NewStatsManager(statsMap BPFMap, numPorts uint32) *StatsManager {
	return &StatsManager{statsMap: statsMap, numPorts: numPorts}
}

// GetStats takes the same BPF spin lock as TC, so packet/byte pairs and the
// counter generation are one coherent observation. Older per-CPU maps cannot
// satisfy this contract and must be recreated with the current switch program.
func (sm *StatsManager) GetStats(slotID uint32) (*SlotStats, error) {
	if slotID >= sm.numPorts {
		return nil, fmt.Errorf("stats slot %d out of range", slotID)
	}
	locked, ok := sm.statsMap.(interface {
		LookupWithFlags(any, any, ebpf.MapLookupFlags) error
	})
	if !ok {
		return nil, fmt.Errorf("stats map does not support locked reads")
	}
	var stats SlotStats
	if err := locked.LookupWithFlags(slotID, &stats, ebpf.LookupLock); err != nil {
		return nil, fmt.Errorf("failed to read stats for slot %d: %w", slotID, err)
	}
	return &stats, nil
}

// ResetStats atomically replaces the counter instance. TC captures generation
// before reading attachment fields and rejects late writes from an old instance.
// Call only under the ownership lock, after publishing all attachment fields.
func (sm *StatsManager) ResetStats(slotID uint32) error {
	previous, err := sm.GetStats(slotID)
	if err != nil {
		return err
	}
	if previous.Generation == math.MaxUint64 {
		return fmt.Errorf("stats generation exhausted for slot %d", slotID)
	}
	zero := SlotStats{Generation: previous.Generation + 1}
	if err := sm.statsMap.Update(slotID, &zero, ebpf.UpdateLock); err != nil {
		return fmt.Errorf("failed to reset stats for slot %d: %w", slotID, err)
	}
	return nil
}
