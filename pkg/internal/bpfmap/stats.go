package bpfmap

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// StatsManager handles per-CPU stats map operations.
type StatsManager struct {
	statsMap BPFMap
	numPorts uint32
}

// NewStatsManager creates a stats manager. The statsMap should be the BPF
// per-CPU array map keyed by slot_id.
func NewStatsManager(statsMap BPFMap, numPorts uint32) *StatsManager {
	return &StatsManager{
		statsMap: statsMap,
		numPorts: numPorts,
	}
}

// GetStats reads a slot's traffic statistics. For per-CPU maps this returns
// the sum across all CPUs; for non-per-CPU (test mocks), returns the value
// directly.
func (sm *StatsManager) GetStats(slotID uint32) (*SlotStats, error) {
	var perCPUStats []SlotStats
	if err := sm.statsMap.Lookup(slotID, &perCPUStats); err != nil {
		// Fallback: single value (non-per-CPU)
		var stats SlotStats
		if err := sm.statsMap.Lookup(slotID, &stats); err != nil {
			return nil, fmt.Errorf("failed to read stats for slot %d: %w", slotID, err)
		}
		return &stats, nil
	}

	total := &SlotStats{}
	for _, s := range perCPUStats {
		total.MgmtRxPackets += s.MgmtRxPackets
		total.MgmtRxBytes += s.MgmtRxBytes
		total.MgmtTxPackets += s.MgmtTxPackets
		total.MgmtTxBytes += s.MgmtTxBytes
		total.TransitRxPackets += s.TransitRxPackets
		total.TransitRxBytes += s.TransitRxBytes
		total.TransitTxPackets += s.TransitTxPackets
		total.TransitTxBytes += s.TransitTxBytes
	}
	return total, nil
}

// ResetStats zeroes the stats for a slot. Per-CPU maps require a slice with
// one element per CPU; we read first to discover the slice length, zero it
// out, and write back.
func (sm *StatsManager) ResetStats(slotID uint32) error {
	var perCPUStats []SlotStats
	if err := sm.statsMap.Lookup(slotID, &perCPUStats); err != nil {
		var zero SlotStats
		if err := sm.statsMap.Update(slotID, &zero, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("failed to reset stats for slot %d: %w", slotID, err)
		}
		return nil
	}
	for i := range perCPUStats {
		perCPUStats[i] = SlotStats{}
	}
	if err := sm.statsMap.Update(slotID, perCPUStats, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to reset stats for slot %d: %w", slotID, err)
	}
	return nil
}
