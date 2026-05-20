package vswitch

import (
	"fmt"

	"github.com/cilium/ebpf"

	"github.com/fullof-work/sandbox-vswitch/pkg/internal/bpf"
	"github.com/fullof-work/sandbox-vswitch/pkg/internal/bpfmap"
)

// Type aliases re-exporting the BPF and bpfmap types so vswitch callers
// (and the CLI via exports.go) can use them without importing pkg/internal/*.
type (
	MgmtCIDR     = bpf.MgmtCIDR
	SlotItem     = bpf.SlotItem
	SwitchConfig = bpf.SwitchConfig
	SlotStats    = bpf.SlotStats
	PortKind     = bpf.PortKind
	MmappedSlots = bpfmap.MmappedSlots
	StatsManager = bpfmap.StatsManager
)

// Re-export constants from the BPF binding for vswitch-package callers.
const (
	MaxMgmtCIDRPerSlot = bpf.MaxMgmtCIDRPerSlot
	MaxMgmtCIDRExt     = bpf.MaxMgmtCIDRExt
	InnerIPFree        = bpf.InnerIPFree
	InnerIPReserved    = bpf.InnerIPReserved
	PortKindVeth       = bpf.PortKindVeth
	PortKindTap        = bpf.PortKindTap
)

// Function-level re-exports so existing vswitch code can call these without
// the bpfmap. prefix everywhere.
var (
	NewMmappedSlots = bpfmap.NewMmappedSlots
	NewStatsManager = bpfmap.NewStatsManager
	InitSlotReserved = bpfmap.InitSlotReserved
	IsSlotFreeOrReserved = bpfmap.IsSlotFreeOrReserved
	IsSlotAllocated      = bpfmap.IsSlotAllocated
	PortMAC              = bpfmap.PortMAC
	MgmtMAC              = bpfmap.MgmtMAC
	PortMACFixed         = bpfmap.PortMACFixed
	IsZeroMAC            = bpfmap.IsZeroMAC
	GetPortMAC           = bpfmap.GetPortMAC
)

// SlotPortKind returns the PortKind stored in SlotItem.Mode.
// Slots that predate the mode field (Mode==0) read back as PortKindVeth.
func SlotPortKind(s *SlotItem) PortKind { return PortKind(s.Mode) }

// PortDeviceName returns the sandbox-side device name for a slot's veth port.
func PortDeviceName(switchName string, slotID uint32) string {
	return fmt.Sprintf("%s-p%d", switchName, slotID+1)
}

// PeerDeviceName returns the switch-side veth peer name for a slot.
func PeerDeviceName(switchName string, slotID uint32) string {
	return fmt.Sprintf("%s-n%d", switchName, slotID+1)
}

// TapDeviceName returns the switch-side tap device name for a slot.
func TapDeviceName(switchName string, slotID uint32) string {
	return fmt.Sprintf("%s-t%d", switchName, slotID+1)
}

// UpdateSwitchConfig writes the user-facing Config into the BPF config map.
// Performs the Config → SwitchConfig type conversion (including IP encoding)
// then issues a single map update.
func UpdateSwitchConfig(configMap BPFMap, cfg *Config) error {
	var bpfCfg SwitchConfig
	bpfCfg.SetSwitchMacAddr(cfg.MACAddr)
	bpfCfg.N_ports = cfg.NumPorts
	bpfCfg.FloatingIpBase = bpf.IPToUint32(cfg.FloatingIPBase)
	bpfCfg.GenevePortBase = uint32(cfg.GenevePortBase)
	if cfg.GeneveEncapEth {
		bpfCfg.GeneveEncapEth = 1
	}
	if cfg.TransitNexthop != nil {
		bpfCfg.TransitNexthop = bpf.IPToUint32(cfg.TransitNexthop)
	}
	if len(cfg.PortMAC) >= 6 {
		bpfCfg.SetPortMacAddr(cfg.PortMAC)
	}

	key := uint32(0)
	if err := configMap.Update(key, &bpfCfg, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update config map: %w", err)
	}
	return nil
}

// updateSwitchConfigFields reads, applies a callback, and writes back. Used
// for fine-grained edits (e.g. transit fields populated post-DHCP).
func updateSwitchConfigFields(configMap BPFMap, update func(*SwitchConfig)) error {
	var bpfCfg SwitchConfig
	key := uint32(0)

	if err := configMap.Lookup(key, &bpfCfg); err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}

	update(&bpfCfg)

	if err := configMap.Update(key, &bpfCfg, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update config: %w", err)
	}
	return nil
}

// GetSwitchConfig reads the switch configuration from the BPF map.
func GetSwitchConfig(configMap BPFMap) (*SwitchConfig, error) {
	var bpfCfg SwitchConfig
	key := uint32(0)
	if err := configMap.Lookup(key, &bpfCfg); err != nil {
		return nil, fmt.Errorf("failed to read config map: %w", err)
	}
	return &bpfCfg, nil
}

// newMmappedSlotsForTest is the test-only constructor used by *_test.go in this
// package. Re-exported from bpfmap so internal vswitch tests don't have to
// reach across packages.
func newMmappedSlotsForTest(numSlots uint32) *MmappedSlots {
	return bpfmap.NewMmappedSlotsForTest(numSlots)
}
