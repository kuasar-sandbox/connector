package bpfmap

import (
	"github.com/cilium/ebpf"

	"github.com/kuasar-sandbox/sandbox-vswitch/pkg/internal/bpf"
)

// Re-exports of BPF binding types and constants. Higher layers can type-alias
// these (`type MmappedSlots = bpfmap.MmappedSlots`) to keep their API stable
// even if BPF struct definitions move.
type (
	SlotItem     = bpf.SlotItem
	SlotStats    = bpf.SlotStats
	SwitchConfig = bpf.SwitchConfig
	MgmtCIDR     = bpf.MgmtCIDR
	PortKind     = bpf.PortKind
)

const (
	InnerIPFree        = bpf.InnerIPFree
	InnerIPReserved    = bpf.InnerIPReserved
	MaxMgmtCIDRPerSlot = bpf.MaxMgmtCIDRPerSlot
	MaxMgmtCIDRExt     = bpf.MaxMgmtCIDRExt
	PortKindVeth       = bpf.PortKindVeth
	PortKindTap        = bpf.PortKindTap
)

// BPFMap is the subset of *ebpf.Map operations bpfmap needs. Tests substitute
// mocks via this interface so slot/stats code can run without a real kernel
// BPF map attached.
type BPFMap interface {
	Lookup(key, valueOut any) error
	Update(key, value any, flags ebpf.MapUpdateFlags) error
	Delete(key any) error
}

// BPFArrayMap is the subset of *ebpf.Map operations required to mmap a BPF
// array (the slots map is the only user today).
type BPFArrayMap interface {
	FD() int
	ValueSize() uint32
	MaxEntries() uint32
}

// Ensure *ebpf.Map satisfies BPFMap.
var _ BPFMap = (*ebpf.Map)(nil)
