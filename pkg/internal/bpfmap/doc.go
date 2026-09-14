// Package bpfmap holds the mmap-backed BPF slot operations and other helpers
// that read/write BPF map memory by raw byte offset. This package directly
// depends on the BPF struct layout defined in pkg/internal/bpf — a change of
// a single field offset here is an ABI break.
//
// It is intentionally placed under pkg/internal/ so only pkg/* siblings
// (notably pkg/vswitch) can import it. External Go consumers should use the
// higher-level pkg/vswitch API instead.
//
// Contents:
//   - slots.go : MmappedSlots (mmap of the BPF array map), GetSlot/Update,
//     count helpers, FindFreeSlot
//   - cas.go   : atomic CAS operations on SlotItem.InnerIP (allocate, release,
//     reserve, unreserve) plus IsSlotFreeOrReserved / IsSlotAllocated
//     classifiers
//   - stats.go : StatsManager wrapping the kernel-locked stats map
//   - mac.go   : per-port / per-mgmt-plane MAC derivation tied to slot_id encoding
//   - types.go : BPFMap / BPFArrayMap interfaces used for mocking
package bpfmap
