package bpfmap

import (
	"fmt"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

// InnerIPOffset is the byte offset of InnerIP within SlotItem. Must match
// the C struct layout: ifindex (4 bytes) then inner_ip.
const InnerIPOffset = 4

// MmappedSlots provides direct memory access to the slots BPF map for atomic
// CAS operations on the InnerIP field. The constructor mmaps the entire map
// (BPF_F_MMAPABLE required); Close munmaps and clears the slice.
type MmappedSlots struct {
	data     []byte
	slotSize uint32
	numSlots uint32
}

// NewMmappedSlots creates a MmappedSlots by mmapping the BPF array map.
func NewMmappedSlots(slotsMap BPFArrayMap, numSlots uint32) (*MmappedSlots, error) {
	fd := slotsMap.FD()
	valueSize := slotsMap.ValueSize()
	maxEntries := slotsMap.MaxEntries()

	// BPF array mmap layout aligns each entry to 8-byte boundary.
	slotSize := (valueSize + 7) &^ 7

	// BPF_F_MMAPABLE requires mmap of the entire array, rounded up to page size.
	pageSize := unix.Getpagesize()
	mapSize := int(maxEntries) * int(slotSize)
	mapSize = ((mapSize + pageSize - 1) / pageSize) * pageSize

	data, err := unixMmap(fd, 0, mapSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("failed to mmap slots map: %w", err)
	}

	return &MmappedSlots{
		data:     data,
		slotSize: slotSize,
		numSlots: numSlots,
	}, nil
}

// Close unmaps the memory region.
func (m *MmappedSlots) Close() error {
	if m.data != nil {
		if err := unixMunmap(m.data); err != nil {
			return fmt.Errorf("failed to munmap: %w", err)
		}
		m.data = nil
	}
	return nil
}

// getInnerIPPtr returns a pointer to the InnerIP field for the given slot.
// Exposed (capitalized) so cas.go can use it across files within the package.
func (m *MmappedSlots) getInnerIPPtr(slotID uint32) *uint32 {
	if slotID >= m.numSlots {
		return nil
	}
	offset := uintptr(slotID)*uintptr(m.slotSize) + InnerIPOffset
	return (*uint32)(unsafe.Pointer(&m.data[offset]))
}

// GetSlot returns a pointer to the SlotItem for direct field access.
// WARNING: not thread-safe for fields other than InnerIP. Use UpdateSlotFields
// to modify other fields after CAS allocation.
func (m *MmappedSlots) GetSlot(slotID uint32) *SlotItem {
	if slotID >= m.numSlots {
		return nil
	}
	offset := uintptr(slotID) * uintptr(m.slotSize)
	return (*SlotItem)(unsafe.Pointer(&m.data[offset]))
}

// UpdateSlotFields allows updating slot fields via a callback. InnerIP should
// be modified via TryAllocate/TryRelease for atomicity (cas.go).
func (m *MmappedSlots) UpdateSlotFields(slotID uint32, update func(*SlotItem)) {
	slot := m.GetSlot(slotID)
	if slot == nil {
		return
	}
	update(slot)
}

// FindFreeSlot scans for a free slot (InnerIP == 0) and attempts to allocate
// it. Returns the slot ID on success, or an error if no free slots remain.
func (m *MmappedSlots) FindFreeSlot(innerIP uint32) (uint32, error) {
	for i := uint32(0); i < m.numSlots; i++ {
		if m.TryAllocate(i, innerIP) {
			return i, nil
		}
	}
	return 0, fmt.Errorf("no free slots available")
}

// CountAllocatedSlots counts slots currently allocated (not Free, not Reserved).
func (m *MmappedSlots) CountAllocatedSlots() uint32 {
	var count uint32
	for i := uint32(0); i < m.numSlots; i++ {
		if IsSlotAllocated(m.GetInnerIP(i)) {
			count++
		}
	}
	return count
}

// CountReservedSlots counts slots in Reserved state.
func (m *MmappedSlots) CountReservedSlots() uint32 {
	var count uint32
	for i := uint32(0); i < m.numSlots; i++ {
		if m.GetInnerIP(i) == InnerIPReserved {
			count++
		}
	}
	return count
}

// CountFreeSlots counts truly Free slots (InnerIP == 0).
func (m *MmappedSlots) CountFreeSlots() uint32 {
	var count uint32
	for i := uint32(0); i < m.numSlots; i++ {
		if m.GetInnerIP(i) == InnerIPFree {
			count++
		}
	}
	return count
}

// NewMmappedSlotsForTest creates a MmappedSlots backed by regular memory for
// testing. Allows testing slot/CAS logic without real BPF maps or mmap.
func NewMmappedSlotsForTest(numSlots uint32) *MmappedSlots {
	slotSize := uint32((unsafe.Sizeof(SlotItem{}) + 7) &^ 7)
	data := make([]byte, numSlots*slotSize)
	return &MmappedSlots{
		data:     data,
		slotSize: slotSize,
		numSlots: numSlots,
	}
}

// Function variables for testing (can be replaced with mocks).
var (
	unixMmap   = unix.Mmap
	unixMunmap = unix.Munmap
)

// InitSlotReserved uses CAS(Free → Reserved) plus an initial field write.
// Returns false if CAS fails (slot not Free). Called from StartReserved
// during switch creation to claim all slots before provisioning.
func InitSlotReserved(m *MmappedSlots, slotID uint32) bool {
	ptr := m.getInnerIPPtr(slotID)
	if ptr == nil || !atomic.CompareAndSwapUint32(ptr, InnerIPFree, InnerIPReserved) {
		return false
	}
	// CAS succeeded — safe to write other fields (Reserved state prevents
	// concurrent access until TryUnreserve).
	m.UpdateSlotFields(slotID, func(slot *SlotItem) {
		slot.Ifindex = 0
		slot.TransitGatewayIp = 0
		slot.TransitGeneveVni = 0
		slot.ClearTransitMac()
	})
	return true
}

// NumSlots returns the number of slots in the mmap region (read-only accessor).
func (m *MmappedSlots) NumSlots() uint32 {
	return m.numSlots
}
