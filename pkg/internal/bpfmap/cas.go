package bpfmap

import "sync/atomic"

// IsSlotFreeOrReserved checks if a slot is Free or Reserved (not allocated).
func IsSlotFreeOrReserved(innerIP uint32) bool {
	return innerIP == InnerIPFree || innerIP == InnerIPReserved
}

// IsSlotAllocated checks if a slot is allocated to a sandbox (not Free,
// not Reserved).
func IsSlotAllocated(innerIP uint32) bool {
	return !IsSlotFreeOrReserved(innerIP)
}

// TryAllocate attempts to atomically allocate a slot using CAS.
// Returns true on CAS success (0 → innerIP).
func (m *MmappedSlots) TryAllocate(slotID uint32, innerIP uint32) bool {
	ptr := m.getInnerIPPtr(slotID)
	if ptr == nil {
		return false
	}
	return atomic.CompareAndSwapUint32(ptr, 0, innerIP)
}

// TryRelease attempts to atomically release a slot using CAS.
// Returns true on CAS success (currentIP → 0).
func (m *MmappedSlots) TryRelease(slotID uint32, currentIP uint32) bool {
	ptr := m.getInnerIPPtr(slotID)
	if ptr == nil {
		return false
	}
	return atomic.CompareAndSwapUint32(ptr, currentIP, 0)
}

// TryReserve attempts to reserve a slot by setting innerIP to InnerIPReserved
// (0xFFFFFFFF). Returns true on CAS success (currentIP → InnerIPReserved).
// Used during Stop to prevent concurrent Attach operations.
func (m *MmappedSlots) TryReserve(slotID uint32, currentIP uint32) bool {
	if currentIP == InnerIPReserved {
		return false
	}
	ptr := m.getInnerIPPtr(slotID)
	if ptr == nil {
		return false
	}
	return atomic.CompareAndSwapUint32(ptr, currentIP, InnerIPReserved)
}

// TryUnreserve attempts CAS(Reserved → Free). Used after provision completes.
func (m *MmappedSlots) TryUnreserve(slotID uint32) bool {
	ptr := m.getInnerIPPtr(slotID)
	if ptr == nil {
		return false
	}
	return atomic.CompareAndSwapUint32(ptr, InnerIPReserved, InnerIPFree)
}

// GetInnerIP returns the current InnerIP value for a slot (atomic load).
func (m *MmappedSlots) GetInnerIP(slotID uint32) uint32 {
	ptr := m.getInnerIPPtr(slotID)
	if ptr == nil {
		return 0
	}
	return atomic.LoadUint32(ptr)
}
