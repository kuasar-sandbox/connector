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
	if !atomic.CompareAndSwapUint32(ptr, InnerIPFree, innerIP) {
		return false
	}
	// Only the CAS winner may mutate attachment-owned state. Free slots are
	// dataplane-down on current switches, so readiness can be invalidated after
	// ownership is acquired without exposing the previous attachment.
	atomic.StoreUint32(&m.GetSlot(slotID).StatsReady, 0)
	return true
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
	if atomic.LoadUint32(ptr) != InnerIPReserved {
		return false
	}
	// Reserved is control-owned and cannot be attached. Clear dataplane
	// publication before exposing Free so a subsequent Attach always starts
	// from a fail-closed slot.
	atomic.StoreUint32(&m.GetSlot(slotID).Flags, 0)
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

// TryUpdateInnerIP changes the address of an already allocated, down port.
// It never transitions through Free or Reserved.
func (m *MmappedSlots) TryUpdateInnerIP(slotID, oldIP, newIP uint32) bool {
	if !IsSlotAllocated(oldIP) || !IsSlotAllocated(newIP) {
		return false
	}
	ptr := m.getInnerIPPtr(slotID)
	return ptr != nil && atomic.CompareAndSwapUint32(ptr, oldIP, newIP)
}
