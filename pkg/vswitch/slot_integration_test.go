//go:build integration

package vswitch

import (
	"os"
	"sync"
	"testing"

	"github.com/fullof-work/sandbox-vswitch/pkg/internal/bpf"
)

func skipIfNotRoot(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
}

// TestMmappedSlotsWithRealMap tests MmappedSlots with actual BPF map mmap.
func TestMmappedSlotsWithRealMap(t *testing.T) {
	skipIfNotRoot(t)

	objs, err := bpf.LoadObjects()
	if err != nil {
		t.Fatalf("LoadObjects: %v", err)
	}
	defer objs.Close()

	numSlots := uint32(16)

	// Create mmap'd slots
	mmapSlots, err := NewMmappedSlots(objs.Maps.Slots, numSlots)
	if err != nil {
		t.Fatalf("NewMmappedSlots: %v", err)
	}
	defer mmapSlots.Close()

	// Verify initial state (all slots should be empty)
	for i := uint32(0); i < numSlots; i++ {
		if ip := mmapSlots.GetInnerIP(i); ip != 0 {
			t.Errorf("slot %d: initial InnerIP = %#x, want 0", i, ip)
		}
	}
}

// TestMmappedSlotsCASWithRealMap tests atomic CAS operations with real BPF map.
func TestMmappedSlotsCASWithRealMap(t *testing.T) {
	skipIfNotRoot(t)

	objs, err := bpf.LoadObjects()
	if err != nil {
		t.Fatalf("LoadObjects: %v", err)
	}
	defer objs.Close()

	numSlots := uint32(16)

	mmapSlots, err := NewMmappedSlots(objs.Maps.Slots, numSlots)
	if err != nil {
		t.Fatalf("NewMmappedSlots: %v", err)
	}
	defer mmapSlots.Close()

	// TryAllocate on empty slot should succeed
	if !mmapSlots.TryAllocate(0, 0x0a000001) {
		t.Error("TryAllocate on empty slot should succeed")
	}

	// Verify InnerIP was set
	if ip := mmapSlots.GetInnerIP(0); ip != 0x0a000001 {
		t.Errorf("InnerIP = %#x, want %#x", ip, 0x0a000001)
	}

	// TryAllocate on occupied slot should fail
	if mmapSlots.TryAllocate(0, 0x0a000002) {
		t.Error("TryAllocate on occupied slot should fail")
	}

	// TryRelease with correct IP should succeed
	if !mmapSlots.TryRelease(0, 0x0a000001) {
		t.Error("TryRelease with correct IP should succeed")
	}

	// Verify slot is now free
	if ip := mmapSlots.GetInnerIP(0); ip != 0 {
		t.Errorf("InnerIP after release = %#x, want 0", ip)
	}

	// TryRelease on empty slot should fail
	if mmapSlots.TryRelease(0, 0x0a000001) {
		t.Error("TryRelease on empty slot should fail")
	}
}

// TestMmappedSlotsFindFreeSlotWithRealMap tests FindFreeSlot with real BPF map.
func TestMmappedSlotsFindFreeSlotWithRealMap(t *testing.T) {
	skipIfNotRoot(t)

	objs, err := bpf.LoadObjects()
	if err != nil {
		t.Fatalf("LoadObjects: %v", err)
	}
	defer objs.Close()

	numSlots := uint32(8)

	mmapSlots, err := NewMmappedSlots(objs.Maps.Slots, numSlots)
	if err != nil {
		t.Fatalf("NewMmappedSlots: %v", err)
	}
	defer mmapSlots.Close()

	// Allocate several slots
	for i := uint32(0); i < 4; i++ {
		ip := 0x0a000001 + i
		slotID, err := mmapSlots.FindFreeSlot(ip)
		if err != nil {
			t.Fatalf("FindFreeSlot %d: %v", i, err)
		}
		if slotID != i {
			t.Errorf("FindFreeSlot %d: got slotID %d, want %d", i, slotID, i)
		}
	}

	// Release slot 2
	if !mmapSlots.TryRelease(2, 0x0a000003) {
		t.Fatal("TryRelease slot 2 failed")
	}

	// FindFreeSlot should return slot 2
	slotID, err := mmapSlots.FindFreeSlot(0x0a000010)
	if err != nil {
		t.Fatalf("FindFreeSlot after release: %v", err)
	}
	if slotID != 2 {
		t.Errorf("FindFreeSlot after release: got %d, want 2", slotID)
	}

	// Cleanup: release all allocated slots
	for i := uint32(0); i < numSlots; i++ {
		ip := mmapSlots.GetInnerIP(i)
		if ip != 0 {
			mmapSlots.TryRelease(i, ip)
		}
	}
}

// TestMmappedSlotsUpdateFieldsWithRealMap tests updating slot fields via mmap.
func TestMmappedSlotsUpdateFieldsWithRealMap(t *testing.T) {
	skipIfNotRoot(t)

	objs, err := bpf.LoadObjects()
	if err != nil {
		t.Fatalf("LoadObjects: %v", err)
	}
	defer objs.Close()

	numSlots := uint32(4)

	mmapSlots, err := NewMmappedSlots(objs.Maps.Slots, numSlots)
	if err != nil {
		t.Fatalf("NewMmappedSlots: %v", err)
	}
	defer mmapSlots.Close()

	// Allocate slot
	if !mmapSlots.TryAllocate(0, 0x0a000001) {
		t.Fatal("TryAllocate failed")
	}
	defer mmapSlots.TryRelease(0, 0x0a000001)

	// Update fields
	mmapSlots.UpdateSlotFields(0, func(slot *SlotItem) {
		slot.Ifindex = 42
		slot.TransitGatewayIp = 0xc0a80101
		slot.TransitGeneveVni = 12345
		slot.TransitMac = [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
		slot.MgmtCidrCount = 1
		slot.MgmtCidrs0 = MgmtCIDR{
			Ip:      0x0a000000,
			Mask:    0xff000000,
			Ifindex: 5,
			MgmtMac: [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02},
		}
	})

	// Verify fields via GetSlot
	slot := mmapSlots.GetSlot(0)
	if slot.Ifindex != 42 {
		t.Errorf("Ifindex = %d, want 42", slot.Ifindex)
	}
	if slot.TransitGatewayIp != 0xc0a80101 {
		t.Errorf("TransitGatewayIp = %#x, want %#x", slot.TransitGatewayIp, 0xc0a80101)
	}
	if slot.TransitGeneveVni != 12345 {
		t.Errorf("TransitGeneveVni = %d, want 12345", slot.TransitGeneveVni)
	}
	expectedMAC := [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	if slot.TransitMac != expectedMAC {
		t.Errorf("TransitMac = %v, want %v", slot.TransitMac, expectedMAC)
	}
	if slot.MgmtCidrCount != 1 {
		t.Errorf("MgmtCidrCount = %d, want 1", slot.MgmtCidrCount)
	}
	if slot.MgmtCidrs0.Ip != 0x0a000000 {
		t.Errorf("MgmtCidrs0.Ip = %#x, want %#x", slot.MgmtCidrs0.Ip, 0x0a000000)
	}
}

// TestMmappedSlotsConcurrentWithRealMap tests concurrent access with real BPF map.
func TestMmappedSlotsConcurrentWithRealMap(t *testing.T) {
	skipIfNotRoot(t)

	objs, err := bpf.LoadObjects()
	if err != nil {
		t.Fatalf("LoadObjects: %v", err)
	}
	defer objs.Close()

	numSlots := uint32(64)

	mmapSlots, err := NewMmappedSlots(objs.Maps.Slots, numSlots)
	if err != nil {
		t.Fatalf("NewMmappedSlots: %v", err)
	}
	defer mmapSlots.Close()

	// Multiple goroutines compete for slots
	const numGoroutines = 8
	const numIterations = 50

	var wg sync.WaitGroup
	allocCount := make([]int, numGoroutines)

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			ip := uint32(0x0a000001 + gid)
			for i := 0; i < numIterations; i++ {
				// Find and allocate a free slot
				for s := uint32(0); s < numSlots; s++ {
					if mmapSlots.TryAllocate(s, ip) {
						allocCount[gid]++
						// Immediately release
						mmapSlots.TryRelease(s, ip)
						break
					}
				}
			}
		}(g)
	}

	wg.Wait()

	// Verify all slots are free
	for i := uint32(0); i < numSlots; i++ {
		if ip := mmapSlots.GetInnerIP(i); ip != 0 {
			t.Errorf("slot %d still allocated: %#x", i, ip)
		}
	}

	// Verify some allocations succeeded
	total := 0
	for _, c := range allocCount {
		total += c
	}
	if total == 0 {
		t.Error("no allocations succeeded in concurrent test")
	}
	t.Logf("total allocations across %d goroutines: %d", numGoroutines, total)
}

// TestMmappedSlotsSingleSlotContention tests contention on a single slot.
func TestMmappedSlotsSingleSlotContention(t *testing.T) {
	skipIfNotRoot(t)

	objs, err := bpf.LoadObjects()
	if err != nil {
		t.Fatalf("LoadObjects: %v", err)
	}
	defer objs.Close()

	mmapSlots, err := NewMmappedSlots(objs.Maps.Slots, 1)
	if err != nil {
		t.Fatalf("NewMmappedSlots: %v", err)
	}
	defer mmapSlots.Close()

	// Multiple goroutines compete for the same slot
	const numGoroutines = 10
	winners := make(chan int, numGoroutines)

	var wg sync.WaitGroup
	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			ip := uint32(0x0a000001 + gid)
			if mmapSlots.TryAllocate(0, ip) {
				winners <- gid
			}
		}(g)
	}

	wg.Wait()
	close(winners)

	// Exactly one should win
	count := 0
	var winner int
	for gid := range winners {
		count++
		winner = gid
	}
	if count != 1 {
		t.Errorf("expected exactly 1 winner, got %d", count)
	}

	// Verify winner's IP is in the slot
	expectedIP := uint32(0x0a000001 + winner)
	if ip := mmapSlots.GetInnerIP(0); ip != expectedIP {
		t.Errorf("InnerIP = %#x, want %#x", ip, expectedIP)
	}

	// Cleanup
	mmapSlots.TryRelease(0, expectedIP)
}

// TestMmappedSlotsMapConsistency verifies mmap writes are visible via map lookup.
func TestMmappedSlotsMapConsistency(t *testing.T) {
	skipIfNotRoot(t)

	objs, err := bpf.LoadObjects()
	if err != nil {
		t.Fatalf("LoadObjects: %v", err)
	}
	defer objs.Close()

	numSlots := uint32(4)

	mmapSlots, err := NewMmappedSlots(objs.Maps.Slots, numSlots)
	if err != nil {
		t.Fatalf("NewMmappedSlots: %v", err)
	}
	defer mmapSlots.Close()

	// Write via mmap
	if !mmapSlots.TryAllocate(0, 0x0a000001) {
		t.Fatal("TryAllocate failed")
	}
	mmapSlots.UpdateSlotFields(0, func(slot *SlotItem) {
		slot.Ifindex = 123
		slot.TransitGeneveVni = 9999
	})

	// Read via map lookup (not mmap)
	var slot SlotItem
	key := uint32(0)
	if err := objs.Maps.Slots.Lookup(key, &slot); err != nil {
		t.Fatalf("Slots.Lookup: %v", err)
	}

	// Verify consistency
	if slot.InnerIp != 0x0a000001 {
		t.Errorf("InnerIp via lookup = %#x, want %#x", slot.InnerIp, 0x0a000001)
	}
	if slot.Ifindex != 123 {
		t.Errorf("Ifindex via lookup = %d, want 123", slot.Ifindex)
	}
	if slot.TransitGeneveVni != 9999 {
		t.Errorf("TransitGeneveVni via lookup = %d, want 9999", slot.TransitGeneveVni)
	}

	// Cleanup
	mmapSlots.TryRelease(0, 0x0a000001)
}
