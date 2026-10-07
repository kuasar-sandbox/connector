package bpfmap

import "testing"

// TestMmappedSlotsClose exercises Close's idempotency with already-nil data.
// Constructed via the package-internal struct literal because newMmappedSlotsForTest
// allocates memory via make() — unix.Munmap on which would fail.
func TestMmappedSlotsClose(t *testing.T) {
	m := &MmappedSlots{
		data:     nil, // Already "closed"
		slotSize: 256,
		numSlots: 4,
	}

	// Close on nil data should be idempotent (no error)
	if err := m.Close(); err != nil {
		t.Errorf("Close on nil data: %v", err)
	}

	// Multiple closes should be safe
	if err := m.Close(); err != nil {
		t.Errorf("Second Close should be idempotent: %v", err)
	}

	// After close, data should still be nil
	if m.data != nil {
		t.Error("data should be nil after Close")
	}
}

// TestMmappedSlotsClosePreservesOtherFields verifies that Close clears the
// data slice but leaves the slot/count fields intact (callers that check
// counts after Close should still see meaningful values).
func TestMmappedSlotsClosePreservesOtherFields(t *testing.T) {
	m := NewMmappedSlotsForTest(4)
	m.Close()

	if m.numSlots != 4 {
		t.Errorf("numSlots = %d, want 4", m.numSlots)
	}
}

func TestTryAllocateLoserDoesNotMutateStatsReady(t *testing.T) {
	m := NewMmappedSlotsForTest(1)
	if !m.TryAllocate(0, 0x0a000001) {
		t.Fatal("initial allocate")
	}
	m.GetSlot(0).StatsReady = 1
	if m.TryAllocate(0, 0x0a000002) {
		t.Fatal("second allocate unexpectedly won")
	}
	if got := m.GetSlot(0).StatsReady; got != 1 {
		t.Fatalf("loser changed stats_ready=%d", got)
	}
}

func TestTryUnreservePublishesFreeDown(t *testing.T) {
	m := NewMmappedSlotsForTest(1)
	if !m.TryReserve(0, InnerIPFree) {
		t.Fatal("reserve")
	}
	m.GetSlot(0).Flags = 1
	if !m.TryUnreserve(0) {
		t.Fatal("unreserve")
	}
	if got := m.GetInnerIP(0); got != InnerIPFree {
		t.Fatalf("inner=%#x", got)
	}
	if got := m.GetSlot(0).Flags; got != 0 {
		t.Fatalf("flags=%#x", got)
	}
}
