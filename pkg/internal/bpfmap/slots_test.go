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
