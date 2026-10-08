package bpfmap

import "testing"

func TestTryUpdateInnerIPPreservesAllocatedState(t *testing.T) {
	m := NewMmappedSlotsForTest(2)
	if !m.TryAllocate(0, 0x0a000001) {
		t.Fatal("allocate")
	}
	slot := m.GetSlot(0)
	slot.Generation = 7
	slot.StatsReady = 1
	slot.GeneveOptsLen = 8
	before := *slot
	if !m.TryUpdateInnerIP(0, 0x0a000001, 0x0a000002) {
		t.Fatal("allocated address commit")
	}
	before.InnerIp = 0x0a000002
	if *slot != before {
		t.Fatal("address commit mutated other fields")
	}
	if !m.TryUpdateInnerIP(0, 0x0a000002, 0x0a000002) {
		t.Fatal("unchanged address commit")
	}
	for _, v := range []uint32{InnerIPFree, InnerIPReserved} {
		if m.TryUpdateInnerIP(0, 0x0a000002, v) || m.TryUpdateInnerIP(1, v, 0x0a000002) {
			t.Fatal("control state accepted")
		}
	}
	if m.TryUpdateInnerIP(2, 0x0a000002, 0x0a000003) || m.TryUpdateInnerIP(0, 0x0a000003, 0x0a000004) {
		t.Fatal("invalid slot/old address accepted")
	}
	if *slot != before {
		t.Fatal("failed CAS changed slot")
	}
}
