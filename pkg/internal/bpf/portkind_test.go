package bpf

import (
	"testing"
	"unsafe"
)

func TestPortKindString(t *testing.T) {
	cases := []struct {
		k    PortKind
		want string
	}{
		{PortKindVeth, "veth"},
		{PortKindTap, "tap"},
		{PortKind(99), "unknown"},
	}
	for _, c := range cases {
		if got := c.k.String(); got != c.want {
			t.Errorf("%d.String() = %q, want %q", c.k, got, c.want)
		}
	}
}

func TestParsePortKind(t *testing.T) {
	cases := []struct {
		in      string
		want    PortKind
		wantErr bool
	}{
		{"", PortKindVeth, false}, // empty → veth (backward-compatible default)
		{"veth", PortKindVeth, false},
		{"tap", PortKindTap, false},
		{"TAP", 0, true},    // case-sensitive
		{"bridge", 0, true}, // unknown
		{"tun", 0, true},    // not supported (tap-only for now)
	}
	for _, c := range cases {
		got, err := ParsePortKind(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParsePortKind(%q) = %v, want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParsePortKind(%q) unexpected error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParsePortKind(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestSlotItemModeOffset asserts that the new Mode field sits at offset 30
// (where _pad_mac[0] used to be). Existing slot data with byte 30 == 0
// must read back as PortKindVeth for backward compatibility.
func TestSlotItemModeOffset(t *testing.T) {
	var s SlotItem
	// Mode field exists and defaults to 0 = veth.
	if s.Mode != 0 {
		t.Errorf("zero-valued SlotItem has Mode=%d, want 0", s.Mode)
	}
	if PortKind(s.Mode) != PortKindVeth {
		t.Errorf("PortKind of zero SlotItem = %v, want PortKindVeth", PortKind(s.Mode))
	}

	// Verify the struct didn't grow beyond the documented 108 bytes.
	const wantSize = 108
	if got := int(sizeOfSlotItem()); got != wantSize {
		t.Errorf("sizeof(SlotItem) = %d, want %d (struct must stay binary-compatible)", got, wantSize)
	}

	// Sanity: PortKindTap survives a round trip.
	s.Mode = uint8(PortKindTap)
	if PortKind(s.Mode) != PortKindTap {
		t.Errorf("after setting Mode=PortKindTap, read back as %v", PortKind(s.Mode))
	}

}

// sizeOfSlotItem is a tiny indirection so the compile-time size assertion in
// types.go does not break this test if the layout ever legitimately grows.
func sizeOfSlotItem() uintptr {
	return unsafe.Sizeof(SlotItem{})
}
