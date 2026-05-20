package bpf

import (
	"net"
	"testing"
)

func TestIntsToString(t *testing.T) {
	cases := []struct {
		input []int8
		want  string
	}{
		{[]int8{'h', 'e', 'l', 'l', 'o', 0, 'w', 'o', 'r', 'l', 'd'}, "hello"},
		{[]int8{'n', 'o', 't', 'e', 'r', 'm'}, "noterm"},
		{[]int8{0, 'l', 'e', 'a', 'd', 'i', 'n', 'g'}, ""},
		{[]int8{}, ""},
	}
	for _, tc := range cases {
		got := IntsToString(tc.input)
		if got != tc.want {
			t.Errorf("IntsToString(%v) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestCopyStringToInts(t *testing.T) {
	tests := []struct {
		name     string
		src      string
		dstSize  int
		expected string
	}{
		{"short string", "hello", 10, "hello"},
		{"exact fit", "hello", 5, "hello"},
		{"truncate", "hello world", 5, "hello"},
		{"empty string", "", 5, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dst := make([]int8, tc.dstSize)
			CopyStringToInts(dst, tc.src)
			got := IntsToString(dst)
			if got != tc.expected {
				t.Errorf("CopyStringToInts(%q) -> IntsToString() = %q, want %q", tc.src, got, tc.expected)
			}
		})
	}
}

func TestCopyStringToIntsClearsFirst(t *testing.T) {
	// Test that CopyStringToInts clears the buffer first
	dst := []int8{'x', 'x', 'x', 'x', 'x'}
	CopyStringToInts(dst, "hi")
	// Should be "hi\0\0\0"
	if dst[0] != 'h' || dst[1] != 'i' || dst[2] != 0 || dst[3] != 0 || dst[4] != 0 {
		t.Errorf("CopyStringToInts didn't clear buffer correctly: %v", dst)
	}
}

func TestSwitchConfigMacMethods(t *testing.T) {
	cfg := &SwitchConfig{}

	switchMAC, _ := net.ParseMAC("02:00:00:00:00:01")
	portMAC, _ := net.ParseMAC("02:00:00:00:00:02")

	cfg.SetSwitchMacAddr(switchMAC)
	cfg.SetPortMacAddr(portMAC)

	if got := cfg.SwitchMacAddr().String(); got != "02:00:00:00:00:01" {
		t.Errorf("SwitchMacAddr() = %s, want 02:00:00:00:00:01", got)
	}
	if got := cfg.PortMacAddr().String(); got != "02:00:00:00:00:02" {
		t.Errorf("PortMacAddr() = %s, want 02:00:00:00:00:02", got)
	}
}

func TestSwitchConfigIsPortMacZero(t *testing.T) {
	cfg := &SwitchConfig{}

	if !cfg.IsPortMacZero() {
		t.Error("IsPortMacZero() should be true for zero MAC")
	}

	mac, _ := net.ParseMAC("02:00:00:00:00:01")
	cfg.SetPortMacAddr(mac)

	if cfg.IsPortMacZero() {
		t.Error("IsPortMacZero() should be false for non-zero MAC")
	}
}

func TestMgmtCIDRMacMethods(t *testing.T) {
	cidr := &MgmtCIDR{}

	mac, _ := net.ParseMAC("02:00:00:00:ff:f0")
	cidr.SetMgmtMacAddr(mac)

	if got := cidr.MgmtMacAddr().String(); got != "02:00:00:00:ff:f0" {
		t.Errorf("MgmtMacAddr() = %s, want 02:00:00:00:ff:f0", got)
	}
}

func TestSlotItemTransitMacMethods(t *testing.T) {
	slot := &SlotItem{}

	// Initially zero
	if slot.IsTransitMacSet() {
		t.Error("IsTransitMacSet() should be false for zero MAC")
	}

	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	slot.SetTransitMacAddr(mac)

	if !slot.IsTransitMacSet() {
		t.Error("IsTransitMacSet() should be true after setting")
	}
	if got := slot.TransitMacAddr().String(); got != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("TransitMacAddr() = %s, want aa:bb:cc:dd:ee:ff", got)
	}

	slot.ClearTransitMac()
	if slot.IsTransitMacSet() {
		t.Error("IsTransitMacSet() should be false after clearing")
	}
}

func TestIPToUint32(t *testing.T) {
	tests := []struct {
		ip   string
		want uint32
	}{
		{"0.0.0.0", 0},
		{"0.0.0.1", 1},
		{"10.0.0.1", 0x0a000001},
		{"192.168.1.1", 0xc0a80101},
		{"255.255.255.255", 0xffffffff},
	}

	for _, tc := range tests {
		got := IPToUint32(net.ParseIP(tc.ip))
		if got != tc.want {
			t.Errorf("IPToUint32(%s) = 0x%08x, want 0x%08x", tc.ip, got, tc.want)
		}
	}
}

func TestIPToUint32Nil(t *testing.T) {
	if got := IPToUint32(nil); got != 0 {
		t.Errorf("IPToUint32(nil) = %d, want 0", got)
	}
}

func TestUint32ToIP(t *testing.T) {
	tests := []struct {
		n    uint32
		want string
	}{
		{0, "0.0.0.0"},
		{1, "0.0.0.1"},
		{0x0a000001, "10.0.0.1"},
		{0xc0a80101, "192.168.1.1"},
	}

	for _, tc := range tests {
		got := Uint32ToIP(tc.n)
		if got.String() != tc.want {
			t.Errorf("Uint32ToIP(0x%x) = %s, want %s", tc.n, got, tc.want)
		}
	}
}

func TestIPRoundTrip(t *testing.T) {
	ips := []string{"10.0.0.1", "172.16.0.1", "100.100.96.0"}
	for _, s := range ips {
		ip := net.ParseIP(s)
		n := IPToUint32(ip)
		back := Uint32ToIP(n)
		if !ip.Equal(back) {
			t.Errorf("round-trip failed: %s -> 0x%x -> %s", s, n, back)
		}
	}
}

func TestMaskToUint32(t *testing.T) {
	tests := []struct {
		bits int
		want uint32
	}{
		{32, 0xffffffff},
		{24, 0xffffff00},
		{16, 0xffff0000},
		{0, 0x00000000},
	}

	for _, tc := range tests {
		mask := net.CIDRMask(tc.bits, 32)
		got := MaskToUint32(mask)
		if got != tc.want {
			t.Errorf("MaskToUint32(/%d) = 0x%08x, want 0x%08x", tc.bits, got, tc.want)
		}
	}
}

func TestMaskToUint32IPv6Mask(t *testing.T) {
	// 16-byte mask, last 4 bytes = /24
	mask := net.CIDRMask(120, 128) // last 4 bytes: 0xffffff00
	got := MaskToUint32(mask)
	if got != 0xffffff00 {
		t.Errorf("MaskToUint32(ipv6/120) = 0x%08x, want 0xffffff00", got)
	}
}

func TestMaskToUint32OddLength(t *testing.T) {
	// Neither 4 nor 16 bytes — should return 0xffffffff
	mask := net.IPMask{0xff, 0xff}
	got := MaskToUint32(mask)
	if got != 0xffffffff {
		t.Errorf("MaskToUint32(2-byte) = 0x%08x, want 0xffffffff", got)
	}
}

func TestMaskPrefixLen(t *testing.T) {
	tests := []struct {
		name     string
		mask     uint32
		expected int
	}{
		{"32-bit mask", 0xffffffff, 32},
		{"24-bit mask", 0xffffff00, 24},
		{"16-bit mask", 0xffff0000, 16},
		{"8-bit mask", 0xff000000, 8},
		{"0-bit mask", 0x00000000, 0},
		{"31-bit mask", 0xfffffffe, 31},
		{"1-bit mask", 0x80000000, 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := MaskPrefixLen(tc.mask)
			if got != tc.expected {
				t.Errorf("MaskPrefixLen(0x%08x) = %d, want %d", tc.mask, got, tc.expected)
			}
		})
	}
}

func TestConstantTypes(t *testing.T) {
	// Verify constants are the expected type (all uint32)
	_ = MaxPorts + 1           // uint32 arithmetic
	_ = MaxMgmtCIDRPerSlot + 1 // uint32 arithmetic
	_ = InnerIPFree + 1        // uint32 arithmetic
	_ = InnerIPReserved - 1    // uint32 arithmetic (can't add 1 to 0xFFFFFFFF)

	// Verify constants can be used in loops
	for i := uint32(0); i < MaxPorts; i++ {
		_ = i
		break // Don't actually loop
	}
	for i := uint32(0); i < MaxMgmtCIDRPerSlot; i++ {
		_ = i
		break
	}
}
