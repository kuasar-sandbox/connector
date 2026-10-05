package vswitch

import (
	"net"
	"strings"
	"testing"
)

func TestFloatingIPGenerationEncoding(t *testing.T) {
	base := uint32(0x64640000)
	seen := map[uint32]bool{}
	for generation := uint32(0); generation < 16; generation++ {
		got := FloatingIPForAttachment(base, 7, generation)
		want := base + (generation << 12) + 7
		if got != want || seen[got] {
			t.Fatalf("generation=%d got=%08x want=%08x duplicate=%v", generation, got, want, seen[got])
		}
		seen[got] = true
	}
}

func TestGenerationConfigValidation(t *testing.T) {
	base := Config{Name: "sw", SwitchNetNS: "ns", PortNetNS: "ports", NumPorts: MaxPorts, MACAddr: net.HardwareAddr{2, 0, 0, 0, 0, 1}, FloatingIPBase: net.ParseIP("100.100.0.0")}
	for _, tc := range []struct {
		name string
		bits uint8
		ip   string
		want string
	}{
		{"legacy", 0, "100.100.96.0", ""},
		{"four", 4, "100.100.0.0", ""},
		{"too-many", 21, "0.0.0.0", "generation_bits"},
		{"overflow", 4, "255.255.1.0", "overflows IPv4"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			c.GenerationBits = tc.bits
			c.FloatingIPBase = net.ParseIP(tc.ip)
			err := c.Validate()
			if tc.want == "" && err != nil {
				t.Fatal(err)
			}
			if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("err=%v want %q", err, tc.want)
			}
		})
	}
}
