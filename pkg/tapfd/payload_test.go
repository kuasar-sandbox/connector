package tapfd

import (
	"bytes"
	"strings"
	"testing"
)

func TestPortMetadataMarshalRoundTrip(t *testing.T) {
	in := PortMetadata{
		Port:    7,
		MAC:     "02:00:00:00:80:07",
		InnerIP: "169.254.1.7",
		FDCount: 1,
	}
	wire, err := in.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if wire[len(wire)-1] != 0 {
		t.Errorf("payload must end with NUL byte, got tail %#x", wire[len(wire)-1])
	}
	// Field ordering is documented; tests pin it to catch accidental changes.
	want := "port=7 mac=02:00:00:00:80:07 ip=169.254.1.7 fd=1\x00"
	if string(wire) != want {
		t.Errorf("wire mismatch:\n got: %q\nwant: %q", string(wire), want)
	}

	out, err := ParsePayload(wire)
	if err != nil {
		t.Fatalf("ParsePayload: %v", err)
	}
	if *out != in {
		t.Errorf("roundtrip mismatch:\n got: %+v\nwant: %+v", *out, in)
	}
}

func TestPortMetadataMarshalNetnsFD(t *testing.T) {
	in := PortMetadata{
		Port:         3,
		MAC:          "02:00:00:00:80:03",
		InnerIP:      "169.254.1.3",
		FDCount:      1,
		NetnsFDCount: 1,
	}
	wire, err := in.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	// netns_fd is appended after fd when nonzero.
	want := "port=3 mac=02:00:00:00:80:03 ip=169.254.1.3 fd=1 netns_fd=1\x00"
	if string(wire) != want {
		t.Errorf("wire mismatch:\n got: %q\nwant: %q", string(wire), want)
	}
	out, err := ParsePayload(wire)
	if err != nil {
		t.Fatalf("ParsePayload: %v", err)
	}
	if *out != in {
		t.Errorf("roundtrip mismatch:\n got: %+v\nwant: %+v", *out, in)
	}
}

func TestPortMetadataMarshalOmitsNetnsFDWhenZero(t *testing.T) {
	// Default (no netns fd) wire must not advertise extra fd-bearing metadata,
	// so receivers and the fd-count check are unaffected.
	in := PortMetadata{Port: 1, MAC: "02:00:00:00:80:01", InnerIP: "1.2.3.4", FDCount: 1}
	wire, err := in.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(wire), "netns_fd") {
		t.Errorf("netns_fd must be omitted when NetnsFDCount=0, got %q", string(wire))
	}
}

func TestPortMetadataMarshalValidates(t *testing.T) {
	cases := []struct {
		name string
		in   PortMetadata
		want string // substring expected in error
	}{
		{"empty MAC", PortMetadata{Port: 1, InnerIP: "1.2.3.4", FDCount: 1}, "MAC is required"},
		{"empty IP", PortMetadata{Port: 1, MAC: "02:00:00:00:80:01", FDCount: 1}, "InnerIP is required"},
		{"zero FDCount", PortMetadata{Port: 1, MAC: "02:00:00:00:80:01", InnerIP: "1.2.3.4"}, "FDCount must be at least 1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := c.in.Marshal()
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not contain %q", err.Error(), c.want)
			}
		})
	}
}

func TestParsePayloadStripsAfterNul(t *testing.T) {
	// Bytes after the NUL terminator must be ignored (could be garbage from
	// previous socket state or padding).
	buf := []byte("port=1 mac=02:00:00:00:80:01 ip=1.2.3.4 fd=1\x00GARBAGE")
	m, err := ParsePayload(buf)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if m.Port != 1 || m.MAC != "02:00:00:00:80:01" || m.InnerIP != "1.2.3.4" || m.FDCount != 1 {
		t.Errorf("unexpected parse result: %+v", m)
	}
}

func TestParsePayloadIgnoresUnknownKeys(t *testing.T) {
	// Forward compat: receivers built against v1 must not break when a future
	// sender adds new keys.
	buf := []byte("port=1 mac=02:0:0:0:0:1 mtu=9000 ip=10.0.0.1 fd=2 future_key=value extra=blah\x00")
	m, err := ParsePayload(buf)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if m.FDCount != 2 || m.InnerIP != "10.0.0.1" {
		t.Errorf("unexpected: %+v", m)
	}
}

func TestParsePayloadRejectsMalformedToken(t *testing.T) {
	buf := []byte("port=1 mac_without_equals mtu=1500\x00")
	if _, err := ParsePayload(buf); err == nil {
		t.Fatal("expected error for malformed token")
	}
}

func TestPortMetadataPayloadFitsLimit(t *testing.T) {
	// Worst-case realistic payload: longest possible IP + longest device name.
	in := PortMetadata{
		Port:    4096,
		MAC:     "ff:ff:ff:ff:ff:ff",
		InnerIP: "255.255.255.255",
		FDCount: 255,
	}
	wire, err := in.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if len(wire) > MaxPayloadSize {
		t.Errorf("worst-case wire size %d exceeds MaxPayloadSize=%d", len(wire), MaxPayloadSize)
	}
	if !bytes.Contains(wire, []byte("port=4096")) {
		t.Errorf("expected 'port=4096' in wire: %q", string(wire))
	}
}
