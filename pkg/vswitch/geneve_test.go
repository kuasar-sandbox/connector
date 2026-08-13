package vswitch

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestGeneveLocatorParseStringJSON(t *testing.T) {
	tests := []struct {
		input string
		want  GeneveLocator
	}{
		{"", GeneveLocatorPort},
		{"port", GeneveLocatorPort},
		{"VNI", GeneveLocatorVNI},
		{"tlv", GeneveLocatorTLV},
	}
	for _, tt := range tests {
		got, err := ParseGeneveLocator(tt.input)
		if err != nil {
			t.Fatalf("ParseGeneveLocator(%q): %v", tt.input, err)
		}
		if got != tt.want {
			t.Fatalf("ParseGeneveLocator(%q) = %v, want %v", tt.input, got, tt.want)
		}
		data, err := json.Marshal(got)
		if err != nil {
			t.Fatalf("Marshal(%v): %v", got, err)
		}
		var roundTrip GeneveLocator
		if err := json.Unmarshal(data, &roundTrip); err != nil {
			t.Fatalf("Unmarshal(%s): %v", data, err)
		}
		if roundTrip != got || roundTrip.String() != got.String() {
			t.Fatalf("locator round trip = %v, want %v", roundTrip, got)
		}
	}

	var locator GeneveLocator
	if err := locator.Parse("bogus"); err == nil {
		t.Fatal("expected unknown locator error")
	}
	if _, err := json.Marshal(GeneveLocator(99)); err == nil {
		t.Fatal("expected invalid locator JSON error")
	}
	if err := json.Unmarshal([]byte(`"bogus"`), &locator); err == nil {
		t.Fatal("expected unknown locator JSON error")
	}
}

func TestGeneveTLVLocatorParseAndJSON(t *testing.T) {
	locator, err := ParseGeneveTLVLocator("0102:81")
	if err != nil {
		t.Fatal(err)
	}
	if locator.Class != 0x0102 || locator.Type != 0x81 || locator.String() != "0102:81" {
		t.Fatalf("unexpected locator: %#v (%s)", locator, locator.String())
	}
	data, err := json.Marshal(locator)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip GeneveTLVLocator
	if err := json.Unmarshal(data, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if roundTrip != locator {
		t.Fatalf("round trip = %#v, want %#v", roundTrip, locator)
	}

	for _, invalid := range []string{"", "0102", ":01", "0102:", "10000:01", "0102:100", "zzzz:01"} {
		if _, err := ParseGeneveTLVLocator(invalid); err == nil {
			t.Errorf("ParseGeneveTLVLocator(%q) unexpectedly succeeded", invalid)
		}
	}
}

func TestGeneveOptionParseCanonicalAndJSON(t *testing.T) {
	option, err := ParseGeneveOption("0102:83:1122334455667788")
	if err != nil {
		t.Fatal(err)
	}
	if option.Class != 0x0102 || option.Type != 0x83 ||
		!reflect.DeepEqual(option.Data, []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}) {
		t.Fatalf("unexpected option: %#v", option)
	}
	if got := option.String(); got != "0102:83:1122334455667788" {
		t.Fatalf("String() = %q", got)
	}
	data, err := json.Marshal(option)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip GeneveOption
	if err := json.Unmarshal(data, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(roundTrip, option) {
		t.Fatalf("round trip = %#v, want %#v", roundTrip, option)
	}
}

func TestAttachOptionsGeneveOptionsJSONName(t *testing.T) {
	data, err := json.Marshal(AttachOptions{
		TransitGeneveOpts: []GeneveOption{{Class: 0x0102, Type: 0x02, Data: []byte{0, 0, 0, 0x2a}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if got := string(fields["transit_geneve_opts"]); got != `["0102:02:0000002a"]` {
		t.Fatalf("transit_geneve_opts = %s", got)
	}
}

func TestGeneveOptionZeroLengthData(t *testing.T) {
	option, err := ParseGeneveOption("0102:02:")
	if err != nil {
		t.Fatal(err)
	}
	if len(option.Data) != 0 || option.String() != "0102:02:" {
		t.Fatalf("zero option = %#v (%q)", option, option.String())
	}
	value, total, err := marshalGeneveOptions(GeneveLocatorPort, nil, []GeneveOption{option})
	if err != nil {
		t.Fatal(err)
	}
	if value.Len != 4 || total != 4 || value.Data[3] != 0 {
		t.Fatalf("zero option wire = len %d total %d header %x", value.Len, total, value.Data[:4])
	}
}

func TestGeneveOptionParseErrors(t *testing.T) {
	for _, invalid := range []string{
		"", "0102:02", ":02:00000000", "0102::00000000",
		"10000:02:00000000", "0102:100:00000000", "0102:02:0",
		"0102:02:zz", "0102:02:0000",
	} {
		if _, err := ParseGeneveOption(invalid); err == nil {
			t.Errorf("ParseGeneveOption(%q) unexpectedly succeeded", invalid)
		}
	}
}

func TestParseGeneveOptionsPreservesOrder(t *testing.T) {
	options, err := ParseGeneveOptions("0102:02:0000002a,0102:83:1122334455667788")
	if err != nil {
		t.Fatal(err)
	}
	if len(options) != 2 || options[0].Type != 0x02 || options[1].Type != 0x83 {
		t.Fatalf("unexpected option order: %#v", options)
	}
	if empty, err := ParseGeneveOptions(""); err != nil || empty != nil {
		t.Fatalf("empty options = %#v, %v", empty, err)
	}
}

func TestMarshalGeneveOptionsWireAndCritical(t *testing.T) {
	options := []GeneveOption{
		{Class: 0x0102, Type: 0x02, Data: []byte{0, 0, 0, 0x2a}},
		{Class: 0x0103, Type: 0x83, Data: []byte{0x11, 0x22, 0x33, 0x44}},
	}
	value, total, err := marshalGeneveOptions(GeneveLocatorPort, nil, options)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		0x01, 0x02, 0x02, 0x01, 0, 0, 0, 0x2a,
		0x01, 0x03, 0x83, 0x01, 0x11, 0x22, 0x33, 0x44,
	}
	if value.Len != 16 || total != 16 || value.Critical != 1 || !reflect.DeepEqual(value.Data[:16], want) {
		t.Fatalf("wire value len=%d total=%d critical=%d data=%x", value.Len, total, value.Critical, value.Data[:16])
	}
}

func TestMarshalGeneveOptionsLocatorCollision(t *testing.T) {
	locator := &GeneveTLVLocator{Class: 0x0102, Type: 0x01}
	for _, optionType := range []uint8{0x01, 0x81} {
		_, _, err := marshalGeneveOptions(GeneveLocatorTLV, locator, []GeneveOption{{Class: 0x0102, Type: optionType}})
		if err == nil || !strings.Contains(err.Error(), "collides") {
			t.Fatalf("type %#x collision error = %v", optionType, err)
		}
	}
}

func TestMarshalGeneveOptionsLengthBoundaries(t *testing.T) {
	portMax := GeneveOption{Class: 1, Type: 2, Data: make([]byte, 60)} // 4 + 60 = 64
	value, total, err := marshalGeneveOptions(GeneveLocatorPort, nil, []GeneveOption{portMax})
	if err != nil || value.Len != 64 || total != 64 {
		t.Fatalf("port max: len=%d total=%d err=%v", value.Len, total, err)
	}
	if _, _, err := marshalGeneveOptions(GeneveLocatorPort, nil, []GeneveOption{{Class: 1, Type: 2, Data: make([]byte, 64)}}); err == nil {
		t.Fatal("expected port options overflow")
	}

	locator := &GeneveTLVLocator{Class: 0x0102, Type: 1}
	tlvMax := GeneveOption{Class: 2, Type: 2, Data: make([]byte, 52)} // 56 + locator 8 = 64
	value, total, err = marshalGeneveOptions(GeneveLocatorTLV, locator, []GeneveOption{tlvMax})
	if err != nil || value.Len != 56 || total != 64 {
		t.Fatalf("tlv max: len=%d total=%d err=%v", value.Len, total, err)
	}
	if _, _, err := marshalGeneveOptions(GeneveLocatorTLV, locator, []GeneveOption{{Class: 2, Type: 2, Data: make([]byte, 56)}}); err == nil {
		t.Fatal("expected TLV total options overflow")
	}
}

func TestValidateTransitGeneveVNI(t *testing.T) {
	for _, locator := range []GeneveLocator{GeneveLocatorPort, GeneveLocatorTLV} {
		if err := validateTransitGeneveVNI(locator, 0xffffff); err != nil {
			t.Fatalf("%s max VNI: %v", locator, err)
		}
		if err := validateTransitGeneveVNI(locator, 0x1000000); err == nil {
			t.Fatalf("%s accepted 25-bit VNI", locator)
		}
	}
	if err := validateTransitGeneveVNI(GeneveLocatorVNI, 0x0fff); err != nil {
		t.Fatal(err)
	}
	if err := validateTransitGeneveVNI(GeneveLocatorVNI, 0x1000); err == nil {
		t.Fatal("VNI locator accepted VNI > 12 bits")
	}
}

func TestGeneveWireValues(t *testing.T) {
	if got := geneveWirePort(GeneveLocatorPort, 50000, 7); got != 50007 {
		t.Fatalf("port locator UDP = %d", got)
	}
	for _, locator := range []GeneveLocator{GeneveLocatorVNI, GeneveLocatorTLV} {
		if got := geneveWirePort(locator, 50000, 7); got != GeneveStandardPort {
			t.Fatalf("%s UDP = %d", locator, got)
		}
	}
	if got := geneveWireVNI(GeneveLocatorVNI, 0xabc, 0x123); got != 0xabc123 {
		t.Fatalf("VNI wire value = %#x", got)
	}
	if got := geneveWireVNI(GeneveLocatorTLV, 7, 0xabcdef); got != 0xabcdef {
		t.Fatalf("TLV wire VNI = %#x", got)
	}
}
