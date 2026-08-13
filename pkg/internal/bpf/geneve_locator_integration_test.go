//go:build integration

package bpf_test

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/kuasar-sandbox/connector/pkg/internal/bpf"
	"github.com/kuasar-sandbox/connector/pkg/vswitch"
)

const (
	geneveTestSlotID = uint32(2)
	geneveTestVNI    = uint32(0x12345)
	geneveTestVNILow = uint32(0x0abc)
)

var geneveTestTransitMAC = [6]byte{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}

func wireGeneveOption(class uint16, optionType uint8, data []byte) []byte {
	if len(data)%4 != 0 || len(data) > 0x7c {
		panic("GENEVE option test data must be aligned and fit the 5-bit length")
	}
	wire := make([]byte, 4+len(data))
	binary.BigEndian.PutUint16(wire[0:2], class)
	wire[2] = optionType
	wire[3] = byte(len(data) / 4)
	copy(wire[4:], data)
	return wire
}

func wireGeneveLocator(class uint16, optionType uint8, slotID uint32) []byte {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, slotID)
	return wireGeneveOption(class, optionType, data)
}

func testSetupGeneveMaps(
	t *testing.T,
	objs *bpf.Objects,
	locator vswitch.GeneveLocator,
	tlvClass uint16,
	tlvType uint8,
	encapEth bool,
	transitVNI uint32,
	opaque []byte,
	opaqueCritical bool,
) {
	t.Helper()

	cfg := vswitch.SwitchConfig{
		SwitchMac:      testSwitchMAC,
		N_ports:        testNumPorts,
		FloatingIpBase: testFloatingIPBase,
		GenevePortBase: testGenevePortBase,
		GeneveLocator:  uint8(locator),
		GeneveTlvClass: tlvClass,
		GeneveTlvType:  tlvType,
	}
	if encapEth {
		cfg.GeneveEncapEth = 1
	}
	if err := objs.Maps.Config.Update(uint32(0), &cfg, ebpf.UpdateAny); err != nil {
		t.Fatalf("update config: %v", err)
	}

	slot := vswitch.SlotItem{
		Ifindex:          100,
		InnerIp:          0x0a010002,
		TransitIfindex:   200,
		TransitIp:        0xc0000201,
		TransitGatewayIp: 0xc0000202,
		TransitGeneveVni: transitVNI,
		TransitMac:       geneveTestTransitMAC,
		GeneveOptsLen:    uint8(len(opaque)),
	}
	if err := objs.Maps.Slots.Update(geneveTestSlotID, &slot, ebpf.UpdateAny); err != nil {
		t.Fatalf("update slot: %v", err)
	}
	if err := objs.Maps.IfindexToSlot.Update(uint32(0), geneveTestSlotID, ebpf.UpdateAny); err != nil {
		t.Fatalf("update ifindex mapping: %v", err)
	}

	var optionValue vswitch.GeneveOptsValue
	optionValue.Len = uint8(len(opaque))
	if opaqueCritical {
		optionValue.Critical = 1
	}
	copy(optionValue.Data[:], opaque)
	if err := objs.Maps.GeneveOpts.Update(geneveTestSlotID, &optionValue, ebpf.UpdateAny); err != nil {
		t.Fatalf("update GENEVE options: %v", err)
	}
}

func expectedGeneveSourcePort(srcIP, dstIP net.IP, protocol uint8, srcPort, dstPort uint16) uint16 {
	hash := binary.BigEndian.Uint32(srcIP.To4()) ^ binary.BigEndian.Uint32(dstIP.To4()) ^ uint32(protocol)
	hash ^= uint32(srcPort)<<16 | uint32(dstPort)
	hash += hash << 3
	hash ^= hash >> 11
	hash += hash << 15
	return 49152 + uint16(hash&0x3fff)
}

func TestGeneveLocatorOutboundWireFormats(t *testing.T) {
	ensureBPFEnv(t)

	objs, err := bpf.LoadObjects()
	if err != nil {
		t.Fatalf("LoadObjects: %v", err)
	}
	defer objs.Close()

	nonCritical := wireGeneveOption(0x0102, 0x02, []byte{0, 0, 0, 0x2a})
	critical := wireGeneveOption(0x0102, 0x83, []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88})
	maxOption := wireGeneveOption(0x2222, 0x04, bytes.Repeat([]byte{0x5a}, 60))

	tests := []struct {
		name           string
		locator        vswitch.GeneveLocator
		tlvClass       uint16
		tlvType        uint8
		encapEth       bool
		transitVNI     uint32
		opaque         []byte
		opaqueCritical bool
		wantPort       uint16
		wantVNI        uint32
		wantCritical   bool
		wantOptions    []byte
	}{
		{
			name:       "port without options preserves legacy framing",
			locator:    vswitch.GeneveLocatorPort,
			transitVNI: geneveTestVNI,
			wantPort:   uint16(testGenevePortBase + geneveTestSlotID),
			wantVNI:    geneveTestVNI,
		},
		{
			name:        "port with non-critical option",
			locator:     vswitch.GeneveLocatorPort,
			transitVNI:  geneveTestVNI,
			opaque:      nonCritical,
			wantPort:    uint16(testGenevePortBase + geneveTestSlotID),
			wantVNI:     geneveTestVNI,
			wantOptions: nonCritical,
		},
		{
			name:           "port with critical option and Ether payload",
			locator:        vswitch.GeneveLocatorPort,
			encapEth:       true,
			transitVNI:     geneveTestVNI,
			opaque:         critical,
			opaqueCritical: true,
			wantPort:       uint16(testGenevePortBase + geneveTestSlotID),
			wantVNI:        geneveTestVNI,
			wantCritical:   true,
			wantOptions:    critical,
		},
		{
			name:       "vni without options",
			locator:    vswitch.GeneveLocatorVNI,
			transitVNI: geneveTestVNILow,
			wantPort:   vswitch.GeneveStandardPort,
			wantVNI:    geneveTestSlotID<<12 | geneveTestVNILow,
		},
		{
			name:        "vni with ordered option and Ether payload",
			locator:     vswitch.GeneveLocatorVNI,
			encapEth:    true,
			transitVNI:  geneveTestVNILow,
			opaque:      nonCritical,
			wantPort:    vswitch.GeneveStandardPort,
			wantVNI:     geneveTestSlotID<<12 | geneveTestVNILow,
			wantOptions: nonCritical,
		},
		{
			name:         "tlv with critical locator only",
			locator:      vswitch.GeneveLocatorTLV,
			tlvClass:     0x0102,
			tlvType:      0x81,
			transitVNI:   geneveTestVNI,
			wantPort:     vswitch.GeneveStandardPort,
			wantVNI:      geneveTestVNI,
			wantCritical: true,
			wantOptions:  wireGeneveLocator(0x0102, 0x81, geneveTestSlotID),
		},
		{
			name:           "tlv locator precedes multiple opaque options",
			locator:        vswitch.GeneveLocatorTLV,
			tlvClass:       0x0102,
			tlvType:        0x01,
			encapEth:       true,
			transitVNI:     geneveTestVNI,
			opaque:         append(append([]byte{}, nonCritical...), critical...),
			opaqueCritical: true,
			wantPort:       vswitch.GeneveStandardPort,
			wantVNI:        geneveTestVNI,
			wantCritical:   true,
			wantOptions: append(
				append(wireGeneveLocator(0x0102, 0x01, geneveTestSlotID), nonCritical...),
				critical...,
			),
		},
		{
			name:        "maximum 64-byte option sequence",
			locator:     vswitch.GeneveLocatorPort,
			transitVNI:  geneveTestVNI,
			opaque:      maxOption,
			wantPort:    uint16(testGenevePortBase + geneveTestSlotID),
			wantVNI:     geneveTestVNI,
			wantOptions: maxOption,
		},
	}

	sandboxMAC := [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	sandboxIP := net.ParseIP("169.254.1.1")
	externalIP := net.ParseIP("8.8.8.8")
	pkt := buildIPv4UDPPacket(
		sandboxMAC, testSwitchMAC,
		sandboxIP, externalIP,
		12345, 53,
		[]byte("locator-wire-payload"),
	)
	wantSrcPort := expectedGeneveSourcePort(sandboxIP, externalIP, IPProtoUDP, 12345, 53)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			testSetupGeneveMaps(
				t, objs, tc.locator, tc.tlvClass, tc.tlvType, tc.encapEth,
				tc.transitVNI, tc.opaque, tc.opaqueCritical,
			)

			ret, out, err := objs.Programs.IngressNX.Test(pkt)
			if err != nil {
				t.Fatalf("Program.Test: %v", err)
			}
			if ret != TCActRedirect {
				t.Fatalf("return action = %d, want redirect", ret)
			}

			udp, err := parseUDPHeader(out)
			if err != nil {
				t.Fatal(err)
			}
			if udp.DstPort != tc.wantPort || udp.SrcPort != wantSrcPort {
				t.Errorf("UDP ports = %d -> %d, want %d -> %d", udp.SrcPort, udp.DstPort, wantSrcPort, tc.wantPort)
			}
			if int(udp.Length) != len(out)-EthHdrLen-IPHdrLen {
				t.Errorf("UDP length = %d, packet requires %d", udp.Length, len(out)-EthHdrLen-IPHdrLen)
			}
			ip, err := parseIPHeader(out)
			if err != nil {
				t.Fatal(err)
			}
			if int(ip.TotalLen) != len(out)-EthHdrLen {
				t.Errorf("outer IP total length = %d, want %d", ip.TotalLen, len(out)-EthHdrLen)
			}

			geneve, err := parseGeneveHeader(out)
			if err != nil {
				t.Fatal(err)
			}
			if geneve.Version != 0 || geneve.VNI != tc.wantVNI || geneve.Critical != tc.wantCritical {
				t.Errorf("GENEVE header = version %d VNI %#x C=%v, want version 0 VNI %#x C=%v", geneve.Version, geneve.VNI, geneve.Critical, tc.wantVNI, tc.wantCritical)
			}
			if geneve.OptLen != uint8(len(tc.wantOptions)/4) || !bytes.Equal(geneve.Options, tc.wantOptions) {
				t.Errorf("GENEVE options = opt_len %d bytes %x, want %d bytes %x", geneve.OptLen, geneve.Options, len(tc.wantOptions)/4, tc.wantOptions)
			}
			parsedOptions, err := parseGeneveOptions(geneve.Options)
			if err != nil {
				t.Fatalf("parse GENEVE options: %v", err)
			}
			for i, option := range parsedOptions {
				if option.Reserved != 0 || int(option.Length)*4 != len(option.Data) {
					t.Errorf("option %d header = class %#x type %#x reserved %d length %d data %x", i, option.Class, option.Type, option.Reserved, option.Length, option.Data)
				}
			}
			if tc.locator == vswitch.GeneveLocatorTLV {
				if len(parsedOptions) == 0 || parsedOptions[0].Class != tc.tlvClass ||
					parsedOptions[0].Type != tc.tlvType || parsedOptions[0].Length != 1 ||
					binary.BigEndian.Uint32(parsedOptions[0].Data) != geneveTestSlotID {
					t.Fatalf("first TLV locator = %#v", parsedOptions)
				}
			}
			wantProto := uint16(EthTypeIP)
			if tc.encapEth {
				wantProto = GeneveProtoTEB
			}
			if geneve.ProtoType != wantProto {
				t.Errorf("GENEVE protocol = %#x, want %#x", geneve.ProtoType, wantProto)
			}

			innerOffset := EthHdrLen + IPHdrLen + UDPHdrLen + GeneveHdrLen + len(tc.wantOptions)
			if tc.encapEth {
				if len(out) < innerOffset+EthHdrLen {
					t.Fatalf("missing inner Ethernet header: %d bytes", len(out))
				}
				innerEth, err := parseEthernetHeader(out[innerOffset:])
				if err != nil {
					t.Fatal(err)
				}
				if innerEth.DstMAC != geneveTestTransitMAC || innerEth.SrcMAC != portMAC(testSwitchMAC, geneveTestSlotID) || innerEth.EtherType != EthTypeIP {
					t.Errorf("inner Ethernet header = %#v", innerEth)
				}
				innerOffset += EthHdrLen
			}
			if !bytes.Equal(out[innerOffset:], pkt[EthHdrLen:]) {
				t.Errorf("inner IP payload moved or changed at offset %d", innerOffset)
			}
		})
	}
}

func buildGeneveReturnPacket(dstPort uint16, wireVNI uint32, critical bool, options []byte, gatewayIP net.IP, encapEth bool) []byte {
	externalIP := net.ParseIP("8.8.8.8")
	sandboxIP := net.ParseIP("10.1.0.2")
	udp := buildUDPPacket(53, 12345, []byte("return-payload"))
	innerIP := buildIPPacket(externalIP, sandboxIP, IPProtoUDP, udp)
	proto := uint16(EthTypeIP)
	inner := innerIP
	if encapEth {
		proto = GeneveProtoTEB
		inner = buildEthernetFrame(
			portMAC(testSwitchMAC, geneveTestSlotID),
			[6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
			EthTypeIP,
			innerIP,
		)
	}
	return buildGenevePacketWithOptions(
		[6]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
		testSwitchMAC,
		gatewayIP, net.ParseIP("192.0.2.1"),
		49152, dstPort,
		wireVNI, proto, critical, options, inner,
	)
}

func TestGeneveLocatorInboundValidFormats(t *testing.T) {
	ensureBPFEnv(t)

	objs, err := bpf.LoadObjects()
	if err != nil {
		t.Fatalf("LoadObjects: %v", err)
	}
	defer objs.Close()

	tests := []struct {
		name       string
		locator    vswitch.GeneveLocator
		tlvClass   uint16
		tlvType    uint8
		transitVNI uint32
		dstPort    uint16
		wireVNI    uint32
		critical   bool
		options    []byte
		encapEth   bool
	}{
		{
			name:       "port Ether-over-GENEVE",
			locator:    vswitch.GeneveLocatorPort,
			transitVNI: geneveTestVNI,
			dstPort:    uint16(testGenevePortBase + geneveTestSlotID),
			wireVNI:    geneveTestVNI,
			encapEth:   true,
		},
		{
			name:       "vni IP-over-GENEVE",
			locator:    vswitch.GeneveLocatorVNI,
			transitVNI: geneveTestVNILow,
			dstPort:    vswitch.GeneveStandardPort,
			wireVNI:    geneveTestSlotID<<12 | geneveTestVNILow,
		},
		{
			name:       "tlv exact critical locator",
			locator:    vswitch.GeneveLocatorTLV,
			tlvClass:   0x0102,
			tlvType:    0x81,
			transitVNI: geneveTestVNI,
			dstPort:    vswitch.GeneveStandardPort,
			wireVNI:    geneveTestVNI,
			critical:   true,
			options:    wireGeneveLocator(0x0102, 0x81, geneveTestSlotID),
			encapEth:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			testSetupGeneveMaps(t, objs, tc.locator, tc.tlvClass, tc.tlvType, tc.encapEth, tc.transitVNI, nil, false)
			pkt := buildGeneveReturnPacket(tc.dstPort, tc.wireVNI, tc.critical, tc.options, net.ParseIP("192.0.2.2"), tc.encapEth)
			ret, out, err := objs.Programs.IngressTransit.Test(pkt)
			if err != nil {
				t.Fatalf("Program.Test: %v", err)
			}
			if ret != TCActRedirect {
				t.Fatalf("return action = %d, want redirect", ret)
			}
			eth, err := parseEthernetHeader(out)
			if err != nil {
				t.Fatal(err)
			}
			if eth.DstMAC != portMAC(testSwitchMAC, geneveTestSlotID) || eth.SrcMAC != testSwitchMAC || eth.EtherType != EthTypeIP {
				t.Errorf("decapsulated Ethernet header = %#v", eth)
			}
			ip, err := parseIPHeader(out)
			if err != nil {
				t.Fatal(err)
			}
			if !ip.SrcIP.Equal(net.ParseIP("8.8.8.8")) || !ip.DstIP.Equal(net.ParseIP("10.1.0.2")) {
				t.Errorf("decapsulated IP = %s -> %s", ip.SrcIP, ip.DstIP)
			}
		})
	}
}

func TestGeneveLocatorInboundRejectsInvalidFraming(t *testing.T) {
	ensureBPFEnv(t)

	objs, err := bpf.LoadObjects()
	if err != nil {
		t.Fatalf("LoadObjects: %v", err)
	}
	defer objs.Close()

	locator := wireGeneveLocator(0x0102, 0x81, geneveTestSlotID)
	locatorNonCritical := wireGeneveLocator(0x0102, 0x01, geneveTestSlotID)
	zeroOption := wireGeneveOption(0x0203, 0x02, nil)

	tests := []struct {
		name       string
		locator    vswitch.GeneveLocator
		tlvClass   uint16
		tlvType    uint8
		transitVNI uint32
		dstPort    uint16
		wireVNI    uint32
		critical   bool
		options    []byte
		gatewayIP  net.IP
		mutate     func([]byte)
	}{
		{
			name:       "wrong fixed UDP port",
			locator:    vswitch.GeneveLocatorVNI,
			transitVNI: geneveTestVNILow,
			dstPort:    uint16(testGenevePortBase + geneveTestSlotID),
			wireVNI:    geneveTestSlotID<<12 | geneveTestVNILow,
		},
		{
			name:       "slot out of range",
			locator:    vswitch.GeneveLocatorTLV,
			tlvClass:   0x0102,
			tlvType:    0x81,
			transitVNI: geneveTestVNI,
			dstPort:    vswitch.GeneveStandardPort,
			wireVNI:    geneveTestVNI,
			critical:   true,
			options:    wireGeneveLocator(0x0102, 0x81, testNumPorts),
		},
		{
			name:       "wrong VNI low bits",
			locator:    vswitch.GeneveLocatorVNI,
			transitVNI: geneveTestVNILow,
			dstPort:    vswitch.GeneveStandardPort,
			wireVNI:    geneveTestSlotID<<12 | (geneveTestVNILow + 1),
		},
		{
			name:       "wrong full VNI",
			locator:    vswitch.GeneveLocatorTLV,
			tlvClass:   0x0102,
			tlvType:    0x81,
			transitVNI: geneveTestVNI,
			dstPort:    vswitch.GeneveStandardPort,
			wireVNI:    geneveTestVNI + 1,
			critical:   true,
			options:    locator,
		},
		{
			name:       "wrong gateway source",
			locator:    vswitch.GeneveLocatorPort,
			transitVNI: geneveTestVNI,
			dstPort:    uint16(testGenevePortBase + geneveTestSlotID),
			wireVNI:    geneveTestVNI,
			gatewayIP:  net.ParseIP("192.0.2.99"),
		},
		{
			name:       "missing TLV locator",
			locator:    vswitch.GeneveLocatorTLV,
			tlvClass:   0x0102,
			tlvType:    0x81,
			transitVNI: geneveTestVNI,
			dstPort:    vswitch.GeneveStandardPort,
			wireVNI:    geneveTestVNI,
		},
		{
			name:       "wrong locator class",
			locator:    vswitch.GeneveLocatorTLV,
			tlvClass:   0x0102,
			tlvType:    0x81,
			transitVNI: geneveTestVNI,
			dstPort:    vswitch.GeneveStandardPort,
			wireVNI:    geneveTestVNI,
			critical:   true,
			options:    wireGeneveLocator(0x0103, 0x81, geneveTestSlotID),
		},
		{
			name:       "wrong exact locator type",
			locator:    vswitch.GeneveLocatorTLV,
			tlvClass:   0x0102,
			tlvType:    0x01,
			transitVNI: geneveTestVNI,
			dstPort:    vswitch.GeneveStandardPort,
			wireVNI:    geneveTestVNI,
			critical:   true,
			options:    locator,
		},
		{
			name:       "wrong locator length",
			locator:    vswitch.GeneveLocatorTLV,
			tlvClass:   0x0102,
			tlvType:    0x81,
			transitVNI: geneveTestVNI,
			dstPort:    vswitch.GeneveStandardPort,
			wireVNI:    geneveTestVNI,
			critical:   true,
			options:    append([]byte{}, locator...),
			mutate: func(pkt []byte) {
				pkt[EthHdrLen+IPHdrLen+UDPHdrLen+GeneveHdrLen+3] = 2
			},
		},
		{
			name:       "locator reserved bits set",
			locator:    vswitch.GeneveLocatorTLV,
			tlvClass:   0x0102,
			tlvType:    0x81,
			transitVNI: geneveTestVNI,
			dstPort:    vswitch.GeneveStandardPort,
			wireVNI:    geneveTestVNI,
			critical:   true,
			options:    append([]byte{}, locator...),
			mutate: func(pkt []byte) {
				pkt[EthHdrLen+IPHdrLen+UDPHdrLen+GeneveHdrLen+3] = 0x21
			},
		},
		{
			name:       "wrong base C",
			locator:    vswitch.GeneveLocatorTLV,
			tlvClass:   0x0102,
			tlvType:    0x81,
			transitVNI: geneveTestVNI,
			dstPort:    vswitch.GeneveStandardPort,
			wireVNI:    geneveTestVNI,
			options:    locator,
		},
		{
			name:       "extra TLV return option",
			locator:    vswitch.GeneveLocatorTLV,
			tlvClass:   0x0102,
			tlvType:    0x01,
			transitVNI: geneveTestVNI,
			dstPort:    vswitch.GeneveStandardPort,
			wireVNI:    geneveTestVNI,
			options:    append(append([]byte{}, locatorNonCritical...), zeroOption...),
		},
		{
			name:       "port rejects return option",
			locator:    vswitch.GeneveLocatorPort,
			transitVNI: geneveTestVNI,
			dstPort:    uint16(testGenevePortBase + geneveTestSlotID),
			wireVNI:    geneveTestVNI,
			options:    zeroOption,
		},
		{
			name:       "malformed OptLen",
			locator:    vswitch.GeneveLocatorPort,
			transitVNI: geneveTestVNI,
			dstPort:    uint16(testGenevePortBase + geneveTestSlotID),
			wireVNI:    geneveTestVNI,
			mutate: func(pkt []byte) {
				pkt[EthHdrLen+IPHdrLen+UDPHdrLen] = 1
			},
		},
		{
			name:       "options exceed 64-byte parser bound",
			locator:    vswitch.GeneveLocatorPort,
			transitVNI: geneveTestVNI,
			dstPort:    uint16(testGenevePortBase + geneveTestSlotID),
			wireVNI:    geneveTestVNI,
			options:    make([]byte, 68),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			testSetupGeneveMaps(t, objs, tc.locator, tc.tlvClass, tc.tlvType, true, tc.transitVNI, nil, false)
			gatewayIP := tc.gatewayIP
			if gatewayIP == nil {
				gatewayIP = net.ParseIP("192.0.2.2")
			}
			pkt := buildGeneveReturnPacket(tc.dstPort, tc.wireVNI, tc.critical, tc.options, gatewayIP, true)
			if tc.mutate != nil {
				tc.mutate(pkt)
			}
			ret, _, err := objs.Programs.IngressTransit.Test(pkt)
			if err != nil {
				t.Fatalf("Program.Test: %v", err)
			}
			if ret != TCActOK {
				t.Errorf("invalid framing redirected with action %d, want TC_ACT_OK", ret)
			}
		})
	}
}

func TestGeneveOutboundRejectsInconsistentOptionsHint(t *testing.T) {
	ensureBPFEnv(t)

	objs, err := bpf.LoadObjects()
	if err != nil {
		t.Fatalf("LoadObjects: %v", err)
	}
	defer objs.Close()

	opaque := wireGeneveOption(0x0102, 0x02, []byte{0, 0, 0, 1})
	testSetupGeneveMaps(t, objs, vswitch.GeneveLocatorPort, 0, 0, false, geneveTestVNI, opaque, false)
	var value vswitch.GeneveOptsValue
	value.Len = 4
	copy(value.Data[:], opaque)
	if err := objs.Maps.GeneveOpts.Update(geneveTestSlotID, &value, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}

	pkt := buildIPv4UDPPacket(
		[6]byte{0, 1, 2, 3, 4, 5}, testSwitchMAC,
		net.ParseIP("169.254.1.1"), net.ParseIP("8.8.8.8"),
		12345, 53, []byte("mismatched-map-value"),
	)
	ret, out, err := objs.Programs.IngressNX.Test(pkt)
	if err != nil {
		t.Fatalf("Program.Test: %v", err)
	}
	if ret != TCActOK || !bytes.Equal(out, pkt) {
		t.Fatalf("mismatched option length action=%d changed=%v", ret, !bytes.Equal(out, pkt))
	}
}
