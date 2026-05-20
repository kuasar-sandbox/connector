//go:build integration

package bpf_test

import (
	"net"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/fullof-work/sandbox-vswitch/pkg/internal/bpf"
	"github.com/fullof-work/sandbox-vswitch/pkg/vswitch"
)

// NOTE: BPF_PROG_TEST_RUN Limitations for TC Programs
//
// For tc_ingress_nx, the program uses skb->ingress_ifindex to look up the slot.
// BPF_PROG_TEST_RUN does not easily allow setting this field without kernel support
// for context input (requires kernel 5.2+ and proper __sk_buff context size).
//
// Current workaround: Tests for tc_ingress_nx are marked as requiring context
// support and may be skipped on older kernels or environments where context
// passing is not working.
//
// Tests for tc_ingress_mx and tc_ingress_transit work without context because:
// - tc_ingress_mx: Uses floating IP to derive slot_id from packet contents
// - tc_ingress_transit: Uses GENEVE dest port to derive slot_id from packet contents

// Test constants matching BPF program expectations
const (
	testFloatingIPBase = 0x64640000 // 100.100.0.0
	testGenevePortBase = 50000
	testSlotID         = 0
	testNumPorts       = 4
)

// testSwitchMAC is the switch MAC used in tests.
var testSwitchMAC = [6]byte{0x02, 0xde, 0xad, 0xbe, 0xef, 0x00}

// testIngress ifindex for slot 0
// Use 0 to match BPF_PROG_TEST_RUN default skb->ingress_ifindex
const testIngressIfindex = 0

// testSetupMaps initializes BPF maps with test configuration.
func testSetupMaps(t *testing.T, objs *bpf.Objects) {
	t.Helper()

	// Setup switch config
	cfg := vswitch.SwitchConfig{
		SwitchMac:      testSwitchMAC,
		N_ports:        testNumPorts,
		FloatingIpBase: testFloatingIPBase,
		GenevePortBase: testGenevePortBase,
		GeneveEncapEth: 1, // Ether-over-GENEVE
	}
	key := uint32(0)
	if err := objs.Maps.Config.Update(key, &cfg, ebpf.UpdateAny); err != nil {
		t.Fatalf("failed to setup config map: %v", err)
	}

	// Setup slot 0
	slot := vswitch.SlotItem{
		Ifindex:          100,        // sw-n1 ifindex
		InnerIp:          0xa9fe0101, // 169.254.1.1
		MgmtCidrCount:    1,
		TransitIfindex:   200,        // transit dev ifindex
		TransitIp:        0xc0a80a01, // 192.168.10.1
		TransitGatewayIp: 0xc0a80a02, // 192.168.10.2
		TransitGeneveVni: 12345,
	}
	// Add management CIDR for metadata service
	slot.MgmtCidrs0 = vswitch.MgmtCIDR{
		Ip:      0xa9fea9fe, // 169.254.169.254
		Mask:    0xffffffff, // /32
		Ifindex: 150,        // sw-m0 ifindex
		MgmtMac: [6]byte{0x02, 0xde, 0xad, 0xbe, 0xff, 0xf0},
	}
	slotKey := uint32(testSlotID)
	if err := objs.Maps.Slots.Update(slotKey, &slot, ebpf.UpdateAny); err != nil {
		t.Fatalf("failed to setup slot: %v", err)
	}

	// Setup ifindex -> slot_id mapping
	// Use ifindex=0 to match BPF_PROG_TEST_RUN default skb->ingress_ifindex
	ifindex := uint32(0)
	slotID := uint32(testSlotID)
	if err := objs.Maps.IfindexToSlot.Update(ifindex, &slotID, ebpf.UpdateAny); err != nil {
		t.Fatalf("failed to setup ifindex_to_slot: %v", err)
	}
}

// TestIngressNxARPProxy tests ARP proxy functionality in tc_ingress_nx.
// When a sandbox sends an ARP request for any IP, the BPF program should
// reply with the switch MAC (or mgmt MAC for mgmt CIDRs).
//
// NOTE: This test requires skb->ingress_ifindex to be set, which is not
// easily achievable with BPF_PROG_TEST_RUN. The test documents the expected
// behavior but may not pass without proper context support.
func TestIngressNxARPProxy(t *testing.T) {
	ensureBPFEnv(t)

	objs, err := bpf.LoadObjects()
	if err != nil {
		t.Fatalf("LoadObjects: %v", err)
	}
	defer objs.Close()

	testSetupMaps(t, objs)

	testCases := []struct {
		name          string
		targetIP      net.IP
		wantReplyMAC  [6]byte
		wantRetAction uint32
	}{
		{
			name:          "ARP for external IP returns switch MAC",
			targetIP:      net.ParseIP("8.8.8.8"),
			wantReplyMAC:  testSwitchMAC,
			wantRetAction: TCActRedirect,
		},
		{
			name:          "ARP for mgmt service returns mgmt MAC",
			targetIP:      net.ParseIP("169.254.169.254"),
			wantReplyMAC:  [6]byte{0x02, 0xde, 0xad, 0xbe, 0xff, 0xf0},
			wantRetAction: TCActRedirect,
		},
	}

	sandboxMAC := [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	sandboxIP := net.ParseIP("169.254.1.1")

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Build ARP request packet
			pkt := buildARPRequest(sandboxMAC, sandboxIP, tc.targetIP)

			// Run BPF program
			ret, out, err := objs.Programs.IngressNX.Test(pkt)
			if err != nil {
				t.Fatalf("Program.Test failed: %v", err)
			}

			// Verify return action
			if ret != tc.wantRetAction {
				t.Errorf("return action: got %d, want %d (TC_ACT_REDIRECT)", ret, tc.wantRetAction)
			}

			// Parse output as ARP reply
			arpReply, err := parseARPPacket(out)
			if err != nil {
				t.Fatalf("parseARPPacket: %v", err)
			}

			// Verify it's a reply
			if arpReply.Operation != ARPOpReply {
				t.Errorf("ARP operation: got %d, want %d (REPLY)", arpReply.Operation, ARPOpReply)
			}

			// Verify sender MAC matches expected
			if arpReply.SenderMAC != tc.wantReplyMAC {
				t.Errorf("sender MAC: got %v, want %v", arpReply.SenderMAC, tc.wantReplyMAC)
			}

			// Verify sender IP is the target IP from original request
			if !arpReply.SenderIP.Equal(tc.targetIP) {
				t.Errorf("sender IP: got %v, want %v", arpReply.SenderIP, tc.targetIP)
			}

			// Verify target MAC is the original sender
			if arpReply.TargetMAC != sandboxMAC {
				t.Errorf("target MAC: got %v, want %v", arpReply.TargetMAC, sandboxMAC)
			}
		})
	}
}

// TestIngressNxGeneveEncap tests GENEVE encapsulation for external traffic.
//
// NOTE: This test requires skb->ingress_ifindex to be set, which is not
// easily achievable with BPF_PROG_TEST_RUN. The test documents the expected
// behavior but may not pass without proper context support.
func TestIngressNxGeneveEncap(t *testing.T) {
	ensureBPFEnv(t)

	objs, err := bpf.LoadObjects()
	if err != nil {
		t.Fatalf("LoadObjects: %v", err)
	}
	defer objs.Close()

	testSetupMaps(t, objs)

	sandboxMAC := [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	sandboxIP := net.ParseIP("169.254.1.1")
	externalIP := net.ParseIP("8.8.8.8")

	// Build an IP/UDP packet from sandbox to external destination
	pkt := buildIPv4UDPPacket(
		sandboxMAC, testSwitchMAC,
		sandboxIP, externalIP,
		12345, 53, // DNS query
		[]byte("test payload"),
	)

	// Run BPF program
	ret, out, err := objs.Programs.IngressNX.Test(pkt)
	if err != nil {
		t.Fatalf("Program.Test failed: %v", err)
	}

	// For external traffic, we expect the program to return bpf_redirect_neigh()
	// which may return TC_ACT_REDIRECT or another value depending on kernel
	t.Logf("Return action: %d", ret)

	// Parse output - should have GENEVE encapsulation
	if len(out) < EthHdrLen+IPHdrLen+UDPHdrLen+GeneveHdrLen {
		t.Fatalf("output packet too short for GENEVE: %d bytes", len(out))
	}

	// Check outer Ethernet header
	ethHdr, err := parseEthernetHeader(out)
	if err != nil {
		t.Fatalf("parseEthernetHeader: %v", err)
	}
	if ethHdr.EtherType != EthTypeIP {
		t.Errorf("outer EtherType: got 0x%04x, want 0x%04x", ethHdr.EtherType, EthTypeIP)
	}

	// Check outer IP header
	ipHdr, err := parseIPHeader(out)
	if err != nil {
		t.Fatalf("parseIPHeader: %v", err)
	}
	if ipHdr.Protocol != IPProtoUDP {
		t.Errorf("outer IP protocol: got %d, want %d (UDP)", ipHdr.Protocol, IPProtoUDP)
	}

	// Source should be transit IP (192.168.10.1)
	expectedSrcIP := net.ParseIP("192.168.10.1")
	if !ipHdr.SrcIP.Equal(expectedSrcIP) {
		t.Errorf("outer src IP: got %v, want %v", ipHdr.SrcIP, expectedSrcIP)
	}

	// Dest should be transit gateway (192.168.10.2)
	expectedDstIP := net.ParseIP("192.168.10.2")
	if !ipHdr.DstIP.Equal(expectedDstIP) {
		t.Errorf("outer dst IP: got %v, want %v", ipHdr.DstIP, expectedDstIP)
	}

	// Check UDP header
	udpHdr, err := parseUDPHeader(out)
	if err != nil {
		t.Fatalf("parseUDPHeader: %v", err)
	}

	// Dest port should be geneve_port_base + slot_id
	expectedDstPort := uint16(testGenevePortBase + testSlotID)
	if udpHdr.DstPort != expectedDstPort {
		t.Errorf("UDP dst port: got %d, want %d", udpHdr.DstPort, expectedDstPort)
	}

	// Check GENEVE header
	geneveHdr, err := parseGeneveHeader(out)
	if err != nil {
		t.Fatalf("parseGeneveHeader: %v", err)
	}

	if geneveHdr.VNI != 12345 {
		t.Errorf("GENEVE VNI: got %d, want 12345", geneveHdr.VNI)
	}

	// For Ether-over-GENEVE, proto should be TEB
	if geneveHdr.ProtoType != GeneveProtoTEB {
		t.Errorf("GENEVE proto: got 0x%04x, want 0x%04x (TEB)", geneveHdr.ProtoType, GeneveProtoTEB)
	}
}

// TestIngressNxMgmtSNAT tests SNAT for management plane traffic.
//
// NOTE: This test requires skb->ingress_ifindex to be set, which is not
// easily achievable with BPF_PROG_TEST_RUN. The test documents the expected
// behavior but may not pass without proper context support.
func TestIngressNxMgmtSNAT(t *testing.T) {
	ensureBPFEnv(t)

	objs, err := bpf.LoadObjects()
	if err != nil {
		t.Fatalf("LoadObjects: %v", err)
	}
	defer objs.Close()

	testSetupMaps(t, objs)

	sandboxMAC := [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	sandboxIP := net.ParseIP("169.254.1.1")
	mgmtIP := net.ParseIP("169.254.169.254")

	// Build an IP/UDP packet from sandbox to metadata service
	pkt := buildIPv4UDPPacket(
		sandboxMAC, testSwitchMAC,
		sandboxIP, mgmtIP,
		12345, 80, // HTTP to metadata
		[]byte("GET /metadata"),
	)

	// Run BPF program
	ret, out, err := objs.Programs.IngressNX.Test(pkt)
	if err != nil {
		t.Fatalf("Program.Test failed: %v", err)
	}

	if ret != TCActRedirect {
		t.Errorf("return action: got %d, want %d (TC_ACT_REDIRECT)", ret, TCActRedirect)
	}

	// Parse output - source IP should be SNAT'd to floating IP
	ipHdr, err := parseIPHeader(out)
	if err != nil {
		t.Fatalf("parseIPHeader: %v", err)
	}

	// Source should be floating_ip_base + slot_id = 100.100.0.0 + 0 = 100.100.0.0
	expectedSrcIP := net.ParseIP("100.100.0.0")
	if !ipHdr.SrcIP.Equal(expectedSrcIP) {
		t.Errorf("SNAT'd src IP: got %v, want %v", ipHdr.SrcIP, expectedSrcIP)
	}

	// Destination should remain unchanged
	if !ipHdr.DstIP.Equal(mgmtIP) {
		t.Errorf("dst IP: got %v, want %v", ipHdr.DstIP, mgmtIP)
	}

	// Check Ethernet header - dst should be mgmt MAC
	ethHdr, err := parseEthernetHeader(out)
	if err != nil {
		t.Fatalf("parseEthernetHeader: %v", err)
	}
	expectedMgmtMAC := [6]byte{0x02, 0xde, 0xad, 0xbe, 0xff, 0xf0}
	if ethHdr.DstMAC != expectedMgmtMAC {
		t.Errorf("dst MAC: got %v, want %v", ethHdr.DstMAC, expectedMgmtMAC)
	}
}

// TestIngressMxARPProxy tests ARP proxy functionality in tc_ingress_mx.
func TestIngressMxARPProxy(t *testing.T) {
	ensureBPFEnv(t)

	objs, err := bpf.LoadObjects()
	if err != nil {
		t.Fatalf("LoadObjects: %v", err)
	}
	defer objs.Close()

	testSetupMaps(t, objs)

	mgmtServiceMAC := [6]byte{0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}
	mgmtServiceIP := net.ParseIP("169.254.169.254")
	floatingIP := net.ParseIP("100.100.0.0") // slot 0's floating IP

	// Build ARP request from mgmt service for floating IP
	pkt := buildARPRequest(mgmtServiceMAC, mgmtServiceIP, floatingIP)

	// Run BPF program
	ret, out, err := objs.Programs.IngressMX.Test(pkt)
	if err != nil {
		t.Fatalf("Program.Test failed: %v", err)
	}

	if ret != TCActRedirect {
		t.Errorf("return action: got %d, want %d (TC_ACT_REDIRECT)", ret, TCActRedirect)
	}

	// Parse ARP reply
	arpReply, err := parseARPPacket(out)
	if err != nil {
		t.Fatalf("parseARPPacket: %v", err)
	}

	if arpReply.Operation != ARPOpReply {
		t.Errorf("ARP operation: got %d, want %d (REPLY)", arpReply.Operation, ARPOpReply)
	}

	// Reply should be from per-slot port MAC
	expectedPortMAC := portMAC(testSwitchMAC, testSlotID)
	if arpReply.SenderMAC != expectedPortMAC {
		t.Errorf("sender MAC: got %v, want %v (port MAC)", arpReply.SenderMAC, expectedPortMAC)
	}
}

// TestIngressMxDNAT tests DNAT for management responses.
func TestIngressMxDNAT(t *testing.T) {
	ensureBPFEnv(t)

	objs, err := bpf.LoadObjects()
	if err != nil {
		t.Fatalf("LoadObjects: %v", err)
	}
	defer objs.Close()

	testSetupMaps(t, objs)

	mgmtServiceMAC := [6]byte{0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}
	mgmtServiceIP := net.ParseIP("169.254.169.254")
	floatingIP := net.ParseIP("100.100.0.0") // slot 0's floating IP

	// Build response packet from mgmt service to floating IP
	pkt := buildIPv4UDPPacket(
		mgmtServiceMAC, testSwitchMAC,
		mgmtServiceIP, floatingIP,
		80, 12345, // HTTP response
		[]byte("HTTP/1.1 200 OK"),
	)

	// Run BPF program
	ret, out, err := objs.Programs.IngressMX.Test(pkt)
	if err != nil {
		t.Fatalf("Program.Test failed: %v", err)
	}

	if ret != TCActRedirect {
		t.Errorf("return action: got %d, want %d (TC_ACT_REDIRECT)", ret, TCActRedirect)
	}

	// Parse output - destination IP should be DNAT'd to inner IP
	ipHdr, err := parseIPHeader(out)
	if err != nil {
		t.Fatalf("parseIPHeader: %v", err)
	}

	// Destination should be inner_ip = 169.254.1.1
	expectedDstIP := net.ParseIP("169.254.1.1")
	if !ipHdr.DstIP.Equal(expectedDstIP) {
		t.Errorf("DNAT'd dst IP: got %v, want %v", ipHdr.DstIP, expectedDstIP)
	}

	// Source should remain unchanged
	if !ipHdr.SrcIP.Equal(mgmtServiceIP) {
		t.Errorf("src IP: got %v, want %v", ipHdr.SrcIP, mgmtServiceIP)
	}

	// Check Ethernet header - dst should be per-slot port MAC
	ethHdr, err := parseEthernetHeader(out)
	if err != nil {
		t.Fatalf("parseEthernetHeader: %v", err)
	}
	expectedPortMAC := portMAC(testSwitchMAC, testSlotID)
	if ethHdr.DstMAC != expectedPortMAC {
		t.Errorf("dst MAC: got %v, want %v (port MAC)", ethHdr.DstMAC, expectedPortMAC)
	}
}

// TestIngressTransitDecap tests GENEVE decapsulation.
func TestIngressTransitDecap(t *testing.T) {
	ensureBPFEnv(t)

	objs, err := bpf.LoadObjects()
	if err != nil {
		t.Fatalf("LoadObjects: %v", err)
	}
	defer objs.Close()

	testSetupMaps(t, objs)

	// Build inner packet (what will be encapsulated)
	innerSrcMAC := [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	innerDstMAC := portMAC(testSwitchMAC, testSlotID)
	externalIP := net.ParseIP("8.8.8.8")
	sandboxIP := net.ParseIP("169.254.1.1")

	innerPkt := buildIPv4UDPPacket(
		innerSrcMAC, innerDstMAC,
		externalIP, sandboxIP,
		53, 12345, // DNS response
		[]byte("DNS response"),
	)

	// Build outer GENEVE packet from gateway
	outerSrcMAC := [6]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	outerDstMAC := testSwitchMAC
	gatewayIP := net.ParseIP("192.168.10.2")
	transitIP := net.ParseIP("192.168.10.1")

	// GENEVE dst port = geneve_port_base + slot_id
	geneveDstPort := uint16(testGenevePortBase + testSlotID)

	pkt := buildGenevePacket(
		outerSrcMAC, outerDstMAC,
		gatewayIP, transitIP,
		49152, geneveDstPort, // outer UDP ports
		12345,          // VNI
		GeneveProtoTEB, // Ether-over-GENEVE
		innerPkt,
	)

	// Run BPF program
	ret, out, err := objs.Programs.IngressTransit.Test(pkt)
	if err != nil {
		t.Fatalf("Program.Test failed: %v", err)
	}

	if ret != TCActRedirect {
		t.Errorf("return action: got %d, want %d (TC_ACT_REDIRECT)", ret, TCActRedirect)
	}

	// Output should be decapsulated - just Ethernet + IP + UDP
	if len(out) < EthHdrLen+IPHdrLen+UDPHdrLen {
		t.Fatalf("output packet too short after decap: %d bytes", len(out))
	}

	// Check Ethernet header - dst should be per-slot port MAC, src = switch MAC
	ethHdr, err := parseEthernetHeader(out)
	if err != nil {
		t.Fatalf("parseEthernetHeader: %v", err)
	}

	expectedDstMAC := portMAC(testSwitchMAC, testSlotID)
	if ethHdr.DstMAC != expectedDstMAC {
		t.Errorf("dst MAC: got %v, want %v (port MAC)", ethHdr.DstMAC, expectedDstMAC)
	}
	if ethHdr.SrcMAC != testSwitchMAC {
		t.Errorf("src MAC: got %v, want %v (switch MAC)", ethHdr.SrcMAC, testSwitchMAC)
	}

	// Check IP header - should be the inner packet's IP
	ipHdr, err := parseIPHeader(out)
	if err != nil {
		t.Fatalf("parseIPHeader: %v", err)
	}

	if !ipHdr.SrcIP.Equal(externalIP) {
		t.Errorf("inner src IP: got %v, want %v", ipHdr.SrcIP, externalIP)
	}
	if !ipHdr.DstIP.Equal(sandboxIP) {
		t.Errorf("inner dst IP: got %v, want %v", ipHdr.DstIP, sandboxIP)
	}
}

// TestIngressTransitInvalidVNI tests that packets with wrong VNI are dropped.
func TestIngressTransitInvalidVNI(t *testing.T) {
	ensureBPFEnv(t)

	objs, err := bpf.LoadObjects()
	if err != nil {
		t.Fatalf("LoadObjects: %v", err)
	}
	defer objs.Close()

	testSetupMaps(t, objs)

	// Build inner packet
	innerPkt := buildIPv4UDPPacket(
		[6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		portMAC(testSwitchMAC, testSlotID),
		net.ParseIP("8.8.8.8"),
		net.ParseIP("169.254.1.1"),
		53, 12345,
		[]byte("DNS response"),
	)

	gatewayIP := net.ParseIP("192.168.10.2")
	transitIP := net.ParseIP("192.168.10.1")
	geneveDstPort := uint16(testGenevePortBase + testSlotID)

	// Build packet with WRONG VNI
	pkt := buildGenevePacket(
		[6]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
		testSwitchMAC,
		gatewayIP, transitIP,
		49152, geneveDstPort,
		99999, // Wrong VNI (expected 12345)
		GeneveProtoTEB,
		innerPkt,
	)

	// Run BPF program
	ret, _, err := objs.Programs.IngressTransit.Test(pkt)
	if err != nil {
		t.Fatalf("Program.Test failed: %v", err)
	}

	// Should return TC_ACT_OK (pass through, not processed)
	if ret != TCActOK {
		t.Errorf("return action for invalid VNI: got %d, want %d (TC_ACT_OK)", ret, TCActOK)
	}
}

// TestIngressTransitInvalidSource tests that packets from wrong gateway are dropped.
func TestIngressTransitInvalidSource(t *testing.T) {
	ensureBPFEnv(t)

	objs, err := bpf.LoadObjects()
	if err != nil {
		t.Fatalf("LoadObjects: %v", err)
	}
	defer objs.Close()

	testSetupMaps(t, objs)

	// Build inner packet
	innerPkt := buildIPv4UDPPacket(
		[6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		portMAC(testSwitchMAC, testSlotID),
		net.ParseIP("8.8.8.8"),
		net.ParseIP("169.254.1.1"),
		53, 12345,
		[]byte("DNS response"),
	)

	wrongGatewayIP := net.ParseIP("192.168.10.99") // Wrong gateway
	transitIP := net.ParseIP("192.168.10.1")
	geneveDstPort := uint16(testGenevePortBase + testSlotID)

	pkt := buildGenevePacket(
		[6]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
		testSwitchMAC,
		wrongGatewayIP, transitIP,
		49152, geneveDstPort,
		12345,
		GeneveProtoTEB,
		innerPkt,
	)

	// Run BPF program
	ret, _, err := objs.Programs.IngressTransit.Test(pkt)
	if err != nil {
		t.Fatalf("Program.Test failed: %v", err)
	}

	// Should return TC_ACT_OK (pass through, not processed)
	if ret != TCActOK {
		t.Errorf("return action for invalid source: got %d, want %d (TC_ACT_OK)", ret, TCActOK)
	}
}

// TestStatsUpdate tests that statistics are updated after packet processing.
// Uses tc_ingress_mx which can derive slot from packet content (floating IP).
func TestStatsUpdate(t *testing.T) {
	ensureBPFEnv(t)

	objs, err := bpf.LoadObjects()
	if err != nil {
		t.Fatalf("LoadObjects: %v", err)
	}
	defer objs.Close()

	testSetupMaps(t, objs)

	// Read initial stats
	var initialStats []vswitch.SlotStats
	if err := objs.Maps.Stats.Lookup(uint32(testSlotID), &initialStats); err != nil {
		t.Fatalf("failed to read initial stats: %v", err)
	}

	var initialMgmtRx uint64
	for _, s := range initialStats {
		initialMgmtRx += s.MgmtRxPackets
	}

	// Send packet from mgmt service to floating IP (updates mgmt_rx stats)
	// This uses tc_ingress_mx which derives slot from floating IP in packet
	mgmtServiceMAC := [6]byte{0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}
	pkt := buildIPv4UDPPacket(
		mgmtServiceMAC, testSwitchMAC,
		net.ParseIP("169.254.169.254"),
		net.ParseIP("100.100.0.0"), // slot 0's floating IP
		80, 12345,
		[]byte("HTTP/1.1 200 OK"),
	)

	_, _, err = objs.Programs.IngressMX.Test(pkt)
	if err != nil {
		t.Fatalf("Program.Test failed: %v", err)
	}

	// Read updated stats
	var updatedStats []vswitch.SlotStats
	if err := objs.Maps.Stats.Lookup(uint32(testSlotID), &updatedStats); err != nil {
		t.Fatalf("failed to read updated stats: %v", err)
	}

	var updatedMgmtRx uint64
	for _, s := range updatedStats {
		updatedMgmtRx += s.MgmtRxPackets
	}

	// Stats should have increased
	if updatedMgmtRx <= initialMgmtRx {
		t.Errorf("mgmt_rx_packets not updated: initial=%d, updated=%d", initialMgmtRx, updatedMgmtRx)
	}
}

// testSetupMapsMultiCIDR initializes BPF maps with multiple management CIDRs.
func testSetupMapsMultiCIDR(t *testing.T, objs *bpf.Objects) {
	t.Helper()

	// Setup switch config
	cfg := vswitch.SwitchConfig{
		SwitchMac:      testSwitchMAC,
		N_ports:        testNumPorts,
		FloatingIpBase: testFloatingIPBase,
		GenevePortBase: testGenevePortBase,
		GeneveEncapEth: 1,
	}
	key := uint32(0)
	if err := objs.Maps.Config.Update(key, &cfg, ebpf.UpdateAny); err != nil {
		t.Fatalf("failed to setup config map: %v", err)
	}

	// Setup slot 0 with 3 management CIDRs (max supported after optimization)
	slot := vswitch.SlotItem{
		Ifindex:          100,
		InnerIp:          0xa9fe0101, // 169.254.1.1
		MgmtCidrCount:    3,
		TransitIfindex:   200,
		TransitIp:        0xc0a80a01, // 192.168.10.1
		TransitGatewayIp: 0xc0a80a02, // 192.168.10.2
		TransitGeneveVni: 12345,
	}

	// CIDR 0: 169.254.169.254/32 - metadata service (inline hot entry)
	slot.MgmtCidrs0 = vswitch.MgmtCIDR{
		Ip:      0xa9fea9fe, // 169.254.169.254
		Mask:    0xffffffff, // /32
		Ifindex: 150,
		MgmtMac: [6]byte{0x02, 0xde, 0xad, 0xbe, 0xff, 0xf0},
	}
	// CIDR 1: 169.254.169.123/32 - DNS service (extended array)
	slot.MgmtCidrsExt[0] = vswitch.MgmtCIDR{
		Ip:      0xa9fea97b, // 169.254.169.123
		Mask:    0xffffffff, // /32
		Ifindex: 151,
		MgmtMac: [6]byte{0x02, 0xde, 0xad, 0xbe, 0xff, 0xf1},
	}
	// CIDR 2: 169.254.170.0/24 - subnet (extended array)
	slot.MgmtCidrsExt[1] = vswitch.MgmtCIDR{
		Ip:      0xa9feaa00, // 169.254.170.0
		Mask:    0xffffff00, // /24
		Ifindex: 152,
		MgmtMac: [6]byte{0x02, 0xde, 0xad, 0xbe, 0xff, 0xf2},
	}
	// Note: MAX_MGMT_CIDR_PER_SLOT is now 3, so we can't add a 4th CIDR

	slotKey := uint32(testSlotID)
	if err := objs.Maps.Slots.Update(slotKey, &slot, ebpf.UpdateAny); err != nil {
		t.Fatalf("failed to setup slot: %v", err)
	}

	// Setup ifindex -> slot_id mapping
	ifindex := uint32(0)
	slotID := uint32(testSlotID)
	if err := objs.Maps.IfindexToSlot.Update(ifindex, &slotID, ebpf.UpdateAny); err != nil {
		t.Fatalf("failed to setup ifindex_to_slot: %v", err)
	}
}

// testSetupMapsSlot1 initializes BPF maps with slot 1 configuration.
func testSetupMapsSlot1(t *testing.T, objs *bpf.Objects) {
	t.Helper()

	// Setup switch config
	cfg := vswitch.SwitchConfig{
		SwitchMac:      testSwitchMAC,
		N_ports:        testNumPorts,
		FloatingIpBase: testFloatingIPBase,
		GenevePortBase: testGenevePortBase,
		GeneveEncapEth: 1,
	}
	key := uint32(0)
	if err := objs.Maps.Config.Update(key, &cfg, ebpf.UpdateAny); err != nil {
		t.Fatalf("failed to setup config map: %v", err)
	}

	// Setup slot 1
	slot1ID := uint32(1)
	slot := vswitch.SlotItem{
		Ifindex:          101,
		InnerIp:          0xa9fe0102, // 169.254.1.2
		MgmtCidrCount:    1,
		TransitIfindex:   200,
		TransitIp:        0xc0a80a01, // 192.168.10.1
		TransitGatewayIp: 0xc0a80a02, // 192.168.10.2
		TransitGeneveVni: 12346,
	}
	slot.MgmtCidrs0 = vswitch.MgmtCIDR{
		Ip:      0xa9fea9fe, // 169.254.169.254
		Mask:    0xffffffff, // /32
		Ifindex: 150,
		MgmtMac: [6]byte{0x02, 0xde, 0xad, 0xbe, 0xff, 0xf0},
	}

	if err := objs.Maps.Slots.Update(slot1ID, &slot, ebpf.UpdateAny); err != nil {
		t.Fatalf("failed to setup slot 1: %v", err)
	}
}

// TestIngressNxMultipleMgmtCIDRs tests match_mgmt_cidr() loop logic with multiple CIDRs.
func TestIngressNxMultipleMgmtCIDRs(t *testing.T) {
	ensureBPFEnv(t)

	objs, err := bpf.LoadObjects()
	if err != nil {
		t.Fatalf("LoadObjects: %v", err)
	}
	defer objs.Close()

	testSetupMapsMultiCIDR(t, objs)

	sandboxMAC := [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	sandboxIP := net.ParseIP("169.254.1.1")

	testCases := []struct {
		name          string
		targetIP      net.IP
		expectMgmt    bool
		wantMgmtMAC   [6]byte
		wantRetAction uint32
	}{
		{
			name:          "Match first CIDR (169.254.169.254/32)",
			targetIP:      net.ParseIP("169.254.169.254"),
			expectMgmt:    true,
			wantMgmtMAC:   [6]byte{0x02, 0xde, 0xad, 0xbe, 0xff, 0xf0},
			wantRetAction: TCActRedirect,
		},
		{
			name:          "Match second CIDR (169.254.169.123/32)",
			targetIP:      net.ParseIP("169.254.169.123"),
			expectMgmt:    true,
			wantMgmtMAC:   [6]byte{0x02, 0xde, 0xad, 0xbe, 0xff, 0xf1},
			wantRetAction: TCActRedirect,
		},
		{
			name:          "Match third CIDR - IP in 169.254.170.0/24",
			targetIP:      net.ParseIP("169.254.170.100"),
			expectMgmt:    true,
			wantMgmtMAC:   [6]byte{0x02, 0xde, 0xad, 0xbe, 0xff, 0xf2},
			wantRetAction: TCActRedirect,
		},
		{
			name:          "No match - external IP goes to GENEVE",
			targetIP:      net.ParseIP("8.8.8.8"),
			expectMgmt:    false,
			wantRetAction: TCActRedirect, // bpf_redirect_neigh()
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Build IP/UDP packet from sandbox
			pkt := buildIPv4UDPPacket(
				sandboxMAC, testSwitchMAC,
				sandboxIP, tc.targetIP,
				12345, 80,
				[]byte("test payload"),
			)

			// Run BPF program
			ret, out, err := objs.Programs.IngressNX.Test(pkt)
			if err != nil {
				t.Fatalf("Program.Test failed: %v", err)
			}

			if ret != tc.wantRetAction {
				t.Errorf("return action: got %d, want %d", ret, tc.wantRetAction)
			}

			if tc.expectMgmt {
				// For management traffic, check destination MAC
				ethHdr, err := parseEthernetHeader(out)
				if err != nil {
					t.Fatalf("parseEthernetHeader: %v", err)
				}
				if ethHdr.DstMAC != tc.wantMgmtMAC {
					t.Errorf("dst MAC: got %v, want %v", ethHdr.DstMAC, tc.wantMgmtMAC)
				}
			} else {
				// For external traffic, should have GENEVE encapsulation
				if len(out) < EthHdrLen+IPHdrLen+UDPHdrLen+GeneveHdrLen {
					t.Fatalf("output packet too short for GENEVE: %d bytes", len(out))
				}
				geneveHdr, err := parseGeneveHeader(out)
				if err != nil {
					t.Fatalf("parseGeneveHeader: %v", err)
				}
				if geneveHdr.VNI != 12345 {
					t.Errorf("GENEVE VNI: got %d, want 12345", geneveHdr.VNI)
				}
			}
		})
	}
}

// TestIngressMxInvalidFloatingIP tests floating IP boundary conditions.
func TestIngressMxInvalidFloatingIP(t *testing.T) {
	ensureBPFEnv(t)

	objs, err := bpf.LoadObjects()
	if err != nil {
		t.Fatalf("LoadObjects: %v", err)
	}
	defer objs.Close()

	testSetupMaps(t, objs)

	mgmtServiceMAC := [6]byte{0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}
	mgmtServiceIP := net.ParseIP("169.254.169.254")

	testCases := []struct {
		name          string
		floatingIP    net.IP
		wantRetAction uint32
	}{
		{
			// floating_ip < floating_ip_base
			name:          "Below floating IP base",
			floatingIP:    net.ParseIP("100.99.255.255"),
			wantRetAction: TCActOK,
		},
		{
			// floating_ip >= floating_ip_base + n_ports
			name:          "Above floating IP range",
			floatingIP:    net.ParseIP("100.100.0.4"), // base + 4, n_ports = 4
			wantRetAction: TCActOK,
		},
		{
			// floating_ip == floating_ip_base + n_ports - 1 (last valid slot)
			name:          "Last valid slot boundary",
			floatingIP:    net.ParseIP("100.100.0.3"), // slot 3, last valid
			wantRetAction: TCActOK,                    // slot 3 not initialized
		},
		{
			// Valid floating IP for slot 0
			name:          "Valid floating IP for slot 0",
			floatingIP:    net.ParseIP("100.100.0.0"),
			wantRetAction: TCActRedirect,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pkt := buildIPv4UDPPacket(
				mgmtServiceMAC, testSwitchMAC,
				mgmtServiceIP, tc.floatingIP,
				80, 12345,
				[]byte("HTTP/1.1 200 OK"),
			)

			ret, _, err := objs.Programs.IngressMX.Test(pkt)
			if err != nil {
				t.Fatalf("Program.Test failed: %v", err)
			}

			if ret != tc.wantRetAction {
				t.Errorf("return action: got %d, want %d", ret, tc.wantRetAction)
			}
		})
	}
}

// TestIngressTransitInvalidSlotID tests invalid slot_id boundary conditions.
func TestIngressTransitInvalidSlotID(t *testing.T) {
	ensureBPFEnv(t)

	objs, err := bpf.LoadObjects()
	if err != nil {
		t.Fatalf("LoadObjects: %v", err)
	}
	defer objs.Close()

	testSetupMaps(t, objs)

	// Build inner packet
	innerPkt := buildIPv4UDPPacket(
		[6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		portMAC(testSwitchMAC, testSlotID),
		net.ParseIP("8.8.8.8"),
		net.ParseIP("169.254.1.1"),
		53, 12345,
		[]byte("DNS response"),
	)

	gatewayIP := net.ParseIP("192.168.10.2")
	transitIP := net.ParseIP("192.168.10.1")

	testCases := []struct {
		name          string
		dstPort       uint16
		wantRetAction uint32
	}{
		{
			// dst_port < geneve_port_base
			name:          "Below GENEVE port base",
			dstPort:       uint16(testGenevePortBase - 1),
			wantRetAction: TCActOK,
		},
		{
			// slot_id >= n_ports (dst_port = geneve_port_base + n_ports)
			name:          "Slot ID exceeds n_ports",
			dstPort:       uint16(testGenevePortBase + testNumPorts),
			wantRetAction: TCActOK,
		},
		{
			// Valid slot 0
			name:          "Valid slot 0",
			dstPort:       uint16(testGenevePortBase + 0),
			wantRetAction: TCActRedirect,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pkt := buildGenevePacket(
				[6]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
				testSwitchMAC,
				gatewayIP, transitIP,
				49152, tc.dstPort,
				12345,
				GeneveProtoTEB,
				innerPkt,
			)

			ret, _, err := objs.Programs.IngressTransit.Test(pkt)
			if err != nil {
				t.Fatalf("Program.Test failed: %v", err)
			}

			if ret != tc.wantRetAction {
				t.Errorf("return action: got %d, want %d", ret, tc.wantRetAction)
			}
		})
	}
}

// TestIngressNxUninitializedSlot tests slot.inner_ip == 0 path.
func TestIngressNxUninitializedSlot(t *testing.T) {
	ensureBPFEnv(t)

	objs, err := bpf.LoadObjects()
	if err != nil {
		t.Fatalf("LoadObjects: %v", err)
	}
	defer objs.Close()

	// Setup config
	cfg := vswitch.SwitchConfig{
		SwitchMac:      testSwitchMAC,
		N_ports:        testNumPorts,
		FloatingIpBase: testFloatingIPBase,
		GenevePortBase: testGenevePortBase,
		GeneveEncapEth: 1,
	}
	key := uint32(0)
	if err := objs.Maps.Config.Update(key, &cfg, ebpf.UpdateAny); err != nil {
		t.Fatalf("failed to setup config map: %v", err)
	}

	// Setup slot with inner_ip = 0 (uninitialized)
	slot := vswitch.SlotItem{
		Ifindex: 100,
		InnerIp: 0, // Uninitialized!
	}
	slotKey := uint32(testSlotID)
	if err := objs.Maps.Slots.Update(slotKey, &slot, ebpf.UpdateAny); err != nil {
		t.Fatalf("failed to setup slot: %v", err)
	}

	// Setup ifindex -> slot_id mapping
	ifindex := uint32(0)
	slotID := uint32(testSlotID)
	if err := objs.Maps.IfindexToSlot.Update(ifindex, &slotID, ebpf.UpdateAny); err != nil {
		t.Fatalf("failed to setup ifindex_to_slot: %v", err)
	}

	sandboxMAC := [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	sandboxIP := net.ParseIP("169.254.1.1")
	externalIP := net.ParseIP("8.8.8.8")

	pkt := buildIPv4UDPPacket(
		sandboxMAC, testSwitchMAC,
		sandboxIP, externalIP,
		12345, 53,
		[]byte("test"),
	)

	ret, _, err := objs.Programs.IngressNX.Test(pkt)
	if err != nil {
		t.Fatalf("Program.Test failed: %v", err)
	}

	// Uninitialized slot should return TC_ACT_OK (not processed)
	if ret != TCActOK {
		t.Errorf("return action for uninitialized slot: got %d, want %d (TC_ACT_OK)", ret, TCActOK)
	}
}

// TestIngressMxNonFloatingIPARP tests ARP request for non-floating IP.
func TestIngressMxNonFloatingIPARP(t *testing.T) {
	ensureBPFEnv(t)

	objs, err := bpf.LoadObjects()
	if err != nil {
		t.Fatalf("LoadObjects: %v", err)
	}
	defer objs.Close()

	testSetupMaps(t, objs)

	mgmtServiceMAC := [6]byte{0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}
	mgmtServiceIP := net.ParseIP("169.254.169.254")

	// ARP request for an IP that is NOT a floating IP
	nonFloatingIP := net.ParseIP("192.168.1.1")

	pkt := buildARPRequest(mgmtServiceMAC, mgmtServiceIP, nonFloatingIP)

	ret, out, err := objs.Programs.IngressMX.Test(pkt)
	if err != nil {
		t.Fatalf("Program.Test failed: %v", err)
	}

	// Should return TC_ACT_REDIRECT with ARP reply using switch MAC
	if ret != TCActRedirect {
		t.Errorf("return action: got %d, want %d (TC_ACT_REDIRECT)", ret, TCActRedirect)
	}

	// Parse ARP reply
	arpReply, err := parseARPPacket(out)
	if err != nil {
		t.Fatalf("parseARPPacket: %v", err)
	}

	if arpReply.Operation != ARPOpReply {
		t.Errorf("ARP operation: got %d, want %d (REPLY)", arpReply.Operation, ARPOpReply)
	}

	// For non-floating IP, reply should use switch MAC (not port MAC)
	if arpReply.SenderMAC != testSwitchMAC {
		t.Errorf("sender MAC: got %v, want %v (switch MAC)", arpReply.SenderMAC, testSwitchMAC)
	}
}

// TestIngressNxMgmtSNATTCP tests TCP checksum update in SNAT path.
func TestIngressNxMgmtSNATTCP(t *testing.T) {
	ensureBPFEnv(t)

	objs, err := bpf.LoadObjects()
	if err != nil {
		t.Fatalf("LoadObjects: %v", err)
	}
	defer objs.Close()

	testSetupMaps(t, objs)

	sandboxMAC := [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	sandboxIP := net.ParseIP("169.254.1.1")
	mgmtIP := net.ParseIP("169.254.169.254")

	// Build TCP packet from sandbox to metadata service
	pkt := buildIPv4TCPPacket(
		sandboxMAC, testSwitchMAC,
		sandboxIP, mgmtIP,
		12345, 80,
		TCPFlagSYN|TCPFlagACK,
		[]byte("GET /metadata HTTP/1.1\r\n"),
	)

	ret, out, err := objs.Programs.IngressNX.Test(pkt)
	if err != nil {
		t.Fatalf("Program.Test failed: %v", err)
	}

	if ret != TCActRedirect {
		t.Errorf("return action: got %d, want %d (TC_ACT_REDIRECT)", ret, TCActRedirect)
	}

	// Verify IP header SNAT
	ipHdr, err := parseIPHeader(out)
	if err != nil {
		t.Fatalf("parseIPHeader: %v", err)
	}

	// Source should be SNAT'd to floating IP
	expectedSrcIP := net.ParseIP("100.100.0.0")
	if !ipHdr.SrcIP.Equal(expectedSrcIP) {
		t.Errorf("SNAT'd src IP: got %v, want %v", ipHdr.SrcIP, expectedSrcIP)
	}

	// Verify TCP header is valid
	tcpHdr, err := parseTCPHeader(out)
	if err != nil {
		t.Fatalf("parseTCPHeader: %v", err)
	}

	// Ports should be unchanged
	if tcpHdr.SrcPort != 12345 {
		t.Errorf("TCP src port: got %d, want 12345", tcpHdr.SrcPort)
	}
	if tcpHdr.DstPort != 80 {
		t.Errorf("TCP dst port: got %d, want 80", tcpHdr.DstPort)
	}

	// TCP checksum should have been updated (non-zero)
	if tcpHdr.Checksum == 0 {
		t.Error("TCP checksum is zero after SNAT")
	}

	// Check destination MAC
	ethHdr, err := parseEthernetHeader(out)
	if err != nil {
		t.Fatalf("parseEthernetHeader: %v", err)
	}
	expectedMgmtMAC := [6]byte{0x02, 0xde, 0xad, 0xbe, 0xff, 0xf0}
	if ethHdr.DstMAC != expectedMgmtMAC {
		t.Errorf("dst MAC: got %v, want %v", ethHdr.DstMAC, expectedMgmtMAC)
	}
}

// TestIngressTransitDecapSlot1 tests GENEVE decapsulation for non-slot-0.
func TestIngressTransitDecapSlot1(t *testing.T) {
	ensureBPFEnv(t)

	objs, err := bpf.LoadObjects()
	if err != nil {
		t.Fatalf("LoadObjects: %v", err)
	}
	defer objs.Close()

	testSetupMapsSlot1(t, objs)

	// Build inner packet for slot 1
	slot1ID := uint32(1)
	innerSrcMAC := [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	innerDstMAC := portMAC(testSwitchMAC, slot1ID)
	externalIP := net.ParseIP("8.8.8.8")
	sandboxIP := net.ParseIP("169.254.1.2")

	innerPkt := buildIPv4UDPPacket(
		innerSrcMAC, innerDstMAC,
		externalIP, sandboxIP,
		53, 12345,
		[]byte("DNS response"),
	)

	// Build outer GENEVE packet
	outerSrcMAC := [6]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	outerDstMAC := testSwitchMAC
	gatewayIP := net.ParseIP("192.168.10.2")
	transitIP := net.ParseIP("192.168.10.1")

	// GENEVE dst port for slot 1 = geneve_port_base + 1
	geneveDstPort := uint16(testGenevePortBase + slot1ID)

	pkt := buildGenevePacket(
		outerSrcMAC, outerDstMAC,
		gatewayIP, transitIP,
		49152, geneveDstPort,
		12346, // VNI for slot 1
		GeneveProtoTEB,
		innerPkt,
	)

	ret, out, err := objs.Programs.IngressTransit.Test(pkt)
	if err != nil {
		t.Fatalf("Program.Test failed: %v", err)
	}

	if ret != TCActRedirect {
		t.Errorf("return action: got %d, want %d (TC_ACT_REDIRECT)", ret, TCActRedirect)
	}

	// Check Ethernet header - dst should be slot 1's port MAC
	ethHdr, err := parseEthernetHeader(out)
	if err != nil {
		t.Fatalf("parseEthernetHeader: %v", err)
	}

	expectedDstMAC := portMAC(testSwitchMAC, slot1ID)
	if ethHdr.DstMAC != expectedDstMAC {
		t.Errorf("dst MAC: got %v, want %v (port MAC for slot 1)", ethHdr.DstMAC, expectedDstMAC)
	}
	if ethHdr.SrcMAC != testSwitchMAC {
		t.Errorf("src MAC: got %v, want %v (switch MAC)", ethHdr.SrcMAC, testSwitchMAC)
	}

	// Check IP header
	ipHdr, err := parseIPHeader(out)
	if err != nil {
		t.Fatalf("parseIPHeader: %v", err)
	}

	if !ipHdr.SrcIP.Equal(externalIP) {
		t.Errorf("inner src IP: got %v, want %v", ipHdr.SrcIP, externalIP)
	}
	if !ipHdr.DstIP.Equal(sandboxIP) {
		t.Errorf("inner dst IP: got %v, want %v", ipHdr.DstIP, sandboxIP)
	}
}
