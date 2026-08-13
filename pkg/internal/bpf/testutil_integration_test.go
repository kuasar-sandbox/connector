//go:build integration

package bpf_test

import (
	"encoding/binary"
	"fmt"
	"net"
)

// Ethernet header constants
const (
	EthHdrLen  = 14
	EthAddrLen = 6
	EthTypeIP  = 0x0800
	EthTypeARP = 0x0806
)

// IP header constants
const (
	IPHdrLen     = 20
	IPProtoUDP   = 17
	IPProtoTCP   = 6
	IPProtoICMP  = 1
	IPVersion4   = 4
	IPDefaultTTL = 64
)

// UDP header constants
const UDPHdrLen = 8

// ARP constants
const (
	ARPHdrLen     = 8
	ARPPayloadLen = 20 // Ethernet/IPv4 ARP payload
	ARPHwEther    = 1
	ARPOpRequest  = 1
	ARPOpReply    = 2
	ARPHwLen      = 6
	ARPProtoLen   = 4
)

// GENEVE constants
const (
	GeneveHdrLen   = 8
	GeneveProtoTEB = 0x6558 // Transparent Ethernet Bridging
)

// TC action codes (must match BPF)
const (
	TCActOK       = 0
	TCActShot     = 2
	TCActRedirect = 7
)

// buildEthernetFrame constructs an Ethernet frame.
func buildEthernetFrame(dst, src [6]byte, etherType uint16, payload []byte) []byte {
	frame := make([]byte, EthHdrLen+len(payload))
	copy(frame[0:6], dst[:])
	copy(frame[6:12], src[:])
	binary.BigEndian.PutUint16(frame[12:14], etherType)
	copy(frame[EthHdrLen:], payload)
	return frame
}

// buildARPRequest constructs an ARP request packet.
func buildARPRequest(srcMAC [6]byte, srcIP, dstIP net.IP) []byte {
	arpPayload := make([]byte, ARPHdrLen+ARPPayloadLen)

	// ARP header
	binary.BigEndian.PutUint16(arpPayload[0:2], ARPHwEther)   // Hardware type: Ethernet
	binary.BigEndian.PutUint16(arpPayload[2:4], EthTypeIP)    // Protocol type: IPv4
	arpPayload[4] = ARPHwLen                                  // Hardware size
	arpPayload[5] = ARPProtoLen                               // Protocol size
	binary.BigEndian.PutUint16(arpPayload[6:8], ARPOpRequest) // Opcode: Request

	// ARP payload
	copy(arpPayload[8:14], srcMAC[:])        // Sender MAC
	copy(arpPayload[14:18], srcIP.To4())     // Sender IP
	copy(arpPayload[18:24], make([]byte, 6)) // Target MAC (unknown)
	copy(arpPayload[24:28], dstIP.To4())     // Target IP

	// Ethernet frame
	var broadcastMAC [6]byte
	for i := range broadcastMAC {
		broadcastMAC[i] = 0xff
	}
	return buildEthernetFrame(broadcastMAC, srcMAC, EthTypeARP, arpPayload)
}

// buildARPReply constructs an ARP reply packet.
func buildARPReply(srcMAC, dstMAC [6]byte, srcIP, dstIP net.IP) []byte {
	arpPayload := make([]byte, ARPHdrLen+ARPPayloadLen)

	// ARP header
	binary.BigEndian.PutUint16(arpPayload[0:2], ARPHwEther)
	binary.BigEndian.PutUint16(arpPayload[2:4], EthTypeIP)
	arpPayload[4] = ARPHwLen
	arpPayload[5] = ARPProtoLen
	binary.BigEndian.PutUint16(arpPayload[6:8], ARPOpReply)

	// ARP payload
	copy(arpPayload[8:14], srcMAC[:])
	copy(arpPayload[14:18], srcIP.To4())
	copy(arpPayload[18:24], dstMAC[:])
	copy(arpPayload[24:28], dstIP.To4())

	return buildEthernetFrame(dstMAC, srcMAC, EthTypeARP, arpPayload)
}

// ipChecksum computes the IP header checksum.
func ipChecksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i < len(header); i += 2 {
		if i+1 < len(header) {
			sum += uint32(header[i])<<8 | uint32(header[i+1])
		} else {
			sum += uint32(header[i]) << 8
		}
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// buildIPPacket constructs an IP packet with the given payload.
func buildIPPacket(srcIP, dstIP net.IP, proto uint8, payload []byte) []byte {
	totalLen := IPHdrLen + len(payload)
	ip := make([]byte, totalLen)

	ip[0] = (IPVersion4 << 4) | (IPHdrLen / 4) // Version + IHL
	ip[1] = 0                                  // TOS
	binary.BigEndian.PutUint16(ip[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(ip[4:6], 0)      // ID
	binary.BigEndian.PutUint16(ip[6:8], 0x4000) // Flags: Don't Fragment
	ip[8] = IPDefaultTTL
	ip[9] = proto
	// Checksum at ip[10:12], computed below
	copy(ip[12:16], srcIP.To4())
	copy(ip[16:20], dstIP.To4())

	// Compute checksum
	csum := ipChecksum(ip[:IPHdrLen])
	binary.BigEndian.PutUint16(ip[10:12], csum)

	copy(ip[IPHdrLen:], payload)
	return ip
}

// buildUDPPacket constructs a UDP packet.
func buildUDPPacket(srcPort, dstPort uint16, payload []byte) []byte {
	udpLen := UDPHdrLen + len(payload)
	udp := make([]byte, udpLen)

	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	// Checksum at udp[6:8], leave as 0 (optional for IPv4/UDP)

	copy(udp[UDPHdrLen:], payload)
	return udp
}

// buildIPv4UDPPacket constructs a complete Ethernet+IP+UDP packet.
func buildIPv4UDPPacket(srcMAC, dstMAC [6]byte, srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	udp := buildUDPPacket(srcPort, dstPort, payload)
	ip := buildIPPacket(srcIP, dstIP, IPProtoUDP, udp)
	return buildEthernetFrame(dstMAC, srcMAC, EthTypeIP, ip)
}

// buildGeneveHeader constructs a GENEVE header without options.
func buildGeneveHeader(vni uint32, protoType uint16) []byte {
	return buildGeneveHeaderWithOptions(vni, protoType, false, nil)
}

// buildGeneveHeaderWithOptions constructs a GENEVE header with the exact wire
// options supplied by the caller. Options must already include their headers.
func buildGeneveHeaderWithOptions(vni uint32, protoType uint16, critical bool, options []byte) []byte {
	if len(options)%4 != 0 || len(options) > 0xfc {
		panic("GENEVE test options must be 4-byte aligned and fit opt_len")
	}
	geneve := make([]byte, GeneveHdrLen+len(options))
	geneve[0] = byte(len(options) / 4)
	if critical {
		geneve[1] = 0x40
	}
	binary.BigEndian.PutUint16(geneve[2:4], protoType)
	geneve[4] = byte((vni >> 16) & 0xff)
	geneve[5] = byte((vni >> 8) & 0xff)
	geneve[6] = byte(vni & 0xff)
	geneve[7] = 0 // Reserved
	copy(geneve[GeneveHdrLen:], options)
	return geneve
}

// buildGenevePacket constructs a GENEVE-encapsulated packet.
// Outer: Ethernet + IP + UDP + GENEVE
// Inner: raw payload (could be Ethernet frame or IP packet)
func buildGenevePacket(
	outerSrcMAC, outerDstMAC [6]byte,
	outerSrcIP, outerDstIP net.IP,
	srcPort, dstPort uint16,
	vni uint32,
	protoType uint16,
	innerPayload []byte,
) []byte {
	return buildGenevePacketWithOptions(
		outerSrcMAC, outerDstMAC,
		outerSrcIP, outerDstIP,
		srcPort, dstPort,
		vni, protoType, false, nil, innerPayload,
	)
}

// buildGenevePacketWithOptions constructs a GENEVE packet with exact option
// bytes and base-header C bit.
func buildGenevePacketWithOptions(
	outerSrcMAC, outerDstMAC [6]byte,
	outerSrcIP, outerDstIP net.IP,
	srcPort, dstPort uint16,
	vni uint32,
	protoType uint16,
	critical bool,
	options []byte,
	innerPayload []byte,
) []byte {
	geneve := buildGeneveHeaderWithOptions(vni, protoType, critical, options)

	// UDP payload = GENEVE header + inner payload
	udpPayload := make([]byte, 0, len(geneve)+len(innerPayload))
	udpPayload = append(udpPayload, geneve...)
	udpPayload = append(udpPayload, innerPayload...)
	udp := buildUDPPacket(srcPort, dstPort, udpPayload)
	ip := buildIPPacket(outerSrcIP, outerDstIP, IPProtoUDP, udp)
	return buildEthernetFrame(outerDstMAC, outerSrcMAC, EthTypeIP, ip)
}

// ARPPacket represents a parsed ARP packet.
type ARPPacket struct {
	HardwareType uint16
	ProtocolType uint16
	HardwareLen  uint8
	ProtocolLen  uint8
	Operation    uint16
	SenderMAC    [6]byte
	SenderIP     net.IP
	TargetMAC    [6]byte
	TargetIP     net.IP
}

// parseARPPacket parses an ARP packet from raw bytes.
func parseARPPacket(data []byte) (*ARPPacket, error) {
	if len(data) < EthHdrLen+ARPHdrLen+ARPPayloadLen {
		return nil, fmt.Errorf("packet too short for ARP: %d bytes", len(data))
	}

	// Skip Ethernet header
	arp := data[EthHdrLen:]

	pkt := &ARPPacket{
		HardwareType: binary.BigEndian.Uint16(arp[0:2]),
		ProtocolType: binary.BigEndian.Uint16(arp[2:4]),
		HardwareLen:  arp[4],
		ProtocolLen:  arp[5],
		Operation:    binary.BigEndian.Uint16(arp[6:8]),
		SenderIP:     net.IP(arp[14:18]),
		TargetIP:     net.IP(arp[24:28]),
	}
	copy(pkt.SenderMAC[:], arp[8:14])
	copy(pkt.TargetMAC[:], arp[18:24])

	return pkt, nil
}

// EthernetHeader represents a parsed Ethernet header.
type EthernetHeader struct {
	DstMAC    [6]byte
	SrcMAC    [6]byte
	EtherType uint16
}

// parseEthernetHeader parses an Ethernet header from raw bytes.
func parseEthernetHeader(data []byte) (*EthernetHeader, error) {
	if len(data) < EthHdrLen {
		return nil, fmt.Errorf("packet too short for Ethernet: %d bytes", len(data))
	}

	hdr := &EthernetHeader{
		EtherType: binary.BigEndian.Uint16(data[12:14]),
	}
	copy(hdr.DstMAC[:], data[0:6])
	copy(hdr.SrcMAC[:], data[6:12])

	return hdr, nil
}

// IPHeader represents a parsed IPv4 header.
type IPHeader struct {
	Version    uint8
	IHL        uint8
	TOS        uint8
	TotalLen   uint16
	ID         uint16
	Flags      uint16
	FragOffset uint16
	TTL        uint8
	Protocol   uint8
	Checksum   uint16
	SrcIP      net.IP
	DstIP      net.IP
}

// parseIPHeader parses an IPv4 header from raw bytes (after Ethernet header).
func parseIPHeader(data []byte) (*IPHeader, error) {
	if len(data) < EthHdrLen+IPHdrLen {
		return nil, fmt.Errorf("packet too short for IP: %d bytes", len(data))
	}

	ip := data[EthHdrLen:]

	hdr := &IPHeader{
		Version:    (ip[0] >> 4) & 0x0f,
		IHL:        ip[0] & 0x0f,
		TOS:        ip[1],
		TotalLen:   binary.BigEndian.Uint16(ip[2:4]),
		ID:         binary.BigEndian.Uint16(ip[4:6]),
		Flags:      (binary.BigEndian.Uint16(ip[6:8]) >> 13) & 0x7,
		FragOffset: binary.BigEndian.Uint16(ip[6:8]) & 0x1fff,
		TTL:        ip[8],
		Protocol:   ip[9],
		Checksum:   binary.BigEndian.Uint16(ip[10:12]),
		SrcIP:      net.IP(ip[12:16]),
		DstIP:      net.IP(ip[16:20]),
	}

	return hdr, nil
}

// UDPHeader represents a parsed UDP header.
type UDPHeader struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16
}

// parseUDPHeader parses a UDP header from raw bytes (after Ethernet+IP headers).
func parseUDPHeader(data []byte) (*UDPHeader, error) {
	offset := EthHdrLen + IPHdrLen
	if len(data) < offset+UDPHdrLen {
		return nil, fmt.Errorf("packet too short for UDP: %d bytes", len(data))
	}

	udp := data[offset:]
	return &UDPHeader{
		SrcPort:  binary.BigEndian.Uint16(udp[0:2]),
		DstPort:  binary.BigEndian.Uint16(udp[2:4]),
		Length:   binary.BigEndian.Uint16(udp[4:6]),
		Checksum: binary.BigEndian.Uint16(udp[6:8]),
	}, nil
}

// GeneveHeader represents a parsed GENEVE header.
type GeneveHeader struct {
	Version   uint8
	OptLen    uint8
	OAM       bool
	Critical  bool
	ProtoType uint16
	VNI       uint32
	Options   []byte
}

// parseGeneveHeader parses a GENEVE header from raw bytes (after Ethernet+IP+UDP).
func parseGeneveHeader(data []byte) (*GeneveHeader, error) {
	offset := EthHdrLen + IPHdrLen + UDPHdrLen
	if len(data) < offset+GeneveHdrLen {
		return nil, fmt.Errorf("packet too short for GENEVE: %d bytes", len(data))
	}

	g := data[offset:]
	optionsLen := int(g[0]&0x3f) * 4
	if len(g) < GeneveHdrLen+optionsLen {
		return nil, fmt.Errorf("packet too short for %d GENEVE option bytes: %d bytes", optionsLen, len(g))
	}
	return &GeneveHeader{
		Version:   (g[0] >> 6) & 0x3,
		OptLen:    g[0] & 0x3f,
		OAM:       (g[1] & 0x80) != 0,
		Critical:  (g[1] & 0x40) != 0,
		ProtoType: binary.BigEndian.Uint16(g[2:4]),
		VNI:       uint32(g[4])<<16 | uint32(g[5])<<8 | uint32(g[6]),
		Options:   g[GeneveHdrLen : GeneveHdrLen+optionsLen],
	}, nil
}

// GeneveOptionHeader represents one parsed wire option.
type GeneveOptionHeader struct {
	Class    uint16
	Type     uint8
	Reserved uint8
	Length   uint8
	Data     []byte
}

// parseGeneveOptions parses a bounded flat option sequence for test
// assertions. Production ingress deliberately does not use a general parser.
func parseGeneveOptions(options []byte) ([]GeneveOptionHeader, error) {
	var parsed []GeneveOptionHeader
	for len(options) > 0 {
		if len(options) < 4 {
			return nil, fmt.Errorf("truncated GENEVE option header: %d bytes", len(options))
		}
		dataLen := int(options[3]&0x1f) * 4
		wireLen := 4 + dataLen
		if len(options) < wireLen {
			return nil, fmt.Errorf("truncated GENEVE option data: have %d, want %d", len(options), wireLen)
		}
		parsed = append(parsed, GeneveOptionHeader{
			Class:    binary.BigEndian.Uint16(options[0:2]),
			Type:     options[2],
			Reserved: options[3] >> 5,
			Length:   options[3] & 0x1f,
			Data:     options[4:wireLen],
		})
		options = options[wireLen:]
	}
	return parsed, nil
}

// macToArray converts net.HardwareAddr to [6]byte.
func macToArray(mac net.HardwareAddr) [6]byte {
	var arr [6]byte
	copy(arr[:], mac)
	return arr
}

// portMAC derives a per-port MAC address (matches BPF logic).
// copy switchMAC[0:4], then:
// byte4 = ((switchMAC[4] ^ 0x80) & 0x80) | (slotID >> 8)
// byte5 = slotID & 0xFF
func portMAC(switchMAC [6]byte, slotID uint32) [6]byte {
	var mac [6]byte
	copy(mac[:4], switchMAC[:4])
	mac[4] = ((switchMAC[4] ^ 0x80) & 0x80) | byte(slotID>>8)
	mac[5] = byte(slotID & 0xff)
	return mac
}

// TCP header constants
const (
	TCPHdrLen  = 20
	TCPFlagSYN = 0x02
	TCPFlagACK = 0x10
	TCPFlagPSH = 0x08
	TCPFlagRST = 0x04
)

// TCPHeader represents a parsed TCP header.
type TCPHeader struct {
	SrcPort    uint16
	DstPort    uint16
	SeqNum     uint32
	AckNum     uint32
	DataOffset uint8
	Flags      uint8
	Window     uint16
	Checksum   uint16
	UrgentPtr  uint16
}

// parseTCPHeader parses a TCP header from raw bytes (after Ethernet+IP headers).
func parseTCPHeader(data []byte) (*TCPHeader, error) {
	offset := EthHdrLen + IPHdrLen
	if len(data) < offset+TCPHdrLen {
		return nil, fmt.Errorf("packet too short for TCP: %d bytes", len(data))
	}

	tcp := data[offset:]
	return &TCPHeader{
		SrcPort:    binary.BigEndian.Uint16(tcp[0:2]),
		DstPort:    binary.BigEndian.Uint16(tcp[2:4]),
		SeqNum:     binary.BigEndian.Uint32(tcp[4:8]),
		AckNum:     binary.BigEndian.Uint32(tcp[8:12]),
		DataOffset: (tcp[12] >> 4) & 0x0f,
		Flags:      tcp[13],
		Window:     binary.BigEndian.Uint16(tcp[14:16]),
		Checksum:   binary.BigEndian.Uint16(tcp[16:18]),
		UrgentPtr:  binary.BigEndian.Uint16(tcp[18:20]),
	}, nil
}

// buildTCPPacket constructs a TCP packet.
func buildTCPPacket(srcPort, dstPort uint16, flags uint8, payload []byte) []byte {
	tcpLen := TCPHdrLen + len(payload)
	tcp := make([]byte, tcpLen)

	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], 1000) // Seq num
	binary.BigEndian.PutUint32(tcp[8:12], 0)   // Ack num
	tcp[12] = (TCPHdrLen / 4) << 4             // Data offset
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535) // Window
	// Checksum at tcp[16:18], leave as 0 (will be computed below)
	binary.BigEndian.PutUint16(tcp[18:20], 0) // Urgent ptr

	copy(tcp[TCPHdrLen:], payload)
	return tcp
}

// tcpChecksum computes the TCP checksum including pseudo-header.
func tcpChecksum(srcIP, dstIP net.IP, tcpData []byte) uint16 {
	// Pseudo-header
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], srcIP.To4())
	copy(pseudo[4:8], dstIP.To4())
	pseudo[8] = 0
	pseudo[9] = IPProtoTCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcpData)))

	// Combine pseudo-header and TCP segment
	data := append(pseudo, tcpData...)

	// Pad to even length
	if len(data)%2 != 0 {
		data = append(data, 0)
	}

	// Compute checksum
	var sum uint32
	for i := 0; i < len(data); i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// buildIPv4TCPPacket constructs a complete Ethernet+IP+TCP packet.
func buildIPv4TCPPacket(srcMAC, dstMAC [6]byte, srcIP, dstIP net.IP, srcPort, dstPort uint16, flags uint8, payload []byte) []byte {
	tcp := buildTCPPacket(srcPort, dstPort, flags, payload)

	// Compute TCP checksum
	csum := tcpChecksum(srcIP, dstIP, tcp)
	binary.BigEndian.PutUint16(tcp[16:18], csum)

	ip := buildIPPacket(srcIP, dstIP, IPProtoTCP, tcp)
	return buildEthernetFrame(dstMAC, srcMAC, EthTypeIP, ip)
}
