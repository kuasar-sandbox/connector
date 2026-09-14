package bpf

import (
	"fmt"
	"net"
	"unsafe"
)

// Type aliases - re-export bpf2go generated types for external use.
// Using aliases (=) instead of definitions allows direct assignment compatibility.
type MgmtCIDR = vswitchMgmtCidr
type SlotItem = vswitchSlotItem
type SwitchConfig = vswitchSwitchConfig
type GeneveOptsValue = vswitchGeneveOptsValue
type SlotStats = vswitchSlotStats
type SvcKey = vswitchSvcKey
type SvcVal = vswitchSvcVal

// MetadataMaxSize is the maximum size of the JSON metadata stored in the BPF map.
const MetadataMaxSize = 4096

// Compile-time size checks
var (
	_ [108]byte = [unsafe.Sizeof(SlotItem{})]byte{}
	_ [104]byte = [unsafe.Offsetof(SlotItem{}.StatsReady)]byte{}
	_ [40]byte  = [unsafe.Sizeof(SwitchConfig{})]byte{}
	_ [68]byte  = [unsafe.Sizeof(GeneveOptsValue{})]byte{}
	_ [64]byte  = [unsafe.Sizeof(SlotStats{})]byte{}
	_ [20]byte  = [unsafe.Sizeof(MgmtCIDR{})]byte{}
	_ [8]byte   = [unsafe.Sizeof(SvcKey{})]byte{}
	_ [8]byte   = [unsafe.Sizeof(SvcVal{})]byte{}
)

// Re-exported constants from bpf2go generated enum values
const (
	MaxPorts             = uint32(vswitchExportedU32MAX_PORTS)
	MaxMgmtCIDRPerSlot   = uint32(vswitchExportedU32MAX_MGMT_CIDR_PER_SLOT)
	InnerIPFree          = uint32(vswitchExportedU32INNER_IP_FREE)
	InnerIPReserved      = uint32(vswitchExportedU32INNER_IP_RESERVED)
	MaxGeneveOptsLen     = uint32(vswitchExportedU32MAX_GENEVE_OPTS_LEN)
	GenevePort           = uint16(vswitchExportedU32GENEVE_PORT)
	GeneveLocatorPort    = uint8(vswitchExportedU32GENEVE_LOCATOR_PORT)
	GeneveLocatorVNI     = uint8(vswitchExportedU32GENEVE_LOCATOR_VNI)
	GeneveLocatorTLV     = uint8(vswitchExportedU32GENEVE_LOCATOR_TLV)
	GeneveVNILocatorBits = uint32(vswitchExportedU32GENEVE_VNI_LOCATOR_BITS)
	GeneveVNIValueMask   = uint32(vswitchExportedU32GENEVE_VNI_VALUE_MASK)
)

// PortKind identifies the underlying netdev type backing a port slot.
// Stored in SlotItem.Mode (offset 30).
// Existing pre-mode-bit slots have Mode==0 → treated as Veth (backward compatible).
type PortKind uint8

const (
	PortKindVeth PortKind = PortKind(vswitchExportedU32PORT_KIND_VETH) // 0 - default
	PortKindTap  PortKind = PortKind(vswitchExportedU32PORT_KIND_TAP)  // 1 - tap (sandbox sees fd)
)

// String returns a stable short label for the port kind.
func (k PortKind) String() string {
	switch k {
	case PortKindVeth:
		return "veth"
	case PortKindTap:
		return "tap"
	default:
		return "unknown"
	}
}

// ParsePortKind parses a port kind label. Empty string returns PortKindVeth (default).
func ParsePortKind(s string) (PortKind, error) {
	switch s {
	case "", "veth":
		return PortKindVeth, nil
	case "tap":
		return PortKindTap, nil
	default:
		return 0, fmt.Errorf("unknown port kind %q (want veth or tap)", s)
	}
}

// MaxMgmtCIDRExt is the size of the extended mgmt_cidrs array (cold path).
const MaxMgmtCIDRExt = MaxMgmtCIDRPerSlot - 1

// ========== SwitchConfig methods ==========

// SwitchMacAddr returns the switch MAC address.
func (c *SwitchConfig) SwitchMacAddr() net.HardwareAddr { return net.HardwareAddr(c.SwitchMac[:]) }

// SetSwitchMacAddr sets the switch MAC address.
func (c *SwitchConfig) SetSwitchMacAddr(mac net.HardwareAddr) { copy(c.SwitchMac[:], mac) }

// PortMacAddr returns the port MAC address.
func (c *SwitchConfig) PortMacAddr() net.HardwareAddr { return net.HardwareAddr(c.PortMac[:]) }

// SetPortMacAddr sets the port MAC address.
func (c *SwitchConfig) SetPortMacAddr(mac net.HardwareAddr) { copy(c.PortMac[:], mac) }

// IsPortMacZero returns true if the port MAC is all zeros.
func (c *SwitchConfig) IsPortMacZero() bool { return c.PortMac == [6]uint8{} }

// ========== MgmtCIDR methods ==========

// MgmtMacAddr returns the management MAC address.
func (m *MgmtCIDR) MgmtMacAddr() net.HardwareAddr { return net.HardwareAddr(m.MgmtMac[:]) }

// SetMgmtMacAddr sets the management MAC address.
func (m *MgmtCIDR) SetMgmtMacAddr(mac net.HardwareAddr) { copy(m.MgmtMac[:], mac) }

// ========== SlotItem methods ==========

// TransitMacAddr returns the transit MAC address.
func (s *SlotItem) TransitMacAddr() net.HardwareAddr { return net.HardwareAddr(s.TransitMac[:]) }

// SetTransitMacAddr sets the transit MAC address.
func (s *SlotItem) SetTransitMacAddr(mac net.HardwareAddr) { copy(s.TransitMac[:], mac) }

// IsTransitMacSet returns true if the transit MAC is set (non-zero).
func (s *SlotItem) IsTransitMacSet() bool { return s.TransitMac != [6]uint8{} }

// ClearTransitMac clears the transit MAC address.
func (s *SlotItem) ClearTransitMac() { s.TransitMac = [6]uint8{} }

// ========== Public helper functions ==========

// CopyStringToInts copies a string to an int8 slice (for bpf2go char arrays).
func CopyStringToInts(dst []int8, src string) {
	for i := range dst {
		dst[i] = 0 // Clear first
	}
	for i := 0; i < len(dst) && i < len(src); i++ {
		dst[i] = int8(src[i])
	}
}

// IntsToString converts an int8 slice to a Go string (stops at null terminator).
func IntsToString(arr []int8) string {
	if len(arr) == 0 {
		return ""
	}
	for i, c := range arr {
		if c == 0 {
			return string(unsafe.Slice((*byte)(unsafe.Pointer(&arr[0])), i))
		}
	}
	return string(unsafe.Slice((*byte)(unsafe.Pointer(&arr[0])), len(arr)))
}

// IPToUint32 converts a net.IP to uint32 (network byte order).
func IPToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// Uint32ToIP converts a uint32 to net.IP.
func Uint32ToIP(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

// MaskToUint32 converts a net.IPMask to uint32.
func MaskToUint32(mask net.IPMask) uint32 {
	if len(mask) == 4 {
		return uint32(mask[0])<<24 | uint32(mask[1])<<16 | uint32(mask[2])<<8 | uint32(mask[3])
	}
	// For IPv6 mask, take last 4 bytes
	if len(mask) == 16 {
		return uint32(mask[12])<<24 | uint32(mask[13])<<16 | uint32(mask[14])<<8 | uint32(mask[15])
	}
	return 0xffffffff
}

// MaskPrefixLen converts a uint32 mask to CIDR prefix length.
// For example, 0xffffff00 -> 24, 0xffffffff -> 32.
func MaskPrefixLen(mask uint32) int {
	prefixLen := 0
	for i := 31; i >= 0; i-- {
		if mask&(1<<uint(i)) != 0 {
			prefixLen++
		} else {
			break
		}
	}
	return prefixLen
}
