package bpfmap

import "net"

// PortMACXOR is the byte4 MSB flip mask used so per-port MACs cannot collide
// with the user-supplied switch MAC. See PortMAC for the derivation.
const PortMACXOR = 0x80

// MgmtMACIDBase is the base ID for management plane MACs (0x7FF0 + mgmtIdx).
// Chosen so mgmt MACs sit in a distinct numeric range from per-port MACs.
const MgmtMACIDBase = 0x7FF0

// PortMAC derives a per-port MAC address from the switch MAC and slot id.
//
//	copy switchMAC[0:4]
//	byte4 = ((switchMAC[4] ^ 0x80) & 0x80) | (slotID >> 8)
//	byte5 =  slotID & 0xFF
func PortMAC(switchMAC net.HardwareAddr, slotID uint32) net.HardwareAddr {
	mac := make(net.HardwareAddr, 6)
	copy(mac[:4], switchMAC[:4])
	mac[4] = ((switchMAC[4] ^ PortMACXOR) & PortMACXOR) | byte(slotID>>8)
	mac[5] = byte(slotID & 0xff)
	return mac
}

// MgmtMAC derives a per-mgmt-plane MAC: same scheme as PortMAC but with
// id = 0x7FF0 + mgmtIdx, so mgmt MACs occupy a reserved numeric range.
func MgmtMAC(switchMAC net.HardwareAddr, mgmtIdx int) net.HardwareAddr {
	mac := make(net.HardwareAddr, 6)
	copy(mac[:4], switchMAC[:4])
	id := uint16(MgmtMACIDBase) + uint16(mgmtIdx)
	mac[4] = ((switchMAC[4] ^ PortMACXOR) & PortMACXOR) | byte(id>>8)
	mac[5] = byte(id & 0xff)
	return mac
}

// PortMACFixed derives the fixed port MAC used when --port-mac-addr=fixed.
// All ports share this same MAC; see GetPortMAC for the per-port vs fixed
// selection logic.
func PortMACFixed(switchMAC net.HardwareAddr) net.HardwareAddr {
	return PortMAC(switchMAC, 1)
}

// IsZeroMAC reports whether the MAC is all-zero (sentinel for per-port mode).
func IsZeroMAC(mac net.HardwareAddr) bool {
	for _, b := range mac {
		if b != 0 {
			return false
		}
	}
	return true
}

// GetPortMAC returns the per-port MAC for a slot. If portMAC is zero
// (per-port mode), derives from switchMAC and slotID; otherwise returns a
// copy of the fixed portMAC.
func GetPortMAC(switchMAC, portMAC net.HardwareAddr, slotID uint32) net.HardwareAddr {
	if IsZeroMAC(portMAC) {
		return PortMAC(switchMAC, slotID)
	}
	result := make(net.HardwareAddr, 6)
	copy(result, portMAC)
	return result
}
