package vswitch

import (
	"errors"
	"net"
	"sync"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"

	"github.com/kuasar-sandbox/connector/pkg/internal/bpf"
)

// --- MAC derivation ---

func TestPortMAC(t *testing.T) {
	// Test 1: switch_mac[4] MSB=0 (0xAB = 0b10101011, MSB=1 actually)
	// Let's use a clearer example: switch_mac = 02:00:00:00:00:00 (byte4 MSB=0)
	switchMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x00}

	mac0 := PortMAC(switchMAC, 0)
	// byte4 = ((0x00 ^ 0x80) & 0x80) | 0x00 = 0x80 | 0x00 = 0x80
	// byte5 = 0x00
	if mac0.String() != "02:00:00:00:80:00" {
		t.Errorf("PortMAC(0) = %s, want 02:00:00:00:80:00", mac0)
	}

	mac1 := PortMAC(switchMAC, 1)
	// byte4 = 0x80 | 0x00 = 0x80, byte5 = 0x01
	if mac1.String() != "02:00:00:00:80:01" {
		t.Errorf("PortMAC(1) = %s, want 02:00:00:00:80:01", mac1)
	}

	mac256 := PortMAC(switchMAC, 256)
	// byte4 = 0x80 | 0x01 = 0x81, byte5 = 0x00
	if mac256.String() != "02:00:00:00:81:00" {
		t.Errorf("PortMAC(256) = %s, want 02:00:00:00:81:00", mac256)
	}

	mac4095 := PortMAC(switchMAC, 4095)
	// byte4 = 0x80 | 0x0F = 0x8F, byte5 = 0xFF
	if mac4095.String() != "02:00:00:00:8f:ff" {
		t.Errorf("PortMAC(4095) = %s, want 02:00:00:00:8f:ff", mac4095)
	}
}

func TestPortMACPreservesPrefix(t *testing.T) {
	switchMAC := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x00}
	mac := PortMAC(switchMAC, 0)
	// First 4 bytes preserved, byte4 = ((0x00 ^ 0x80) & 0x80) | 0x00 = 0x80
	if mac[0] != 0xaa || mac[1] != 0xbb || mac[2] != 0xcc || mac[3] != 0xdd || mac[4] != 0x80 {
		t.Errorf("prefix not preserved: %s, want aa:bb:cc:dd:80:00", mac)
	}
}

func TestPortMACWithMSBSet(t *testing.T) {
	// Test with switch_mac[4] MSB=1 (should flip to 0)
	switchMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x80, 0x00}

	mac0 := PortMAC(switchMAC, 0)
	// byte4 = ((0x80 ^ 0x80) & 0x80) | 0x00 = 0x00 | 0x00 = 0x00
	if mac0.String() != "02:00:00:00:00:00" {
		t.Errorf("PortMAC(0) = %s, want 02:00:00:00:00:00", mac0)
	}

	mac1 := PortMAC(switchMAC, 1)
	// byte4 = 0x00 | 0x00 = 0x00, byte5 = 0x01
	if mac1.String() != "02:00:00:00:00:01" {
		t.Errorf("PortMAC(1) = %s, want 02:00:00:00:00:01", mac1)
	}

	mac256 := PortMAC(switchMAC, 256)
	// byte4 = 0x00 | 0x01 = 0x01, byte5 = 0x00
	if mac256.String() != "02:00:00:00:01:00" {
		t.Errorf("PortMAC(256) = %s, want 02:00:00:00:01:00", mac256)
	}
}

func TestPortMACClearsLowBits(t *testing.T) {
	// Test that & 0x80 clears the low 7 bits of switch_mac[4]
	switchMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x85, 0xAB}

	mac0 := PortMAC(switchMAC, 0)
	// byte4 = ((0x85 ^ 0x80) & 0x80) | 0x00 = (0x05 & 0x80) | 0x00 = 0x00
	if mac0.String() != "02:00:00:00:00:00" {
		t.Errorf("PortMAC(0) = %s, want 02:00:00:00:00:00", mac0)
	}

	mac256 := PortMAC(switchMAC, 256)
	// byte4 = 0x00 | 0x01 = 0x01
	if mac256.String() != "02:00:00:00:01:00" {
		t.Errorf("PortMAC(256) = %s, want 02:00:00:00:01:00", mac256)
	}
}

func TestMgmtMAC(t *testing.T) {
	// Test with switch_mac[4] MSB=0
	switchMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x00}

	mac0 := MgmtMAC(switchMAC, 0)
	// id = 0x7FF0 + 0 = 0x7FF0
	// byte4 = ((0x00 ^ 0x80) & 0x80) | 0x7F = 0x80 | 0x7F = 0xFF
	// byte5 = 0xF0
	if mac0.String() != "02:00:00:00:ff:f0" {
		t.Errorf("MgmtMAC(0) = %s, want 02:00:00:00:ff:f0", mac0)
	}

	mac1 := MgmtMAC(switchMAC, 1)
	// id = 0x7FF1, byte5 = 0xF1
	if mac1.String() != "02:00:00:00:ff:f1" {
		t.Errorf("MgmtMAC(1) = %s, want 02:00:00:00:ff:f1", mac1)
	}

	// Test with switch_mac[4] MSB=1
	switchMAC2 := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x80, 0x00}
	mac2 := MgmtMAC(switchMAC2, 0)
	// byte4 = ((0x80 ^ 0x80) & 0x80) | 0x7F = 0x00 | 0x7F = 0x7F
	// byte5 = 0xF0
	if mac2.String() != "02:00:00:00:7f:f0" {
		t.Errorf("MgmtMAC(0) with MSB=1 = %s, want 02:00:00:00:7f:f0", mac2)
	}
}

func TestMACsDoNotOverlap(t *testing.T) {
	switchMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x05, 0xAB}

	// PortMAC range: byte4 MSB flipped, bytes4-5 encodes slot_id (0-4095)
	// MgmtMAC range: same derivation but with id = 0x7FF0..0x7FFF
	// switch_mac itself: byte4 MSB opposite from derived MACs

	port0 := PortMAC(switchMAC, 0)
	mgmt0 := MgmtMAC(switchMAC, 0)

	if port0.String() == mgmt0.String() {
		t.Error("PortMAC(0) == MgmtMAC(0)")
	}
	if port0.String() == switchMAC.String() {
		t.Error("PortMAC(0) == switchMAC")
	}
	if mgmt0.String() == switchMAC.String() {
		t.Error("MgmtMAC(0) == switchMAC")
	}

	// Verify byte4 MSB is always opposite from switch_mac[4] MSB
	switchMSB := switchMAC[4] & 0x80
	portMSB := port0[4] & 0x80
	if portMSB == switchMSB {
		t.Errorf("PortMAC byte4 MSB (%x) should be opposite of switch_mac byte4 MSB (%x)", portMSB, switchMSB)
	}
}

func TestPortMACFixed(t *testing.T) {
	// PortMACFixed uses slotID=1, so it's equivalent to PortMAC(switchMAC, 1)
	switchMAC, _ := net.ParseMAC("02:00:00:00:00:00")
	got := PortMACFixed(switchMAC)
	// byte4 = ((0x00 ^ 0x80) & 0x80) | 0x00 = 0x80, byte5 = 0x01
	want, _ := net.ParseMAC("02:00:00:00:80:01")
	if got.String() != want.String() {
		t.Errorf("PortMACFixed() = %s, want %s", got, want)
	}

	// Test with switch_mac[4] MSB=1
	switchMAC2, _ := net.ParseMAC("aa:bb:cc:dd:80:ff")
	got2 := PortMACFixed(switchMAC2)
	// byte4 = ((0x80 ^ 0x80) & 0x80) | 0x00 = 0x00, byte5 = 0x01
	want2, _ := net.ParseMAC("aa:bb:cc:dd:00:01")
	if got2.String() != want2.String() {
		t.Errorf("PortMACFixed() = %s, want %s", got2, want2)
	}

	// Verify PortMACFixed equals PortMAC with slotID=1
	if got.String() != PortMAC(switchMAC, 1).String() {
		t.Errorf("PortMACFixed should equal PortMAC(switchMAC, 1)")
	}
}

func TestIsZeroMAC(t *testing.T) {
	zero := make(net.HardwareAddr, 6)
	if !IsZeroMAC(zero) {
		t.Error("IsZeroMAC(zero) should be true")
	}

	nonzero, _ := net.ParseMAC("02:00:00:01:00:01")
	if IsZeroMAC(nonzero) {
		t.Error("IsZeroMAC(nonzero) should be false")
	}

	// Test with first byte non-zero
	firstNonZero := net.HardwareAddr{0x01, 0x00, 0x00, 0x00, 0x00, 0x00}
	if IsZeroMAC(firstNonZero) {
		t.Error("IsZeroMAC(firstNonZero) should be false")
	}

	// Test with last byte non-zero
	lastNonZero := net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	if IsZeroMAC(lastNonZero) {
		t.Error("IsZeroMAC(lastNonZero) should be false")
	}

	// Test empty MAC
	if !IsZeroMAC(nil) {
		t.Error("IsZeroMAC(nil) should be true")
	}
}

func TestGetPortMAC(t *testing.T) {
	switchMAC, _ := net.ParseMAC("02:00:00:00:00:00")

	// per-port mode (portMAC is all zeros)
	zeroMAC := make(net.HardwareAddr, 6)
	got0 := GetPortMAC(switchMAC, zeroMAC, 0)
	want0, _ := net.ParseMAC("02:00:00:00:80:00") // slot 0
	if got0.String() != want0.String() {
		t.Errorf("GetPortMAC(per-port, 0) = %s, want %s", got0, want0)
	}

	got1 := GetPortMAC(switchMAC, zeroMAC, 1)
	want1, _ := net.ParseMAC("02:00:00:00:80:01") // slot 1
	if got1.String() != want1.String() {
		t.Errorf("GetPortMAC(per-port, 1) = %s, want %s", got1, want1)
	}

	// fixed mode (portMAC is non-zero)
	fixedMAC, _ := net.ParseMAC("02:00:00:00:80:01")
	gotFixed0 := GetPortMAC(switchMAC, fixedMAC, 0)
	if gotFixed0.String() != fixedMAC.String() {
		t.Errorf("GetPortMAC(fixed, 0) = %s, want %s", gotFixed0, fixedMAC)
	}

	gotFixed1 := GetPortMAC(switchMAC, fixedMAC, 1)
	if gotFixed1.String() != fixedMAC.String() {
		t.Errorf("GetPortMAC(fixed, 1) = %s, want %s", gotFixed1, fixedMAC)
	}

	// custom mode (user-specified MAC)
	customMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	gotCustom := GetPortMAC(switchMAC, customMAC, 5)
	if gotCustom.String() != customMAC.String() {
		t.Errorf("GetPortMAC(custom, 5) = %s, want %s", gotCustom, customMAC)
	}
}

// --- SwitchMetadata getters ---

func TestSwitchMetadataGetters(t *testing.T) {
	meta := SwitchMetadata{
		SwitchNetNS: "test_switch",
		PortNetNS:   "test_port",
		TransitDev:  "eth1",
	}

	if meta.SwitchNetnsName() != "test_switch" {
		t.Errorf("SwitchNetnsName = %q", meta.SwitchNetnsName())
	}
	if meta.PortNetnsName() != "test_port" {
		t.Errorf("PortNetnsName = %q", meta.PortNetnsName())
	}
	if meta.TransitDevName() != "eth1" {
		t.Errorf("TransitDevName = %q", meta.TransitDevName())
	}
}

func TestSwitchMetadataGettersEmpty(t *testing.T) {
	meta := SwitchMetadata{}
	if meta.SwitchNetnsName() != "" {
		t.Errorf("SwitchNetnsName = %q, want empty", meta.SwitchNetnsName())
	}
	if meta.TransitDevName() != "" {
		t.Errorf("TransitDevName = %q, want empty", meta.TransitDevName())
	}
}

// --- MmappedSlots tests ---

func TestMmappedSlotsTryAllocate(t *testing.T) {
	m := newMmappedSlotsForTest(4)
	defer m.Close()

	// Allocate empty slot should succeed
	if !m.TryAllocate(0, 0x0a000001) {
		t.Error("TryAllocate on empty slot should succeed")
	}

	// Verify InnerIP was set
	if ip := m.GetInnerIP(0); ip != 0x0a000001 {
		t.Errorf("InnerIP = %#x, want %#x", ip, 0x0a000001)
	}

	// Allocate already occupied slot should fail
	if m.TryAllocate(0, 0x0a000002) {
		t.Error("TryAllocate on occupied slot should fail")
	}

	// InnerIP should remain unchanged
	if ip := m.GetInnerIP(0); ip != 0x0a000001 {
		t.Errorf("InnerIP after failed allocate = %#x, want %#x", ip, 0x0a000001)
	}
}

func TestMmappedSlotsTryAllocateMultipleSlots(t *testing.T) {
	m := newMmappedSlotsForTest(4)
	defer m.Close()

	// Allocate multiple different slots
	for i := uint32(0); i < 4; i++ {
		ip := 0x0a000001 + i
		if !m.TryAllocate(i, ip) {
			t.Errorf("TryAllocate slot %d should succeed", i)
		}
	}

	// Verify all allocated
	for i := uint32(0); i < 4; i++ {
		expected := 0x0a000001 + i
		if ip := m.GetInnerIP(i); ip != expected {
			t.Errorf("slot %d: InnerIP = %#x, want %#x", i, ip, expected)
		}
	}
}

func TestMmappedSlotsTryRelease(t *testing.T) {
	m := newMmappedSlotsForTest(4)
	defer m.Close()

	// Allocate slot first
	m.TryAllocate(0, 0x0a000001)

	// Release with correct IP should succeed
	if !m.TryRelease(0, 0x0a000001) {
		t.Error("TryRelease with correct IP should succeed")
	}

	// Verify slot is now free
	if ip := m.GetInnerIP(0); ip != 0 {
		t.Errorf("InnerIP after release = %#x, want 0", ip)
	}
}

func TestMmappedSlotsTryReleaseWrongIP(t *testing.T) {
	m := newMmappedSlotsForTest(4)
	defer m.Close()

	// Allocate slot first
	m.TryAllocate(0, 0x0a000001)

	// Release with wrong IP should fail
	if m.TryRelease(0, 0x0a000002) {
		t.Error("TryRelease with wrong IP should fail")
	}

	// Verify slot still occupied with original IP
	if ip := m.GetInnerIP(0); ip != 0x0a000001 {
		t.Errorf("InnerIP after failed release = %#x, want %#x", ip, 0x0a000001)
	}
}

func TestMmappedSlotsTryReleaseEmptySlot(t *testing.T) {
	m := newMmappedSlotsForTest(4)
	defer m.Close()

	// Release on empty slot should fail (current IP is 0, not 0x0a000001)
	if m.TryRelease(0, 0x0a000001) {
		t.Error("TryRelease on empty slot should fail")
	}
}

func TestMmappedSlotsTryReserve(t *testing.T) {
	m := newMmappedSlotsForTest(4)
	defer m.Close()

	// Allocate slot first
	m.TryAllocate(0, 0x0a000001)

	// Reserve with correct IP should succeed
	if !m.TryReserve(0, 0x0a000001) {
		t.Error("TryReserve with correct IP should succeed")
	}

	// Verify slot is now reserved (0xFFFFFFFF)
	if ip := m.GetInnerIP(0); ip != InnerIPReserved {
		t.Errorf("InnerIP after reserve = %#x, want %#x", ip, InnerIPReserved)
	}
}

func TestMmappedSlotsTryReserveWrongIP(t *testing.T) {
	m := newMmappedSlotsForTest(4)
	defer m.Close()

	// Allocate slot first
	m.TryAllocate(0, 0x0a000001)

	// Reserve with wrong IP should fail
	if m.TryReserve(0, 0x0a000002) {
		t.Error("TryReserve with wrong IP should fail")
	}

	// Verify slot still has original IP
	if ip := m.GetInnerIP(0); ip != 0x0a000001 {
		t.Errorf("InnerIP after failed reserve = %#x, want %#x", ip, 0x0a000001)
	}
}

func TestMmappedSlotsTryReserveAlreadyReserved(t *testing.T) {
	m := newMmappedSlotsForTest(4)
	defer m.Close()

	// Allocate and then reserve
	m.TryAllocate(0, 0x0a000001)
	m.TryReserve(0, 0x0a000001)

	// Second reserve should fail (currentIP == InnerIPReserved check)
	if m.TryReserve(0, InnerIPReserved) {
		t.Error("TryReserve on already reserved slot should fail")
	}
}

func TestMmappedSlotsTryReserveEmptySlot(t *testing.T) {
	m := newMmappedSlotsForTest(4)
	defer m.Close()

	// Reserve on empty slot should succeed (0 -> InnerIPReserved)
	if !m.TryReserve(0, 0) {
		t.Error("TryReserve on empty slot should succeed")
	}

	// Verify slot is now reserved
	if ip := m.GetInnerIP(0); ip != InnerIPReserved {
		t.Errorf("InnerIP after reserve = %#x, want %#x", ip, InnerIPReserved)
	}
}

func TestMmappedSlotsTryReserveOutOfBounds(t *testing.T) {
	m := newMmappedSlotsForTest(4)
	defer m.Close()

	// Reserve on out of bounds slot should fail (ptr == nil)
	if m.TryReserve(4, 0) {
		t.Error("TryReserve on out of bounds slot should fail")
	}
	if m.TryReserve(100, 0) {
		t.Error("TryReserve way out of bounds should fail")
	}
}

func TestMmappedSlotsGetInnerIP(t *testing.T) {
	m := newMmappedSlotsForTest(4)
	defer m.Close()

	// Empty slot should return 0
	if ip := m.GetInnerIP(0); ip != 0 {
		t.Errorf("GetInnerIP on empty slot = %#x, want 0", ip)
	}

	// After allocation
	m.TryAllocate(0, 0xc0a80001) // 192.168.0.1
	if ip := m.GetInnerIP(0); ip != 0xc0a80001 {
		t.Errorf("GetInnerIP = %#x, want %#x", ip, 0xc0a80001)
	}
}

func TestMmappedSlotsGetSlot(t *testing.T) {
	m := newMmappedSlotsForTest(4)
	defer m.Close()

	// Get slot pointer
	slot := m.GetSlot(0)
	if slot == nil {
		t.Fatal("GetSlot returned nil")
	}

	// Modify via pointer
	slot.Ifindex = 123
	slot.InnerIp = 0x0a000001

	// Verify via GetInnerIP
	if ip := m.GetInnerIP(0); ip != 0x0a000001 {
		t.Errorf("InnerIP via GetInnerIP = %#x, want %#x", ip, 0x0a000001)
	}

	// Verify via GetSlot again
	slot2 := m.GetSlot(0)
	if slot2.Ifindex != 123 {
		t.Errorf("Ifindex = %d, want 123", slot2.Ifindex)
	}
}

func TestMmappedSlotsGetSlotDifferentSlots(t *testing.T) {
	m := newMmappedSlotsForTest(4)
	defer m.Close()

	// Modify different slots
	for i := uint32(0); i < 4; i++ {
		slot := m.GetSlot(i)
		slot.Ifindex = i + 100
		slot.InnerIp = 0x0a000000 + i
	}

	// Verify each slot has correct values
	for i := uint32(0); i < 4; i++ {
		slot := m.GetSlot(i)
		if slot.Ifindex != i+100 {
			t.Errorf("slot %d: Ifindex = %d, want %d", i, slot.Ifindex, i+100)
		}
		expectedIP := 0x0a000000 + i
		if slot.InnerIp != expectedIP {
			t.Errorf("slot %d: InnerIP = %#x, want %#x", i, slot.InnerIp, expectedIP)
		}
	}
}

func TestMmappedSlotsUpdateSlotFields(t *testing.T) {
	m := newMmappedSlotsForTest(4)
	defer m.Close()

	// First allocate the slot
	m.TryAllocate(0, 0x0a000001)

	// Update fields via callback
	m.UpdateSlotFields(0, func(slot *SlotItem) {
		slot.TransitGatewayIp = 0xc0a80001
		slot.TransitGeneveVni = 12345
		slot.TransitMac = [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	})

	// Verify fields
	slot := m.GetSlot(0)
	if slot.TransitGatewayIp != 0xc0a80001 {
		t.Errorf("TransitGatewayIP = %#x, want %#x", slot.TransitGatewayIp, 0xc0a80001)
	}
	if slot.TransitGeneveVni != 12345 {
		t.Errorf("TransitGeneveVNI = %d, want 12345", slot.TransitGeneveVni)
	}
	expectedMAC := [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	if slot.TransitMac != expectedMAC {
		t.Errorf("TransitMAC = %v, want %v", slot.TransitMac, expectedMAC)
	}
}

func TestMmappedSlotsUpdateSlotFieldsMgmtCIDR(t *testing.T) {
	m := newMmappedSlotsForTest(4)
	defer m.Close()

	m.UpdateSlotFields(0, func(slot *SlotItem) {
		slot.MgmtCidrCount = 1
		slot.MgmtCidrs0 = MgmtCIDR{
			Ip:      0x0a000000, // 10.0.0.0
			Mask:    0xff000000, // /8
			Ifindex: 5,
			MgmtMac: [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02},
		}
	})

	slot := m.GetSlot(0)
	if slot.MgmtCidrCount != 1 {
		t.Errorf("MgmtCIDRCount = %d, want 1", slot.MgmtCidrCount)
	}
	if slot.MgmtCidrs0.Ip != 0x0a000000 {
		t.Errorf("MgmtCIDRs0.Ip = %#x, want %#x", slot.MgmtCidrs0.Ip, 0x0a000000)
	}
	if slot.MgmtCidrs0.Ifindex != 5 {
		t.Errorf("MgmtCIDRs0.Ifindex = %d, want 5", slot.MgmtCidrs0.Ifindex)
	}
}

func TestMmappedSlotsFindFreeSlot(t *testing.T) {
	m := newMmappedSlotsForTest(4)
	defer m.Close()

	// All slots free - should get slot 0
	slotID, err := m.FindFreeSlot(0x0a000001)
	if err != nil {
		t.Fatalf("FindFreeSlot: %v", err)
	}
	if slotID != 0 {
		t.Errorf("slotID = %d, want 0", slotID)
	}

	// Slot 0 now occupied, should get slot 1
	slotID, err = m.FindFreeSlot(0x0a000002)
	if err != nil {
		t.Fatalf("FindFreeSlot: %v", err)
	}
	if slotID != 1 {
		t.Errorf("slotID = %d, want 1", slotID)
	}
}

func TestMmappedSlotsFindFreeSlotAllOccupied(t *testing.T) {
	m := newMmappedSlotsForTest(4)
	defer m.Close()

	// Occupy all slots
	for i := uint32(0); i < 4; i++ {
		m.TryAllocate(i, 0x0a000001+i)
	}

	// Should fail
	_, err := m.FindFreeSlot(0x0a000010)
	if err == nil {
		t.Error("FindFreeSlot should fail when all slots occupied")
	}
}

func TestMmappedSlotsFindFreeSlotAfterRelease(t *testing.T) {
	m := newMmappedSlotsForTest(4)
	defer m.Close()

	// Occupy all slots
	for i := uint32(0); i < 4; i++ {
		m.TryAllocate(i, 0x0a000001+i)
	}

	// Release slot 2
	m.TryRelease(2, 0x0a000003)

	// Should get slot 2
	slotID, err := m.FindFreeSlot(0x0a000010)
	if err != nil {
		t.Fatalf("FindFreeSlot: %v", err)
	}
	if slotID != 2 {
		t.Errorf("slotID = %d, want 2", slotID)
	}
}

func TestMmappedSlotsOutOfBounds(t *testing.T) {
	m := newMmappedSlotsForTest(4)
	defer m.Close()

	// TryAllocate out of bounds
	if m.TryAllocate(4, 0x0a000001) {
		t.Error("TryAllocate out of bounds should fail")
	}
	if m.TryAllocate(100, 0x0a000001) {
		t.Error("TryAllocate way out of bounds should fail")
	}

	// TryRelease out of bounds
	if m.TryRelease(4, 0x0a000001) {
		t.Error("TryRelease out of bounds should fail")
	}

	// GetInnerIP out of bounds
	if ip := m.GetInnerIP(4); ip != 0 {
		t.Errorf("GetInnerIP out of bounds = %#x, want 0", ip)
	}

	// GetSlot out of bounds
	if slot := m.GetSlot(4); slot != nil {
		t.Error("GetSlot out of bounds should return nil")
	}

	// UpdateSlotFields out of bounds should not panic
	m.UpdateSlotFields(4, func(slot *SlotItem) {
		t.Error("UpdateSlotFields callback should not be called for out of bounds")
	})
}

func TestMmappedSlotsConcurrent(t *testing.T) {
	m := newMmappedSlotsForTest(100)
	defer m.Close()

	// Multiple goroutines try to allocate and release concurrently
	const numGoroutines = 10
	const numOperations = 100

	var wg sync.WaitGroup
	allocateCount := make([]int, numGoroutines)

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			ip := uint32(0x0a000001 + gid)
			for i := 0; i < numOperations; i++ {
				// Try to allocate any slot
				for s := uint32(0); s < 100; s++ {
					if m.TryAllocate(s, ip) {
						allocateCount[gid]++
						// Immediately release
						m.TryRelease(s, ip)
						break
					}
				}
			}
		}(g)
	}

	wg.Wait()

	// Verify all slots are free after concurrent operations
	for i := uint32(0); i < 100; i++ {
		if ip := m.GetInnerIP(i); ip != 0 {
			t.Errorf("slot %d still allocated after concurrent test: %#x", i, ip)
		}
	}

	// Verify some operations succeeded (not all will due to contention)
	totalAllocations := 0
	for _, c := range allocateCount {
		totalAllocations += c
	}
	if totalAllocations == 0 {
		t.Error("No allocations succeeded in concurrent test")
	}
}

func TestMmappedSlotsConcurrentSameSlot(t *testing.T) {
	m := newMmappedSlotsForTest(1)
	defer m.Close()

	// Multiple goroutines compete for same slot
	const numGoroutines = 10
	successCount := make(chan int, numGoroutines)

	var wg sync.WaitGroup
	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			ip := uint32(0x0a000001 + gid)
			if m.TryAllocate(0, ip) {
				successCount <- gid
			}
		}(g)
	}

	wg.Wait()
	close(successCount)

	// Exactly one should succeed
	count := 0
	var winner int
	for gid := range successCount {
		count++
		winner = gid
	}
	if count != 1 {
		t.Errorf("Expected exactly 1 allocation, got %d", count)
	}

	// Verify the winner's IP is in the slot
	expectedIP := uint32(0x0a000001 + winner)
	if ip := m.GetInnerIP(0); ip != expectedIP {
		t.Errorf("InnerIP = %#x, want %#x", ip, expectedIP)
	}
}

// TestMmappedSlotsClose and TestMmappedSlotsClosePreservesOtherFields moved to
// pkg/internal/bpfmap/slots_test.go because they exercise unexported fields
// of MmappedSlots which are no longer accessible from this package.

// --- InitSlotReserved tests ---

func TestInitSlotReservedSuccess(t *testing.T) {
	m := newMmappedSlotsForTest(4)
	defer m.Close()

	if !InitSlotReserved(m, 0) {
		t.Fatal("InitSlotReserved should succeed on free slot")
	}

	// Verify slot is reserved
	if ip := m.GetInnerIP(0); ip != InnerIPReserved {
		t.Errorf("InnerIP = %#x, want %#x", ip, InnerIPReserved)
	}
}

func TestInitSlotReservedAlreadyAllocated(t *testing.T) {
	m := newMmappedSlotsForTest(4)
	defer m.Close()

	// Pre-allocate slot
	m.TryAllocate(0, 0x0a000001)

	// Should fail because slot is not free
	if InitSlotReserved(m, 0) {
		t.Fatal("InitSlotReserved should fail on allocated slot")
	}
}

func TestInitSlotReservedDoubleReserve(t *testing.T) {
	m := newMmappedSlotsForTest(4)
	defer m.Close()

	// Reserve slot
	if !InitSlotReserved(m, 0) {
		t.Fatal("first InitSlotReserved should succeed")
	}

	// Second reserve should fail (slot is already reserved, not free)
	if InitSlotReserved(m, 0) {
		t.Fatal("InitSlotReserved should fail on already reserved slot")
	}
}

func TestCountAllocatedSlotsWithAllocatedSlots(t *testing.T) {
	m := newMmappedSlotsForTest(4)
	defer m.Close()

	// Initially all slots are free
	if count := m.CountAllocatedSlots(); count != 0 {
		t.Errorf("CountAllocatedSlots() = %d, want 0", count)
	}

	// Allocate some slots
	m.TryAllocate(0, 0x0a000001)
	m.TryAllocate(2, 0x0a000003)

	if count := m.CountAllocatedSlots(); count != 2 {
		t.Errorf("CountAllocatedSlots() = %d, want 2", count)
	}

	// Allocate all slots
	m.TryAllocate(1, 0x0a000002)
	m.TryAllocate(3, 0x0a000004)

	if count := m.CountAllocatedSlots(); count != 4 {
		t.Errorf("CountAllocatedSlots() = %d, want 4", count)
	}

	// Release one slot
	m.TryRelease(1, 0x0a000002)

	if count := m.CountAllocatedSlots(); count != 3 {
		t.Errorf("CountAllocatedSlots() = %d, want 3", count)
	}
}

func TestCountReservedSlots(t *testing.T) {
	m := newMmappedSlotsForTest(8)
	defer m.Close()

	// Initially no reserved slots
	if count := m.CountReservedSlots(); count != 0 {
		t.Errorf("CountReservedSlots() = %d, want 0", count)
	}

	// Reserve some slots
	m.TryReserve(0, InnerIPFree)
	m.TryReserve(2, InnerIPFree)
	m.TryReserve(5, InnerIPFree)

	if count := m.CountReservedSlots(); count != 3 {
		t.Errorf("CountReservedSlots() = %d, want 3", count)
	}

	// Allocate a slot (should not count as reserved)
	m.TryAllocate(1, 0x0a000001)

	if count := m.CountReservedSlots(); count != 3 {
		t.Errorf("CountReservedSlots() = %d, want 3 (allocated slot should not count)", count)
	}

	// Unreserve one
	m.TryUnreserve(2)

	if count := m.CountReservedSlots(); count != 2 {
		t.Errorf("CountReservedSlots() = %d, want 2", count)
	}
}

func TestCountFreeSlots(t *testing.T) {
	m := newMmappedSlotsForTest(8)
	defer m.Close()

	// Initially all slots are free
	if count := m.CountFreeSlots(); count != 8 {
		t.Errorf("CountFreeSlots() = %d, want 8", count)
	}

	// Allocate some
	m.TryAllocate(0, 0x0a000001)
	m.TryAllocate(1, 0x0a000002)

	if count := m.CountFreeSlots(); count != 6 {
		t.Errorf("CountFreeSlots() = %d, want 6", count)
	}

	// Reserve some
	m.TryReserve(3, InnerIPFree)
	m.TryReserve(4, InnerIPFree)

	if count := m.CountFreeSlots(); count != 4 {
		t.Errorf("CountFreeSlots() = %d, want 4 (reserved slots should not count as free)", count)
	}

	// Verify: used + reserved + free == total
	used := m.CountAllocatedSlots()
	reserved := m.CountReservedSlots()
	free := m.CountFreeSlots()
	if used+reserved+free != 8 {
		t.Errorf("used(%d) + reserved(%d) + free(%d) = %d, want 8", used, reserved, free, used+reserved+free)
	}
}

// --- TryUnreserve tests ---

func TestTryUnreserveOutOfRange(t *testing.T) {
	m := newMmappedSlotsForTest(4)
	defer m.Close()

	// slotID >= numSlots should return false (nil ptr branch)
	if m.TryUnreserve(4) {
		t.Error("TryUnreserve on out-of-range slot (== numSlots) should return false")
	}
	if m.TryUnreserve(100) {
		t.Error("TryUnreserve on out-of-range slot (>> numSlots) should return false")
	}
}

func TestTryUnreserveSuccess(t *testing.T) {
	m := newMmappedSlotsForTest(4)
	defer m.Close()

	// Reserve slot 0: Free -> Reserved
	if !m.TryReserve(0, InnerIPFree) {
		t.Fatal("TryReserve should succeed on free slot")
	}
	if ip := m.GetInnerIP(0); ip != InnerIPReserved {
		t.Fatalf("slot should be Reserved, got %#x", ip)
	}

	// Unreserve: Reserved -> Free
	if !m.TryUnreserve(0) {
		t.Error("TryUnreserve on Reserved slot should return true")
	}
	if ip := m.GetInnerIP(0); ip != InnerIPFree {
		t.Errorf("slot should be Free after TryUnreserve, got %#x", ip)
	}
}

func TestTryUnreserveNotReserved(t *testing.T) {
	m := newMmappedSlotsForTest(4)
	defer m.Close()

	// Slot 0 is Free (default) — TryUnreserve expects Reserved, CAS should fail
	// because CAS(Reserved → Free) when current is Free will fail
	// Actually InnerIPFree == 0, InnerIPReserved == 0xFFFFFFFF, so CAS(0xFFFFFFFF → 0) on 0 fails
	if m.TryUnreserve(0) {
		t.Error("TryUnreserve on Free slot should return false")
	}

	// Slot 1 is Allocated — TryUnreserve should also fail
	m.TryAllocate(1, 0x0a000001)
	if m.TryUnreserve(1) {
		t.Error("TryUnreserve on Allocated slot should return false")
	}

	// Verify slot 1 still has its original IP
	if ip := m.GetInnerIP(1); ip != 0x0a000001 {
		t.Errorf("slot 1 InnerIP = %#x, want %#x", ip, 0x0a000001)
	}
}

// --- Struct size validation tests ---

func TestStructSize(t *testing.T) {
	tests := []struct {
		name     string
		actual   uintptr
		expected uintptr
	}{
		{"SwitchConfig", unsafe.Sizeof(SwitchConfig{}), 40},
		{"SlotItem", unsafe.Sizeof(SlotItem{}), 108},
		{"MgmtCIDR", unsafe.Sizeof(MgmtCIDR{}), 20},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.actual != tt.expected {
				t.Errorf("%s: got %d bytes, want %d bytes", tt.name, tt.actual, tt.expected)
			}
		})
	}
}

func TestIsSlotFreeOrReserved(t *testing.T) {
	tests := []struct {
		innerIP  uint32
		expected bool
	}{
		{InnerIPFree, true},     // 0 is free
		{InnerIPReserved, true}, // 0xFFFFFFFF is reserved
		{0x0a000001, false},     // Normal IP is not free/reserved
		{1, false},              // Non-zero is not free/reserved
		{0xFFFFFFFE, false},     // Close to reserved but not free/reserved
	}
	for _, tt := range tests {
		if got := IsSlotFreeOrReserved(tt.innerIP); got != tt.expected {
			t.Errorf("IsSlotFreeOrReserved(0x%08x) = %v, want %v", tt.innerIP, got, tt.expected)
		}
	}
}

func TestIsSlotAllocated(t *testing.T) {
	tests := []struct {
		innerIP  uint32
		expected bool
	}{
		{InnerIPFree, false},     // 0 is free, not allocated
		{InnerIPReserved, false}, // 0xFFFFFFFF is reserved, not allocated
		{0x0a000001, true},       // Normal IP is allocated
		{1, true},                // Non-zero non-special is allocated
		{0xFFFFFFFE, true},       // Close to reserved but still allocated
	}
	for _, tt := range tests {
		if got := IsSlotAllocated(tt.innerIP); got != tt.expected {
			t.Errorf("IsSlotAllocated(0x%08x) = %v, want %v", tt.innerIP, got, tt.expected)
		}
	}
}

// --- UpdateSwitchMetadata / GetSwitchMetadata / updateTransitNexthopInConfig ---

// mockBPFMapForMetadata is a mock BPF map for metadata tests.
// It stores raw byte slices for metadata (JSON) and SwitchConfig structs.
type mockBPFMapForMetadata struct {
	data      map[uint32]interface{}
	lookupErr error
	updateErr error
}

func newMockBPFMapForMetadata() *mockBPFMapForMetadata {
	return &mockBPFMapForMetadata{
		data: make(map[uint32]interface{}),
	}
}

func (m *mockBPFMapForMetadata) Lookup(key, valueOut interface{}) error {
	if m.lookupErr != nil {
		return m.lookupErr
	}
	k := key.(uint32)
	if v, ok := m.data[k]; ok {
		switch out := valueOut.(type) {
		case *[]byte:
			if buf, ok := v.([]byte); ok {
				copy(*out, buf)
			}
		case *SwitchConfig:
			*out = v.(SwitchConfig)
		}
	}
	return nil
}

func (m *mockBPFMapForMetadata) Update(key, value interface{}, flags ebpf.MapUpdateFlags) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	k := key.(uint32)
	switch v := value.(type) {
	case []byte:
		buf := make([]byte, len(v))
		copy(buf, v)
		m.data[k] = buf
	case *SwitchConfig:
		m.data[k] = *v
	}
	return nil
}

func (m *mockBPFMapForMetadata) Delete(key interface{}) error {
	return nil
}

func TestUpdateSwitchMetadataSuccess(t *testing.T) {
	mockMap := newMockBPFMapForMetadata()

	cfg := &Config{
		SwitchNetNS:  "test_switch_ns",
		PortNetNS:    "test_port_ns",
		TransitDev:   "eth0",
		MgmtExtracts: []*MgmtExtract{{}, {}}, // 2 mgmt planes
	}

	err := UpdateSwitchMetadata(mockMap, cfg)
	if err != nil {
		t.Fatalf("UpdateSwitchMetadata failed: %v", err)
	}

	// Verify the stored metadata by reading it back
	stored, err := GetSwitchMetadata(mockMap)
	if err != nil {
		t.Fatalf("GetSwitchMetadata failed: %v", err)
	}
	if stored.SwitchNetnsName() != "test_switch_ns" {
		t.Errorf("SwitchNetnsName = %s, want test_switch_ns", stored.SwitchNetnsName())
	}
	if stored.PortNetnsName() != "test_port_ns" {
		t.Errorf("PortNetnsName = %s, want test_port_ns", stored.PortNetnsName())
	}
	if stored.TransitDevName() != "eth0" {
		t.Errorf("TransitDevName = %s, want eth0", stored.TransitDevName())
	}
	if stored.MgmtCount() != 2 {
		t.Errorf("MgmtCount() = %d, want 2", stored.MgmtCount())
	}
}

func TestUpdateSwitchMetadataError(t *testing.T) {
	mockMap := newMockBPFMapForMetadata()
	mockMap.updateErr = errors.New("update failed")

	cfg := &Config{
		SwitchNetNS: "test_ns",
	}

	err := UpdateSwitchMetadata(mockMap, cfg)
	if err == nil {
		t.Fatal("expected error but got nil")
	}
	if !containsSubstring(err.Error(), "failed to update metadata map") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestGetSwitchMetadataSuccess(t *testing.T) {
	mockMap := newMockBPFMapForMetadata()

	// Pre-populate the metadata using SaveMetadata (JSON)
	meta := &SwitchMetadata{
		SwitchNetNS: "my_switch_ns",
		PortNetNS:   "my_port_ns",
		TransitDev:  "br0",
		MgmtExtracts: []MgmtExtractMeta{
			{NetNS: "ns1", Dev: "dev1"},
			{NetNS: "ns2", Dev: "dev2"},
			{NetNS: "ns3", Dev: "dev3"},
		},
	}
	if err := SaveMetadata(mockMap, meta); err != nil {
		t.Fatalf("SaveMetadata failed: %v", err)
	}

	result, err := GetSwitchMetadata(mockMap)
	if err != nil {
		t.Fatalf("GetSwitchMetadata failed: %v", err)
	}

	if result.SwitchNetnsName() != "my_switch_ns" {
		t.Errorf("SwitchNetnsName = %s, want my_switch_ns", result.SwitchNetnsName())
	}
	if result.PortNetnsName() != "my_port_ns" {
		t.Errorf("PortNetnsName = %s, want my_port_ns", result.PortNetnsName())
	}
	if result.TransitDevName() != "br0" {
		t.Errorf("TransitDevName = %s, want br0", result.TransitDevName())
	}
	if result.MgmtCount() != 3 {
		t.Errorf("MgmtCount() = %d, want 3", result.MgmtCount())
	}
}

func TestGetSwitchMetadataError(t *testing.T) {
	mockMap := newMockBPFMapForMetadata()
	mockMap.lookupErr = errors.New("lookup failed")

	_, err := GetSwitchMetadata(mockMap)
	if err == nil {
		t.Fatal("expected error but got nil")
	}
	if !containsSubstring(err.Error(), "failed to read metadata map") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestUpdateSwitchConfigFieldsSuccess(t *testing.T) {
	mockMap := newMockBPFMapForMetadata()

	// Pre-populate with existing config
	var cfg SwitchConfig
	cfg.N_ports = 256
	cfg.FloatingIpBase = 0xc0a80100 // 192.168.1.0
	mockMap.data[0] = cfg

	nexthop := net.ParseIP("10.0.0.1")
	err := updateSwitchConfigFields(mockMap, func(c *SwitchConfig) {
		c.TransitNexthop = bpf.IPToUint32(nexthop)
	})
	if err != nil {
		t.Fatalf("updateSwitchConfigFields failed: %v", err)
	}

	// Verify the updated config
	stored := mockMap.data[0].(SwitchConfig)
	if stored.TransitNexthop != bpf.IPToUint32(nexthop) {
		t.Errorf("TransitNexthop = 0x%x, want 0x%x", stored.TransitNexthop, bpf.IPToUint32(nexthop))
	}
	// Verify other fields are preserved
	if stored.N_ports != 256 {
		t.Errorf("N_ports = %d, want 256", stored.N_ports)
	}
	if stored.FloatingIpBase != 0xc0a80100 {
		t.Errorf("FloatingIpBase = 0x%x, want 0xc0a80100", stored.FloatingIpBase)
	}
}

func TestUpdateSwitchConfigFieldsMultipleFields(t *testing.T) {
	mockMap := newMockBPFMapForMetadata()

	// Pre-populate with existing config
	var cfg SwitchConfig
	cfg.N_ports = 256
	mockMap.data[0] = cfg

	// Update multiple fields at once
	err := updateSwitchConfigFields(mockMap, func(c *SwitchConfig) {
		c.TransitNexthop = 0x0a000001
		c.GeneveEncapEth = 1
	})
	if err != nil {
		t.Fatalf("updateSwitchConfigFields failed: %v", err)
	}

	// Verify the updated config
	stored := mockMap.data[0].(SwitchConfig)
	if stored.TransitNexthop != 0x0a000001 {
		t.Errorf("TransitNexthop = 0x%x, want 0x0a000001", stored.TransitNexthop)
	}
	if stored.GeneveEncapEth != 1 {
		t.Errorf("GeneveEncapEth = %d, want 1", stored.GeneveEncapEth)
	}
	// Verify N_ports is preserved
	if stored.N_ports != 256 {
		t.Errorf("N_ports = %d, want 256", stored.N_ports)
	}
}

func TestUpdateSwitchConfigFieldsLookupError(t *testing.T) {
	mockMap := newMockBPFMapForMetadata()
	mockMap.lookupErr = errors.New("lookup failed")

	err := updateSwitchConfigFields(mockMap, func(c *SwitchConfig) {
		c.TransitNexthop = 0x0a000001
	})
	if err == nil {
		t.Fatal("expected error but got nil")
	}
	if !containsSubstring(err.Error(), "failed to read config") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestUpdateSwitchConfigFieldsUpdateError(t *testing.T) {
	mockMap := newMockBPFMapForMetadata()

	// Pre-populate with existing config so lookup succeeds
	var cfg SwitchConfig
	mockMap.data[0] = cfg
	// Set update error after lookup
	mockMap.updateErr = errors.New("update failed")

	err := updateSwitchConfigFields(mockMap, func(c *SwitchConfig) {
		c.TransitNexthop = 0x0a000001
	})
	if err == nil {
		t.Fatal("expected error but got nil")
	}
	if !containsSubstring(err.Error(), "failed to update config") {
		t.Errorf("unexpected error message: %v", err)
	}
}
