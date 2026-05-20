package vswitch

import (
	"testing"
)

func TestPortsAllocatedOnly(t *testing.T) {
	// Setup mmapSlots with some allocated slots
	mmapSlots := newMmappedSlotsForTest(4)
	defer mmapSlots.Close()

	// Allocate slots 0 and 2
	mmapSlots.TryAllocate(0, 0x0a000001)
	mmapSlots.TryAllocate(2, 0x0a000003)

	ctx := &switchContext{
		cfg:       &SwitchConfig{N_ports: 4},
		mmapSlots: mmapSlots,
	}

	// Test Ports(true) returns only allocated
	ports := ctx.Ports(true)
	if len(ports) != 2 {
		t.Fatalf("Ports(true) returned %d ports, want 2", len(ports))
	}

	// Verify port numbers (1-based)
	if ports[0].Port != 1 {
		t.Errorf("ports[0].Port = %d, want 1", ports[0].Port)
	}
	if ports[1].Port != 3 {
		t.Errorf("ports[1].Port = %d, want 3", ports[1].Port)
	}

	// Verify allocated flag
	if !ports[0].Allocated {
		t.Error("ports[0].Allocated should be true")
	}
	if !ports[1].Allocated {
		t.Error("ports[1].Allocated should be true")
	}

	// Verify InnerIP values
	if ports[0].InnerIp != 0x0a000001 {
		t.Errorf("ports[0].InnerIp = %#x, want %#x", ports[0].InnerIp, 0x0a000001)
	}
	if ports[1].InnerIp != 0x0a000003 {
		t.Errorf("ports[1].InnerIp = %#x, want %#x", ports[1].InnerIp, 0x0a000003)
	}
}

func TestPortsAll(t *testing.T) {
	// Setup mmapSlots with some allocated slots
	mmapSlots := newMmappedSlotsForTest(4)
	defer mmapSlots.Close()

	// Allocate slots 0 and 2
	mmapSlots.TryAllocate(0, 0x0a000001)
	mmapSlots.TryAllocate(2, 0x0a000003)

	ctx := &switchContext{
		cfg:       &SwitchConfig{N_ports: 4},
		mmapSlots: mmapSlots,
	}

	// Test Ports(false) returns all slots
	ports := ctx.Ports(false)
	if len(ports) != 4 {
		t.Fatalf("Ports(false) returned %d ports, want 4", len(ports))
	}

	// Verify port numbers (1-based)
	for i, port := range ports {
		expectedPort := i + 1
		if port.Port != expectedPort {
			t.Errorf("ports[%d].Port = %d, want %d", i, port.Port, expectedPort)
		}
	}

	// Verify allocated flags
	if !ports[0].Allocated {
		t.Error("ports[0].Allocated should be true")
	}
	if ports[1].Allocated {
		t.Error("ports[1].Allocated should be false")
	}
	if !ports[2].Allocated {
		t.Error("ports[2].Allocated should be true")
	}
	if ports[3].Allocated {
		t.Error("ports[3].Allocated should be false")
	}
}

func TestPortsEmpty(t *testing.T) {
	mmapSlots := newMmappedSlotsForTest(4)
	defer mmapSlots.Close()

	ctx := &switchContext{
		cfg:       &SwitchConfig{N_ports: 4},
		mmapSlots: mmapSlots,
	}

	// No allocations - Ports(true) should return empty
	ports := ctx.Ports(true)
	if len(ports) != 0 {
		t.Errorf("Ports(true) on empty slots returned %d ports, want 0", len(ports))
	}

	// Ports(false) should return all 4 ports
	allPorts := ctx.Ports(false)
	if len(allPorts) != 4 {
		t.Errorf("Ports(false) on empty slots returned %d ports, want 4", len(allPorts))
	}

	// All should be unallocated
	for i, port := range allPorts {
		if port.Allocated {
			t.Errorf("ports[%d].Allocated should be false", i)
		}
	}
}

func TestPortsAllAllocated(t *testing.T) {
	mmapSlots := newMmappedSlotsForTest(4)
	defer mmapSlots.Close()

	// Allocate all slots
	for i := uint32(0); i < 4; i++ {
		mmapSlots.TryAllocate(i, 0x0a000001+i)
	}

	ctx := &switchContext{
		cfg:       &SwitchConfig{N_ports: 4},
		mmapSlots: mmapSlots,
	}

	// Both should return 4 ports
	allocatedPorts := ctx.Ports(true)
	if len(allocatedPorts) != 4 {
		t.Errorf("Ports(true) returned %d ports, want 4", len(allocatedPorts))
	}

	allPorts := ctx.Ports(false)
	if len(allPorts) != 4 {
		t.Errorf("Ports(false) returned %d ports, want 4", len(allPorts))
	}

	// All should be allocated
	for i, port := range allocatedPorts {
		if !port.Allocated {
			t.Errorf("allocatedPorts[%d].Allocated should be true", i)
		}
	}
}

func TestPortsSlotItemFields(t *testing.T) {
	mmapSlots := newMmappedSlotsForTest(2)
	defer mmapSlots.Close()

	// Allocate and set additional fields
	mmapSlots.TryAllocate(0, 0x0a000001)
	mmapSlots.UpdateSlotFields(0, func(slot *SlotItem) {
		slot.Ifindex = 123
		slot.TransitGatewayIp = 0xc0a80001
	})

	ctx := &switchContext{
		cfg:       &SwitchConfig{N_ports: 2},
		mmapSlots: mmapSlots,
	}

	ports := ctx.Ports(true)
	if len(ports) != 1 {
		t.Fatalf("Ports(true) returned %d ports, want 1", len(ports))
	}

	// Verify embedded SlotItem fields are accessible
	if ports[0].Ifindex != 123 {
		t.Errorf("ports[0].Ifindex = %d, want 123", ports[0].Ifindex)
	}
	if ports[0].TransitGatewayIp != 0xc0a80001 {
		t.Errorf("ports[0].TransitGatewayIp = %#x, want %#x", ports[0].TransitGatewayIp, 0xc0a80001)
	}
}
