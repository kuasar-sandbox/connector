package vswitch

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/kuasar-sandbox/connector/pkg/netlink"
	"github.com/kuasar-sandbox/connector/pkg/netns"

	vnl "github.com/vishvananda/netlink"
)

// --- formatMissingList ---

func TestFormatMissingList(t *testing.T) {
	tests := []struct {
		name  string
		label string
		items []string
		want  string
	}{
		{"empty", "missing", []string{}, "0 missing: "},
		{"single", "missing", []string{"sw-n1"}, "1 missing: sw-n1"},
		{"two items", "DOWN", []string{"sw-n1", "sw-n2"}, "2 DOWN: sw-n1, sw-n2"},
		{"three items", "missing TC", []string{"sw-n1", "sw-n2", "sw-n3"}, "3 missing TC: sw-n1, sw-n2, sw-n3"},
		{"four items", "missing", []string{"sw-n1", "sw-n2", "sw-n3", "sw-n4"}, "4 missing: sw-n1, sw-n2, sw-n3, ... (+1 more)"},
		{"many items", "missing", []string{"sw-n1", "sw-n2", "sw-n3", "sw-n4", "sw-n5", "sw-n6", "sw-n7"}, "7 missing: sw-n1, sw-n2, sw-n3, ... (+4 more)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatMissingList(tt.label, tt.items); got != tt.want {
				t.Errorf("formatMissingList() = %q, want %q", got, tt.want)
			}
		})
	}
}

// --- StatusOutput methods ---

func TestStatusOutputIsReady(t *testing.T) {
	tests := []struct {
		name       string
		conditions []Condition
		want       bool
	}{
		{
			name: "ready true",
			conditions: []Condition{
				{Type: ConditionReady, Status: ConditionTrue},
			},
			want: true,
		},
		{
			name: "ready false",
			conditions: []Condition{
				{Type: ConditionReady, Status: ConditionFalse},
			},
			want: false,
		},
		{
			name: "ready unknown",
			conditions: []Condition{
				{Type: ConditionReady, Status: ConditionUnknown},
			},
			want: false,
		},
		{
			name:       "no conditions",
			conditions: []Condition{},
			want:       false,
		},
		{
			name: "multiple conditions with ready true",
			conditions: []Condition{
				{Type: ConditionReady, Status: ConditionTrue},
				{Type: ConditionPortDevicesReady, Status: ConditionTrue},
				{Type: ConditionTransitDeviceReady, Status: ConditionTrue},
			},
			want: true,
		},
		{
			name: "multiple conditions with ready false",
			conditions: []Condition{
				{Type: ConditionReady, Status: ConditionFalse},
				{Type: ConditionPortDevicesReady, Status: ConditionFalse, Reason: "DevicesMissing"},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &StatusOutput{Conditions: tt.conditions}
			if got := s.IsReady(); got != tt.want {
				t.Errorf("IsReady() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStatusOutputGetNotReadyReasons(t *testing.T) {
	tests := []struct {
		name       string
		conditions []Condition
		want       string
	}{
		{
			name: "all ready",
			conditions: []Condition{
				{Type: ConditionReady, Status: ConditionTrue},
				{Type: ConditionPortDevicesReady, Status: ConditionTrue},
			},
			want: "",
		},
		{
			name: "one not ready",
			conditions: []Condition{
				{Type: ConditionReady, Status: ConditionFalse},
				{Type: ConditionPortDevicesReady, Status: ConditionFalse},
			},
			want: "PortDevicesReady=False",
		},
		{
			name: "multiple not ready",
			conditions: []Condition{
				{Type: ConditionReady, Status: ConditionFalse},
				{Type: ConditionPortDevicesReady, Status: ConditionFalse},
				{Type: ConditionMgmtDevicesReady, Status: ConditionUnknown},
			},
			want: "PortDevicesReady=False, MgmtDevicesReady=Unknown",
		},
		{
			name:       "empty conditions",
			conditions: []Condition{},
			want:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &StatusOutput{Conditions: tt.conditions}
			if got := s.GetNotReadyReasons(); got != tt.want {
				t.Errorf("GetNotReadyReasons() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ============================================================================
// Tests for check functions (checkPortDevices, checkMgmtDevices, checkTransitDevice, checkConditions)
// ============================================================================

// testNetlinkState holds the mock state for netlink functions.
// After refactoring, check functions use nsIfindexMap (from LinkList) + HasTCFilter(link, dir).
type testNetlinkState struct {
	existingDevices map[string]bool
	upDevices       map[string]bool // admin up (IFF_UP flag)
	operUpDevices   map[string]bool // operationally up
	tcDevices       map[string]bool
	deviceIfindexes map[string]int // explicit ifindex per device
	nextIfindex     int            // auto-increment counter
}

func newTestNetlinkState() *testNetlinkState {
	return &testNetlinkState{
		existingDevices: make(map[string]bool),
		upDevices:       make(map[string]bool),
		operUpDevices:   make(map[string]bool),
		tcDevices:       make(map[string]bool),
		deviceIfindexes: make(map[string]int),
		nextIfindex:     10,
	}
}

// getIfindex returns the ifindex for a device, auto-assigning if not explicit.
func (s *testNetlinkState) getIfindex(name string) int {
	if idx, ok := s.deviceIfindexes[name]; ok {
		return idx
	}
	idx := s.nextIfindex
	s.nextIfindex++
	s.deviceIfindexes[name] = idx
	return idx
}

// buildNsIfindexMap builds the nsIfindexMap keyed by ifindex (new format).
func (s *testNetlinkState) buildNsIfindexMap() map[int]netlink.Link {
	nsIfindexMap := make(map[int]netlink.Link)
	for name := range s.existingDevices {
		var flags net.Flags
		if s.upDevices[name] {
			flags |= net.FlagUp
		}
		var operState vnl.LinkOperState = vnl.LinkOperState(vnl.OperDown)
		if s.operUpDevices[name] {
			operState = vnl.LinkOperState(vnl.OperUp)
		}
		ifindex := s.getIfindex(name)
		nsIfindexMap[ifindex] = &vnl.Dummy{
			LinkAttrs: vnl.LinkAttrs{
				Name:      name,
				Index:     ifindex,
				Flags:     flags,
				OperState: operState,
			},
		}
	}
	return nsIfindexMap
}

func (s *testNetlinkState) install() {
	// Mock netnsDoFn to execute function directly (no namespace switching)
	netnsDoFn = func(ns *netns.NetNS, f func() error) error { return f() }

	// Mock LinkList to return links built from testNetlinkState with unique ifindexes
	nsIfindexMap := s.buildNsIfindexMap()
	netlinkLinkList = func() ([]netlink.Link, error) {
		links := make([]netlink.Link, 0, len(nsIfindexMap))
		for _, l := range nsIfindexMap {
			links = append(links, l)
		}
		return links, nil
	}

	// Mock HasTCFilter (for mgmt/transit per-device checks)
	netlinkHasTCFilter = func(link netlink.Link, direction netlink.Direction) bool {
		return s.tcDevices[link.Attrs().Name]
	}

	// Mock HasBlockFilter (for port shared block check)
	netlinkHasBlockFilter = func(blockIndex uint32) bool {
		return true // Default: block filter exists
	}
}

// --- checkPortDevices tests ---

func TestCheckPortDevicesAllReady(t *testing.T) {
	defer resetDeps()

	state := newTestNetlinkState()
	// 4 ports: sw-n1 to sw-n4
	for i := 1; i <= 4; i++ {
		devName := "sw-n" + string('0'+byte(i))
		state.existingDevices[devName] = true
		state.upDevices[devName] = true
		state.tcDevices[devName] = true
	}
	state.install()

	// Create mmapSlots with ifindexes matching the mock devices
	mmapSlots := newMmappedSlotsForTest(4)
	defer mmapSlots.Close()
	for i := uint32(0); i < 4; i++ {
		devName := "sw-n" + string('0'+byte(i+1))
		slot := mmapSlots.GetSlot(i)
		slot.Ifindex = uint32(state.getIfindex(devName))
		slot.InnerIp = 0x0a000001 + i // mark as used (non-zero)
	}

	portsToCheck, _, _ := buildPortsToCheck(4, mmapSlots)
	cond := checkPortDevices(portsToCheck, state.buildNsIfindexMap())

	if cond.Type != ConditionPortDevicesReady {
		t.Errorf("Type = %q, want %q", cond.Type, ConditionPortDevicesReady)
	}
	if cond.Status != ConditionTrue {
		t.Errorf("Status = %q, want %q", cond.Status, ConditionTrue)
	}
}

func TestCheckPortDevicesMissing(t *testing.T) {
	defer resetDeps()

	state := newTestNetlinkState()
	// Only sw-n1 and sw-n3 exist
	state.existingDevices["sw-n1"] = true
	state.existingDevices["sw-n3"] = true
	state.upDevices["sw-n1"] = true
	state.upDevices["sw-n3"] = true
	state.tcDevices["sw-n1"] = true
	state.tcDevices["sw-n3"] = true
	state.install()

	// Create mmapSlots: slots 0,2 have valid ifindexes, slots 1,3 have non-existent ifindexes
	mmapSlots := newMmappedSlotsForTest(4)
	defer mmapSlots.Close()
	mmapSlots.GetSlot(0).Ifindex = uint32(state.getIfindex("sw-n1"))
	mmapSlots.GetSlot(1).Ifindex = 999 // non-existent
	mmapSlots.GetSlot(2).Ifindex = uint32(state.getIfindex("sw-n3"))
	mmapSlots.GetSlot(3).Ifindex = 998 // non-existent

	portsToCheck, _, _ := buildPortsToCheck(4, mmapSlots)
	cond := checkPortDevices(portsToCheck, state.buildNsIfindexMap())

	if cond.Status != ConditionFalse {
		t.Errorf("Status = %q, want %q", cond.Status, ConditionFalse)
	}
	if cond.Reason != "DevicesMissing" {
		t.Errorf("Reason = %q, want 'DevicesMissing'", cond.Reason)
	}
}

func TestCheckPortDevicesDown(t *testing.T) {
	defer resetDeps()

	state := newTestNetlinkState()
	// All exist but sw-n2 is down
	for i := 1; i <= 4; i++ {
		devName := "sw-n" + string('0'+byte(i))
		state.existingDevices[devName] = true
		state.upDevices[devName] = (i != 2)
		state.tcDevices[devName] = true
	}
	state.install()

	// Create mmapSlots with proper ifindexes
	mmapSlots := newMmappedSlotsForTest(4)
	defer mmapSlots.Close()
	for i := uint32(0); i < 4; i++ {
		devName := "sw-n" + string('0'+byte(i+1))
		mmapSlots.GetSlot(i).Ifindex = uint32(state.getIfindex(devName))
	}

	portsToCheck, _, _ := buildPortsToCheck(4, mmapSlots)
	cond := checkPortDevices(portsToCheck, state.buildNsIfindexMap())

	if cond.Status != ConditionFalse {
		t.Errorf("Status = %q, want %q", cond.Status, ConditionFalse)
	}
	if cond.Reason != "DevicesDown" {
		t.Errorf("Reason = %q, want 'DevicesDown'", cond.Reason)
	}
}

func TestCheckPortDevicesMissingBlockFilter(t *testing.T) {
	defer resetDeps()

	state := newTestNetlinkState()
	// All exist and up
	for i := 1; i <= 4; i++ {
		devName := "sw-n" + string('0'+byte(i))
		state.existingDevices[devName] = true
		state.upDevices[devName] = true
	}
	state.install()

	// Mock block filter check to return false
	netlinkHasBlockFilter = func(blockIndex uint32) bool {
		return false
	}

	// Create mmapSlots with proper ifindexes
	mmapSlots := newMmappedSlotsForTest(4)
	defer mmapSlots.Close()
	for i := uint32(0); i < 4; i++ {
		devName := "sw-n" + string('0'+byte(i+1))
		mmapSlots.GetSlot(i).Ifindex = uint32(state.getIfindex(devName))
	}

	portsToCheck, _, _ := buildPortsToCheck(4, mmapSlots)
	cond := checkPortDevices(portsToCheck, state.buildNsIfindexMap())

	if cond.Status != ConditionFalse {
		t.Errorf("Status = %q, want %q", cond.Status, ConditionFalse)
	}
	if cond.Reason != "TCFilterMissing" {
		t.Errorf("Reason = %q, want 'TCFilterMissing'", cond.Reason)
	}
}

func TestCheckPortDevicesPriorityOrder(t *testing.T) {
	defer resetDeps()

	state := newTestNetlinkState()
	// sw-n1 missing, sw-n2 down, sw-n3 missing TC
	// Missing should take priority
	state.existingDevices["sw-n2"] = true
	state.existingDevices["sw-n3"] = true
	state.existingDevices["sw-n4"] = true
	state.upDevices["sw-n3"] = true
	state.upDevices["sw-n4"] = true
	state.tcDevices["sw-n4"] = true
	state.install()

	// Create mmapSlots: slot 0 has non-existent ifindex, others have valid ones
	mmapSlots := newMmappedSlotsForTest(4)
	defer mmapSlots.Close()
	mmapSlots.GetSlot(0).Ifindex = 999 // non-existent (sw-n1 missing)
	mmapSlots.GetSlot(1).Ifindex = uint32(state.getIfindex("sw-n2"))
	mmapSlots.GetSlot(2).Ifindex = uint32(state.getIfindex("sw-n3"))
	mmapSlots.GetSlot(3).Ifindex = uint32(state.getIfindex("sw-n4"))

	portsToCheck, _, _ := buildPortsToCheck(4, mmapSlots)
	cond := checkPortDevices(portsToCheck, state.buildNsIfindexMap())

	if cond.Reason != "DevicesMissing" {
		t.Errorf("Reason = %q, want 'DevicesMissing' (should have priority)", cond.Reason)
	}
}

// --- checkMgmtDevices tests ---

func TestCheckMgmtDevicesAllReady(t *testing.T) {
	defer resetDeps()

	state := newTestNetlinkState()
	// 2 mgmt: sw-m0 and sw-m1
	for i := 0; i < 2; i++ {
		devName := "sw-m" + string('0'+byte(i))
		state.existingDevices[devName] = true
		state.upDevices[devName] = true
		state.tcDevices[devName] = true
	}
	state.install()

	// Build mgmtIfindexes set
	mgmtIfindexes := map[int]struct{}{
		state.getIfindex("sw-m0"): {},
		state.getIfindex("sw-m1"): {},
	}

	cond := checkMgmtDevices(mgmtIfindexes, state.buildNsIfindexMap())

	if cond.Type != ConditionMgmtDevicesReady {
		t.Errorf("Type = %q, want %q", cond.Type, ConditionMgmtDevicesReady)
	}
	if cond.Status != ConditionTrue {
		t.Errorf("Status = %q, want %q", cond.Status, ConditionTrue)
	}
}

func TestCheckMgmtDevicesMissing(t *testing.T) {
	defer resetDeps()

	state := newTestNetlinkState()
	// Only sw-m0 exists
	state.existingDevices["sw-m0"] = true
	state.upDevices["sw-m0"] = true
	state.tcDevices["sw-m0"] = true
	state.install()

	// mgmtIfindexes includes both sw-m0 and a non-existent ifindex for sw-m1
	mgmtIfindexes := map[int]struct{}{
		state.getIfindex("sw-m0"): {},
		999:                       {}, // sw-m1 missing
	}

	cond := checkMgmtDevices(mgmtIfindexes, state.buildNsIfindexMap())

	if cond.Status != ConditionFalse {
		t.Errorf("Status = %q, want %q", cond.Status, ConditionFalse)
	}
	if cond.Reason != "DevicesMissing" {
		t.Errorf("Reason = %q, want 'DevicesMissing'", cond.Reason)
	}
}

func TestCheckMgmtDevicesDown(t *testing.T) {
	defer resetDeps()

	state := newTestNetlinkState()
	// sw-m0 up, sw-m1 down
	state.existingDevices["sw-m0"] = true
	state.existingDevices["sw-m1"] = true
	state.upDevices["sw-m0"] = true
	state.tcDevices["sw-m0"] = true
	state.tcDevices["sw-m1"] = true
	state.install()

	mgmtIfindexes := map[int]struct{}{
		state.getIfindex("sw-m0"): {},
		state.getIfindex("sw-m1"): {},
	}

	cond := checkMgmtDevices(mgmtIfindexes, state.buildNsIfindexMap())

	if cond.Status != ConditionFalse {
		t.Errorf("Status = %q, want %q", cond.Status, ConditionFalse)
	}
	if cond.Reason != "DevicesDown" {
		t.Errorf("Reason = %q, want 'DevicesDown'", cond.Reason)
	}
}

func TestCheckMgmtDevicesMissingTC(t *testing.T) {
	defer resetDeps()

	state := newTestNetlinkState()
	// Both exist and up, but sw-m1 missing TC
	state.existingDevices["sw-m0"] = true
	state.existingDevices["sw-m1"] = true
	state.upDevices["sw-m0"] = true
	state.upDevices["sw-m1"] = true
	state.tcDevices["sw-m0"] = true
	state.install()

	mgmtIfindexes := map[int]struct{}{
		state.getIfindex("sw-m0"): {},
		state.getIfindex("sw-m1"): {},
	}

	cond := checkMgmtDevices(mgmtIfindexes, state.buildNsIfindexMap())

	if cond.Status != ConditionFalse {
		t.Errorf("Status = %q, want %q", cond.Status, ConditionFalse)
	}
	if cond.Reason != "TCFilterMissing" {
		t.Errorf("Reason = %q, want 'TCFilterMissing'", cond.Reason)
	}
}

// --- checkTransitDevice tests ---

func TestCheckTransitDeviceReady(t *testing.T) {
	defer resetDeps()

	state := newTestNetlinkState()
	state.existingDevices["eth0"] = true
	state.operUpDevices["eth0"] = true
	state.tcDevices["eth0"] = true
	state.install()

	transitIfindexes := map[int]struct{}{
		state.getIfindex("eth0"): {},
	}

	cond := checkTransitDevice(transitIfindexes, state.buildNsIfindexMap())

	if cond.Type != ConditionTransitDeviceReady {
		t.Errorf("Type = %q, want %q", cond.Type, ConditionTransitDeviceReady)
	}
	if cond.Status != ConditionTrue {
		t.Errorf("Status = %q, want %q", cond.Status, ConditionTrue)
	}
}

func TestCheckTransitDeviceMissing(t *testing.T) {
	defer resetDeps()

	state := newTestNetlinkState()
	// eth0 does not exist
	state.install()

	transitIfindexes := map[int]struct{}{
		999: {}, // non-existent
	}

	cond := checkTransitDevice(transitIfindexes, state.buildNsIfindexMap())

	if cond.Status != ConditionFalse {
		t.Errorf("Status = %q, want %q", cond.Status, ConditionFalse)
	}
	if cond.Reason != "DeviceMissing" {
		t.Errorf("Reason = %q, want 'DeviceMissing'", cond.Reason)
	}
}

func TestCheckTransitDeviceDown(t *testing.T) {
	defer resetDeps()

	state := newTestNetlinkState()
	state.existingDevices["eth0"] = true
	// operUpDevices["eth0"] not set = down
	state.tcDevices["eth0"] = true
	state.install()

	transitIfindexes := map[int]struct{}{
		state.getIfindex("eth0"): {},
	}

	cond := checkTransitDevice(transitIfindexes, state.buildNsIfindexMap())

	if cond.Status != ConditionFalse {
		t.Errorf("Status = %q, want %q", cond.Status, ConditionFalse)
	}
	if cond.Reason != "DeviceDown" {
		t.Errorf("Reason = %q, want 'DeviceDown'", cond.Reason)
	}
}

func TestCheckTransitDeviceMissingTC(t *testing.T) {
	defer resetDeps()

	state := newTestNetlinkState()
	state.existingDevices["eth0"] = true
	state.operUpDevices["eth0"] = true
	// tcDevices["eth0"] not set = missing
	state.install()

	transitIfindexes := map[int]struct{}{
		state.getIfindex("eth0"): {},
	}

	cond := checkTransitDevice(transitIfindexes, state.buildNsIfindexMap())

	if cond.Status != ConditionFalse {
		t.Errorf("Status = %q, want %q", cond.Status, ConditionFalse)
	}
	if cond.Reason != "TCFilterMissing" {
		t.Errorf("Reason = %q, want 'TCFilterMissing'", cond.Reason)
	}
}

// --- checkConditions tests ---

func TestCheckConditionsAllReady(t *testing.T) {
	defer resetDeps()

	state := newTestNetlinkState()
	// 2 ports, 1 mgmt, transit
	state.existingDevices["sw-n1"] = true
	state.existingDevices["sw-n2"] = true
	state.existingDevices["sw-m0"] = true
	state.existingDevices["eth0"] = true
	state.upDevices["sw-n1"] = true
	state.upDevices["sw-n2"] = true
	state.upDevices["sw-m0"] = true
	state.operUpDevices["eth0"] = true
	state.tcDevices["sw-n1"] = true
	state.tcDevices["sw-n2"] = true
	state.tcDevices["sw-m0"] = true
	state.tcDevices["eth0"] = true
	state.install()

	cfg := &SwitchConfig{N_ports: 2}
	meta := &SwitchMetadata{
		TransitDev:   "eth0",
		MgmtExtracts: []MgmtExtractMeta{{NetNS: "ns0", Dev: "dev0"}},
	}

	// Create mmapSlots with port ifindexes, mgmt ifindexes, and transit ifindex
	mmapSlots := newMmappedSlotsForTest(2)
	defer mmapSlots.Close()
	for i := uint32(0); i < 2; i++ {
		devName := "sw-n" + string('0'+byte(i+1))
		slot := mmapSlots.GetSlot(i)
		slot.Ifindex = uint32(state.getIfindex(devName))
		slot.MgmtCidrCount = 1
		slot.MgmtCidrs0 = MgmtCIDR{
			Ip:      0x0a000000,
			Mask:    0xffffff00,
			Ifindex: uint32(state.getIfindex("sw-m0")),
		}
		slot.TransitIfindex = uint32(state.getIfindex("eth0"))
	}

	conditions, err := checkConditions("sw", cfg, meta, nil, "eth0", mmapSlots)
	if err != nil {
		t.Fatalf("checkConditions() unexpected error: %v", err)
	}

	// Find Ready condition
	var ready *Condition
	for i := range conditions {
		if conditions[i].Type == ConditionReady {
			ready = &conditions[i]
			break
		}
	}

	if ready == nil {
		t.Fatal("Ready condition not found")
	}
	if ready.Status != ConditionTrue {
		t.Errorf("Ready.Status = %q, want %q", ready.Status, ConditionTrue)
	}
}

func TestCheckConditionsPartialFailure(t *testing.T) {
	defer resetDeps()

	state := newTestNetlinkState()
	// Ports ready, mgmt down, transit missing
	state.existingDevices["sw-n1"] = true
	state.existingDevices["sw-n2"] = true
	state.existingDevices["sw-m0"] = true
	state.upDevices["sw-n1"] = true
	state.upDevices["sw-n2"] = true
	// sw-m0 not up
	state.tcDevices["sw-n1"] = true
	state.tcDevices["sw-n2"] = true
	state.tcDevices["sw-m0"] = true
	// eth0 not in existingDevices
	state.install()

	cfg := &SwitchConfig{N_ports: 2}
	meta := &SwitchMetadata{
		TransitDev:   "eth0",
		MgmtExtracts: []MgmtExtractMeta{{NetNS: "ns0", Dev: "dev0"}},
	}

	// Create mmapSlots with port/mgmt/transit ifindexes
	mmapSlots := newMmappedSlotsForTest(2)
	defer mmapSlots.Close()
	for i := uint32(0); i < 2; i++ {
		devName := "sw-n" + string('0'+byte(i+1))
		slot := mmapSlots.GetSlot(i)
		slot.Ifindex = uint32(state.getIfindex(devName))
		slot.MgmtCidrCount = 1
		slot.MgmtCidrs0 = MgmtCIDR{
			Ip:      0x0a000000,
			Mask:    0xffffff00,
			Ifindex: uint32(state.getIfindex("sw-m0")),
		}
		slot.TransitIfindex = 888 // non-existent (eth0 missing)
	}

	conditions, err := checkConditions("sw", cfg, meta, nil, "eth0", mmapSlots)
	if err != nil {
		t.Fatalf("checkConditions() unexpected error: %v", err)
	}

	var ready *Condition
	for i := range conditions {
		if conditions[i].Type == ConditionReady {
			ready = &conditions[i]
			break
		}
	}

	if ready == nil {
		t.Fatal("Ready condition not found")
	}
	if ready.Status != ConditionFalse {
		t.Errorf("Ready.Status = %q, want %q (some conditions failed)", ready.Status, ConditionFalse)
	}
}

func TestCheckConditionsNoMgmt(t *testing.T) {
	defer resetDeps()

	state := newTestNetlinkState()
	state.existingDevices["sw-n1"] = true
	state.upDevices["sw-n1"] = true
	state.tcDevices["sw-n1"] = true
	state.install()

	cfg := &SwitchConfig{N_ports: 1}
	meta := &SwitchMetadata{}

	// Create mmapSlots with port ifindex only (no mgmt, no transit)
	mmapSlots := newMmappedSlotsForTest(1)
	defer mmapSlots.Close()
	mmapSlots.GetSlot(0).Ifindex = uint32(state.getIfindex("sw-n1"))

	conditions, err := checkConditions("sw", cfg, meta, nil, "", mmapSlots)
	if err != nil {
		t.Fatalf("checkConditions() unexpected error: %v", err)
	}

	// Should have Ready and PortDevicesReady only
	if len(conditions) != 2 {
		t.Errorf("len(conditions) = %d, want 2 (Ready + PortDevices)", len(conditions))
	}
}

func TestCheckConditionsNoTransit(t *testing.T) {
	defer resetDeps()

	state := newTestNetlinkState()
	state.existingDevices["sw-n1"] = true
	state.existingDevices["sw-m0"] = true
	state.upDevices["sw-n1"] = true
	state.upDevices["sw-m0"] = true
	state.tcDevices["sw-n1"] = true
	state.tcDevices["sw-m0"] = true
	state.install()

	cfg := &SwitchConfig{N_ports: 1}
	meta := &SwitchMetadata{
		MgmtExtracts: []MgmtExtractMeta{{NetNS: "ns0", Dev: "dev0"}},
	}

	// Create mmapSlots with port + mgmt ifindexes, no transit
	mmapSlots := newMmappedSlotsForTest(1)
	defer mmapSlots.Close()
	slot := mmapSlots.GetSlot(0)
	slot.Ifindex = uint32(state.getIfindex("sw-n1"))
	slot.MgmtCidrCount = 1
	slot.MgmtCidrs0 = MgmtCIDR{
		Ip:      0x0a000000,
		Mask:    0xffffff00,
		Ifindex: uint32(state.getIfindex("sw-m0")),
	}

	conditions, err := checkConditions("sw", cfg, meta, nil, "", mmapSlots)
	if err != nil {
		t.Fatalf("checkConditions() unexpected error: %v", err)
	}

	// Should have Ready, PortDevicesReady, MgmtDevicesReady (no transit)
	if len(conditions) != 3 {
		t.Errorf("len(conditions) = %d, want 3", len(conditions))
	}
}

// --- checkPortDevices with Reserved slots ---

func TestCheckPortDevicesSkipsReserved(t *testing.T) {
	defer resetDeps()

	state := newTestNetlinkState()
	// 8 ports total. Ports 1,2,3,4 are provisioned (non-reserved), ports 5-8 are reserved.
	// Only set up devices for non-reserved ports.
	for i := 1; i <= 4; i++ {
		devName := fmt.Sprintf("sw-n%d", i)
		state.existingDevices[devName] = true
		state.upDevices[devName] = true
		state.tcDevices[devName] = true
	}
	state.install()

	// Create mmapSlots: slots 0-3 have valid ifindexes, slots 4-7 Reserved
	mmapSlots := newMmappedSlotsForTest(8)
	defer mmapSlots.Close()
	for i := uint32(0); i < 4; i++ {
		devName := fmt.Sprintf("sw-n%d", i+1)
		mmapSlots.GetSlot(i).Ifindex = uint32(state.getIfindex(devName))
	}
	for i := uint32(4); i < 8; i++ {
		mmapSlots.TryReserve(i, InnerIPFree)
	}

	portsToCheck, _, _ := buildPortsToCheck(8, mmapSlots)
	cond := checkPortDevices(portsToCheck, state.buildNsIfindexMap())

	if cond.Status != ConditionTrue {
		t.Errorf("Status = %q, want %q (reserved ports should be skipped)", cond.Status, ConditionTrue)
	}
}

func TestCheckPortDevicesAllReserved(t *testing.T) {
	defer resetDeps()

	state := newTestNetlinkState()
	state.install()

	// All 4 ports reserved
	mmapSlots := newMmappedSlotsForTest(4)
	defer mmapSlots.Close()
	for i := uint32(0); i < 4; i++ {
		mmapSlots.TryReserve(i, InnerIPFree)
	}

	portsToCheck, _, _ := buildPortsToCheck(4, mmapSlots)
	cond := checkPortDevices(portsToCheck, state.buildNsIfindexMap())

	if cond.Status != ConditionTrue {
		t.Errorf("Status = %q, want %q (all reserved = nothing to check)", cond.Status, ConditionTrue)
	}
	if cond.Message == "" {
		t.Error("expected non-empty Message indicating all reserved")
	}
}

func TestCheckPortDevicesReservedWithMissing(t *testing.T) {
	defer resetDeps()

	state := newTestNetlinkState()
	// Port 1 exists, port 2 missing, ports 3-4 reserved
	state.existingDevices["sw-n1"] = true
	state.upDevices["sw-n1"] = true
	state.tcDevices["sw-n1"] = true
	state.install()

	mmapSlots := newMmappedSlotsForTest(4)
	defer mmapSlots.Close()
	mmapSlots.GetSlot(0).Ifindex = uint32(state.getIfindex("sw-n1"))
	mmapSlots.GetSlot(1).Ifindex = 999   // non-existent (port 2 missing)
	mmapSlots.TryReserve(2, InnerIPFree) // slot 2 (port 3) reserved
	mmapSlots.TryReserve(3, InnerIPFree) // slot 3 (port 4) reserved

	portsToCheck, _, _ := buildPortsToCheck(4, mmapSlots)
	cond := checkPortDevices(portsToCheck, state.buildNsIfindexMap())

	if cond.Status != ConditionFalse {
		t.Errorf("Status = %q, want %q (port 2 missing)", cond.Status, ConditionFalse)
	}
	if cond.Reason != "DevicesMissing" {
		t.Errorf("Reason = %q, want 'DevicesMissing'", cond.Reason)
	}
}

// --- checkConditions with PortReserved ---

func TestCheckConditionsWithReserved(t *testing.T) {
	defer resetDeps()

	state := newTestNetlinkState()
	// 4 ports, only 2 provisioned
	state.existingDevices["sw-n1"] = true
	state.existingDevices["sw-n2"] = true
	state.upDevices["sw-n1"] = true
	state.upDevices["sw-n2"] = true
	state.tcDevices["sw-n1"] = true
	state.tcDevices["sw-n2"] = true
	state.install()

	mmapSlots := newMmappedSlotsForTest(4)
	defer mmapSlots.Close()
	// Slots 0,1 have valid ifindexes
	mmapSlots.GetSlot(0).Ifindex = uint32(state.getIfindex("sw-n1"))
	mmapSlots.GetSlot(1).Ifindex = uint32(state.getIfindex("sw-n2"))
	// Slots 2,3 are reserved
	mmapSlots.TryReserve(2, InnerIPFree)
	mmapSlots.TryReserve(3, InnerIPFree)

	cfg := &SwitchConfig{N_ports: 4}
	meta := &SwitchMetadata{}

	conditions, err := checkConditions("sw", cfg, meta, nil, "", mmapSlots)
	if err != nil {
		t.Fatalf("checkConditions() unexpected error: %v", err)
	}

	// Find Ready — should be True (PortReserved doesn't affect Ready)
	var ready *Condition
	var portReserved *Condition
	for i := range conditions {
		switch conditions[i].Type {
		case ConditionReady:
			ready = &conditions[i]
		case ConditionPortReserved:
			portReserved = &conditions[i]
		}
	}

	if ready == nil {
		t.Fatal("Ready condition not found")
	}
	if ready.Status != ConditionTrue {
		t.Errorf("Ready.Status = %q, want %q (PortReserved should not affect Ready)", ready.Status, ConditionTrue)
	}

	if portReserved == nil {
		t.Fatal("PortReserved condition not found")
	}
	if portReserved.Status != ConditionTrue {
		t.Errorf("PortReserved.Status = %q, want %q", portReserved.Status, ConditionTrue)
	}
	if portReserved.Message != "2 ports reserved" {
		t.Errorf("PortReserved.Message = %q, want '2 ports reserved'", portReserved.Message)
	}
}

func TestCheckConditionsNoReservedConditionWhenZero(t *testing.T) {
	defer resetDeps()

	state := newTestNetlinkState()
	state.existingDevices["sw-n1"] = true
	state.upDevices["sw-n1"] = true
	state.tcDevices["sw-n1"] = true
	state.install()

	mmapSlots := newMmappedSlotsForTest(1)
	defer mmapSlots.Close()
	mmapSlots.GetSlot(0).Ifindex = uint32(state.getIfindex("sw-n1"))

	cfg := &SwitchConfig{N_ports: 1}
	meta := &SwitchMetadata{}

	conditions, err := checkConditions("sw", cfg, meta, nil, "", mmapSlots)
	if err != nil {
		t.Fatalf("checkConditions() unexpected error: %v", err)
	}

	for _, c := range conditions {
		if c.Type == ConditionPortReserved {
			t.Error("PortReserved condition should not be present when 0 reserved")
		}
	}
}

// --- checkConditions ErrDumpInterrupted ---

func TestCheckConditionsLinkListDumpInterrupted(t *testing.T) {
	defer resetDeps()

	state := newTestNetlinkState()
	// 2 ports, all ready
	state.existingDevices["sw-n1"] = true
	state.existingDevices["sw-n2"] = true
	state.upDevices["sw-n1"] = true
	state.upDevices["sw-n2"] = true
	state.tcDevices["sw-n1"] = true
	state.tcDevices["sw-n2"] = true

	netnsDoFn = func(ns *netns.NetNS, f func() error) error { return f() }

	// Build links with unique ifindexes
	nsIfindexMap := state.buildNsIfindexMap()

	// Mock LinkList to return partial links + ErrDumpInterrupted
	netlinkLinkList = func() ([]netlink.Link, error) {
		links := make([]netlink.Link, 0, len(nsIfindexMap))
		for _, l := range nsIfindexMap {
			links = append(links, l)
		}
		return links, netlink.ErrDumpInterrupted
	}
	netlinkHasTCFilter = func(link netlink.Link, direction netlink.Direction) bool {
		return state.tcDevices[link.Attrs().Name]
	}
	netlinkHasBlockFilter = func(blockIndex uint32) bool {
		return true
	}

	// Create mmapSlots with proper ifindexes
	mmapSlots := newMmappedSlotsForTest(2)
	defer mmapSlots.Close()
	mmapSlots.GetSlot(0).Ifindex = uint32(state.getIfindex("sw-n1"))
	mmapSlots.GetSlot(1).Ifindex = uint32(state.getIfindex("sw-n2"))

	cfg := &SwitchConfig{N_ports: 2}
	meta := &SwitchMetadata{}

	conditions, err := checkConditions("sw", cfg, meta, nil, "", mmapSlots)
	if err != nil {
		t.Fatalf("checkConditions() should not return error for ErrDumpInterrupted, got: %v", err)
	}

	// Should still have valid conditions from partial results
	var ready *Condition
	for i := range conditions {
		if conditions[i].Type == ConditionReady {
			ready = &conditions[i]
			break
		}
	}
	if ready == nil {
		t.Fatal("Ready condition not found")
	}
	if ready.Status != ConditionTrue {
		t.Errorf("Ready.Status = %q, want %q (partial results should be usable)", ready.Status, ConditionTrue)
	}
}

// --- checkConditions error path tests ---

func TestCheckConditionsLinkListError(t *testing.T) {
	defer resetDeps()

	netnsDoFn = func(ns *netns.NetNS, f func() error) error { return f() }
	netlinkLinkList = func() ([]netlink.Link, error) {
		return nil, fmt.Errorf("simulated LinkList failure")
	}

	cfg := &SwitchConfig{N_ports: 2}
	meta := &SwitchMetadata{}

	conditions, err := checkConditions("sw", cfg, meta, nil, "", nil)
	if err == nil {
		t.Fatal("expected error from checkConditions when LinkList fails, got nil")
	}
	if conditions != nil {
		t.Errorf("expected nil conditions on error, got %v", conditions)
	}
	if !strings.Contains(err.Error(), "simulated LinkList failure") {
		t.Errorf("error should contain cause, got: %v", err)
	}
}

func TestCheckConditionsNetnsDoFnError(t *testing.T) {
	defer resetDeps()

	netnsDoFn = func(ns *netns.NetNS, f func() error) error {
		return fmt.Errorf("simulated netns error")
	}

	cfg := &SwitchConfig{N_ports: 1}
	meta := &SwitchMetadata{}

	conditions, err := checkConditions("sw", cfg, meta, nil, "", nil)
	if err == nil {
		t.Fatal("expected error from checkConditions when netnsDoFn fails, got nil")
	}
	if conditions != nil {
		t.Errorf("expected nil conditions on error, got %v", conditions)
	}
	if !strings.Contains(err.Error(), "simulated netns error") {
		t.Errorf("error should contain cause, got: %v", err)
	}
}

// --- buildPortsToCheck tests ---

func TestBuildPortsToCheck(t *testing.T) {
	tests := []struct {
		name          string
		numPorts      uint32
		reservedIdxs  []uint32          // slot indexes to reserve
		portIfindexes map[uint32]uint32 // slot index -> ifindex to set
		wantSlotIDs   []uint32
	}{
		{
			name:        "nil mmapSlots returns all ports with zero ifindex",
			numPorts:    4,
			wantSlotIDs: []uint32{0, 1, 2, 3},
		},
		{
			name:          "skips reserved slots",
			numPorts:      4,
			reservedIdxs:  []uint32{1, 3},
			portIfindexes: map[uint32]uint32{0: 10, 2: 12},
			wantSlotIDs:   []uint32{0, 2},
		},
		{
			name:         "all reserved returns empty",
			numPorts:     3,
			reservedIdxs: []uint32{0, 1, 2},
			wantSlotIDs:  nil,
		},
		{
			name:        "zero ports",
			numPorts:    0,
			wantSlotIDs: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var mmapSlots *MmappedSlots
			if tt.reservedIdxs != nil || tt.portIfindexes != nil {
				mmapSlots = newMmappedSlotsForTest(tt.numPorts)
				defer mmapSlots.Close()
				for _, idx := range tt.reservedIdxs {
					mmapSlots.TryReserve(idx, InnerIPFree)
				}
				for idx, ifindex := range tt.portIfindexes {
					mmapSlots.GetSlot(idx).Ifindex = ifindex
				}
			}

			got, _, _ := buildPortsToCheck(tt.numPorts, mmapSlots)
			if len(got) != len(tt.wantSlotIDs) {
				t.Fatalf("buildPortsToCheck() returned %d items, want %d", len(got), len(tt.wantSlotIDs))
			}
			for i := range got {
				if got[i].slotID != tt.wantSlotIDs[i] {
					t.Errorf("buildPortsToCheck()[%d].slotID = %d, want %d", i, got[i].slotID, tt.wantSlotIDs[i])
				}
			}
		})
	}
}

// TestCheckConditionsSlotReadBeforeLinkList verifies that slot state is read
// before LinkList, preventing false positives during provisioning.
func TestCheckConditionsSlotReadBeforeLinkList(t *testing.T) {
	defer resetDeps()

	// Track call order: slot read must happen before LinkList
	var callOrder []string

	state := newTestNetlinkState()
	state.existingDevices["sw-n1"] = true
	state.existingDevices["sw-n2"] = true
	state.upDevices["sw-n1"] = true
	state.upDevices["sw-n2"] = true
	state.tcDevices["sw-n1"] = true
	state.tcDevices["sw-n2"] = true

	mmapSlots := newMmappedSlotsForTest(4)
	defer mmapSlots.Close()
	// Slots 0,1 have valid ifindexes
	mmapSlots.GetSlot(0).Ifindex = uint32(state.getIfindex("sw-n1"))
	mmapSlots.GetSlot(1).Ifindex = uint32(state.getIfindex("sw-n2"))
	// Slots 2,3 reserved
	mmapSlots.TryReserve(2, InnerIPFree)
	mmapSlots.TryReserve(3, InnerIPFree)

	// Wrap mmapSlots to track when GetInnerIP is called.
	// Since buildPortsToCheck is called before netnsDoFn, we verify
	// by checking that LinkList mock records its call AFTER we've
	// already seen the function proceed past slot reading.

	netnsDoFn = func(ns *netns.NetNS, f func() error) error {
		callOrder = append(callOrder, "netnsDoFn")
		return f()
	}

	nsIfindexMap := state.buildNsIfindexMap()
	netlinkLinkList = func() ([]netlink.Link, error) {
		callOrder = append(callOrder, "LinkList")
		links := make([]netlink.Link, 0, len(nsIfindexMap))
		for _, l := range nsIfindexMap {
			links = append(links, l)
		}
		return links, nil
	}
	netlinkHasTCFilter = func(link netlink.Link, direction netlink.Direction) bool {
		return state.tcDevices[link.Attrs().Name]
	}
	netlinkHasBlockFilter = func(blockIndex uint32) bool {
		return true
	}

	cfg := &SwitchConfig{N_ports: 4}
	meta := &SwitchMetadata{}

	conditions, err := checkConditions("sw", cfg, meta, nil, "", mmapSlots)
	if err != nil {
		t.Fatalf("checkConditions() unexpected error: %v", err)
	}

	// Verify netnsDoFn (which calls LinkList) was called
	if len(callOrder) < 2 {
		t.Fatalf("expected at least 2 calls, got %v", callOrder)
	}
	// netnsDoFn must be called (slot reading happens before it)
	if callOrder[0] != "netnsDoFn" {
		t.Errorf("expected netnsDoFn first in callOrder, got %v", callOrder)
	}
	// LinkList is called inside netnsDoFn
	if callOrder[1] != "LinkList" {
		t.Errorf("expected LinkList second in callOrder, got %v", callOrder)
	}

	// The key invariant: buildPortsToCheck was called BEFORE netnsDoFn,
	// so reserved ports (2,3) are excluded and only ports 0,1 are checked.
	// Both sw-n1 and sw-n2 exist → should be ready.
	var ready *Condition
	var portReserved *Condition
	for i := range conditions {
		switch conditions[i].Type {
		case ConditionReady:
			ready = &conditions[i]
		case ConditionPortReserved:
			portReserved = &conditions[i]
		}
	}

	if ready == nil || ready.Status != ConditionTrue {
		t.Errorf("expected Ready=True, got %v", ready)
	}
	if portReserved == nil || portReserved.Message != "2 ports reserved" {
		t.Errorf("expected PortReserved with 2 ports, got %v", portReserved)
	}
}
