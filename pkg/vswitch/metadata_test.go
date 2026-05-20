package vswitch

import (
	"errors"
	"net"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/fullof-work/sandbox-vswitch/pkg/internal/bpf"
)

// mockMetadataMap stores data written via Update and returns it on Lookup.
type mockMetadataMap struct {
	data    []byte
	lookErr error
	updErr  error
}

func (m *mockMetadataMap) Lookup(key, valueOut interface{}) error {
	if m.lookErr != nil {
		return m.lookErr
	}
	buf := valueOut.(*[]byte)
	if m.data != nil {
		copy(*buf, m.data)
	}
	return nil
}

func (m *mockMetadataMap) Update(key, value interface{}, flags ebpf.MapUpdateFlags) error {
	if m.updErr != nil {
		return m.updErr
	}
	m.data = make([]byte, len(value.([]byte)))
	copy(m.data, value.([]byte))
	return nil
}

func (m *mockMetadataMap) Delete(key interface{}) error { return nil }

func TestSaveAndLoadMetadataRoundTrip(t *testing.T) {
	m := &mockMetadataMap{}
	meta := &SwitchMetadata{
		SwitchNetNS:       "sw_ns",
		PortNetNS:         "port_ns",
		TransitDev:        "eth0",
		TransitDevAddr:    "10.0.0.1/24",
		TransitDevNexthop: "10.0.0.254",
		MgmtExtracts: []MgmtExtractMeta{
			{NetNS: "mgmt_ns", Dev: "mgmt0", ServiceRoutes: []string{"192.168.0.0/16"}},
		},
	}

	if err := SaveMetadata(m, meta); err != nil {
		t.Fatalf("SaveMetadata: %v", err)
	}

	loaded, err := LoadMetadata(m)
	if err != nil {
		t.Fatalf("LoadMetadata: %v", err)
	}
	if loaded.SwitchNetNS != "sw_ns" || loaded.TransitDevAddr != "10.0.0.1/24" {
		t.Errorf("round-trip mismatch: %+v", loaded)
	}
	if loaded.TransitDevNexthop != "10.0.0.254" {
		t.Errorf("TransitDevNexthop = %q, want 10.0.0.254", loaded.TransitDevNexthop)
	}
	if len(loaded.MgmtExtracts) != 1 || loaded.MgmtExtracts[0].ServiceRoutes[0] != "192.168.0.0/16" {
		t.Errorf("MgmtExtracts mismatch: %+v", loaded.MgmtExtracts)
	}
}

func TestLoadMetadataEmptyBuffer(t *testing.T) {
	m := &mockMetadataMap{} // no data written, all zeros
	meta, err := LoadMetadata(m)
	if err != nil {
		t.Fatalf("LoadMetadata empty: %v", err)
	}
	if meta.SwitchNetNS != "" {
		t.Errorf("expected empty metadata, got %+v", meta)
	}
}

func TestLoadMetadataUnmarshalError(t *testing.T) {
	m := &mockMetadataMap{}
	// Write invalid JSON
	m.data = make([]byte, bpf.MetadataMaxSize)
	copy(m.data, []byte("{invalid"))

	_, err := LoadMetadata(m)
	if err == nil {
		t.Fatal("expected unmarshal error")
	}
}

func TestLoadMetadataLookupError(t *testing.T) {
	m := &mockMetadataMap{lookErr: errors.New("map read fail")}
	_, err := LoadMetadata(m)
	if err == nil {
		t.Fatal("expected lookup error")
	}
}

func TestSaveMetadataTooLarge(t *testing.T) {
	m := &mockMetadataMap{}
	// Create metadata with a very large field
	meta := &SwitchMetadata{
		SwitchNetNS: string(make([]byte, bpf.MetadataMaxSize+1)),
	}
	err := SaveMetadata(m, meta)
	if err == nil {
		t.Fatal("expected too-large error")
	}
}

func TestSaveMetadataUpdateError(t *testing.T) {
	m := &mockMetadataMap{updErr: errors.New("map write fail")}
	err := SaveMetadata(m, &SwitchMetadata{SwitchNetNS: "ns"})
	if err == nil {
		t.Fatal("expected update error")
	}
}

func TestUpdateSwitchMetadataWithTransit(t *testing.T) {
	m := &mockMetadataMap{}
	_, ipnet, _ := net.ParseCIDR("10.0.0.1/24")
	nexthop := net.ParseIP("10.0.0.254")

	cfg := &Config{
		SwitchNetNS:    "sw_ns",
		PortNetNS:      "port_ns",
		TransitDev:     "eth0",
		TransitAddr:    ipnet,
		TransitNexthop: nexthop,
		MgmtExtracts: []*MgmtExtract{
			{
				NetNS:         "mgmt_ns",
				Dev:           "mgmt0",
				ServiceRoutes: []*net.IPNet{ipnet},
			},
		},
	}

	if err := UpdateSwitchMetadata(m, cfg); err != nil {
		t.Fatalf("UpdateSwitchMetadata: %v", err)
	}

	loaded, err := LoadMetadata(m)
	if err != nil {
		t.Fatalf("LoadMetadata: %v", err)
	}
	if loaded.TransitDevAddr != "10.0.0.0/24" {
		t.Errorf("TransitDevAddr = %q", loaded.TransitDevAddr)
	}
	if loaded.TransitDevNexthop != "10.0.0.254" {
		t.Errorf("TransitDevNexthop = %q", loaded.TransitDevNexthop)
	}
	if len(loaded.MgmtExtracts) != 1 {
		t.Fatalf("expected 1 mgmt extract, got %d", len(loaded.MgmtExtracts))
	}
	if loaded.MgmtExtracts[0].ServiceRoutes[0] != "10.0.0.0/24" {
		t.Errorf("ServiceRoutes[0] = %q", loaded.MgmtExtracts[0].ServiceRoutes[0])
	}
}

func TestUpdateSwitchMetadataFieldsFn(t *testing.T) {
	m := &mockMetadataMap{}
	// First save some data
	if err := SaveMetadata(m, &SwitchMetadata{SwitchNetNS: "ns1"}); err != nil {
		t.Fatalf("initial save: %v", err)
	}

	// Update a field
	err := updateSwitchMetadataFields(m, func(meta *SwitchMetadata) {
		meta.TransitDev = "eth1"
		meta.TransitDevAddr = "192.168.1.1/24"
		meta.TransitDevNexthop = "192.168.1.254"
	})
	if err != nil {
		t.Fatalf("updateSwitchMetadataFields: %v", err)
	}

	loaded, err := LoadMetadata(m)
	if err != nil {
		t.Fatalf("LoadMetadata: %v", err)
	}
	if loaded.SwitchNetNS != "ns1" {
		t.Errorf("SwitchNetNS should be preserved, got %q", loaded.SwitchNetNS)
	}
	if loaded.TransitDev != "eth1" {
		t.Errorf("TransitDev = %q, want eth1", loaded.TransitDev)
	}
}

func TestMetadataAccessors(t *testing.T) {
	meta := &SwitchMetadata{
		SwitchNetNS:       "sw_ns",
		PortNetNS:         "port_ns",
		TransitDev:        "eth0",
		TransitDevAddr:    "10.0.0.1/24",
		TransitDevNexthop: "10.0.0.254",
		MgmtExtracts:      []MgmtExtractMeta{{NetNS: "m"}},
	}
	if meta.SwitchNetnsName() != "sw_ns" {
		t.Errorf("SwitchNetnsName = %q", meta.SwitchNetnsName())
	}
	if meta.PortNetnsName() != "port_ns" {
		t.Errorf("PortNetnsName = %q", meta.PortNetnsName())
	}
	if meta.TransitDevName() != "eth0" {
		t.Errorf("TransitDevName = %q", meta.TransitDevName())
	}
	if meta.TransitDevAddrStr() != "10.0.0.1/24" {
		t.Errorf("TransitDevAddrStr = %q", meta.TransitDevAddrStr())
	}
	if meta.TransitDevNexthopStr() != "10.0.0.254" {
		t.Errorf("TransitDevNexthopStr = %q", meta.TransitDevNexthopStr())
	}
	if meta.MgmtCount() != 1 {
		t.Errorf("MgmtCount = %d", meta.MgmtCount())
	}
}
