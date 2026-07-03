package vswitch

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/cilium/ebpf"

	"github.com/kuasar-sandbox/connector/pkg/internal/bpf"
)

// SwitchMetadata is the JSON metadata stored in the BPF metadata map.
// Using JSON (rather than a fixed C struct) allows flexible schema evolution.
type SwitchMetadata struct {
	Version           int               `json:"version,omitempty"`
	SwitchNetNS       string            `json:"switch_netns"`
	PortNetNS         string            `json:"port_netns"`
	TransitDev        string            `json:"transit_dev,omitempty"`
	TransitDevAddr    string            `json:"transit_dev_addr,omitempty"`
	TransitDevNexthop string            `json:"transit_dev_nexthop,omitempty"`
	MgmtExtracts      []MgmtExtractMeta `json:"mgmt_extracts,omitempty"`
	MgmtServices      []string          `json:"mgmt_services,omitempty"`
}

// MgmtExtractMeta holds metadata about a management extraction.
type MgmtExtractMeta struct {
	NetNS         string   `json:"netns"`
	Dev           string   `json:"dev"`
	ServiceRoutes []string `json:"service_routes"`
}

// Accessor methods for backward compatibility.

// SwitchNetnsName returns the switch namespace name.
func (m *SwitchMetadata) SwitchNetnsName() string { return m.SwitchNetNS }

// PortNetnsName returns the port namespace name.
func (m *SwitchMetadata) PortNetnsName() string { return m.PortNetNS }

// TransitDevName returns the transit device name.
func (m *SwitchMetadata) TransitDevName() string { return m.TransitDev }

// TransitDevAddrStr returns the transit device address (CIDR format, e.g. "192.168.1.2/24").
func (m *SwitchMetadata) TransitDevAddrStr() string { return m.TransitDevAddr }

// TransitDevNexthopStr returns the transit device nexthop IP.
func (m *SwitchMetadata) TransitDevNexthopStr() string { return m.TransitDevNexthop }

// MgmtCount returns the number of management extractions.
func (m *SwitchMetadata) MgmtCount() int { return len(m.MgmtExtracts) }

// MgmtPlaneInfos reconstructs the management plane list for output from the
// stored metadata. The return-route metric is derived the same way it is
// installed at start time (100 + index).
func (m *SwitchMetadata) MgmtPlaneInfos() []MgmtPlaneInfo {
	if m == nil || len(m.MgmtExtracts) == 0 {
		return nil
	}
	out := make([]MgmtPlaneInfo, 0, len(m.MgmtExtracts))
	for i, me := range m.MgmtExtracts {
		out = append(out, MgmtPlaneInfo{
			Index:             i,
			MgmtNetNS:         me.NetNS,
			MgmtDev:           me.Dev,
			ServiceRoutes:     me.ServiceRoutes,
			ReturnRouteMetric: 100 + i,
		})
	}
	return out
}

// MgmtServiceInfos returns the management service translations for output.
func (m *SwitchMetadata) MgmtServiceInfos() []MgmtServiceInfo {
	if m == nil {
		return nil
	}
	return MgmtServiceInfosFromStrings(m.MgmtServices)
}

// SaveMetadata serializes metadata as JSON and writes it to the BPF metadata map.
func SaveMetadata(metadataMap BPFMap, meta *SwitchMetadata) error {
	data, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}
	if len(data) > bpf.MetadataMaxSize {
		return fmt.Errorf("metadata too large: %d bytes exceeds max %d", len(data), bpf.MetadataMaxSize)
	}
	if meta.Version == 0 {
		meta.Version = 1
	}
	buf := make([]byte, bpf.MetadataMaxSize)
	copy(buf, data)
	key := uint32(0)
	if err := metadataMap.Update(key, buf, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update metadata map: %w", err)
	}
	return nil
}

// LoadMetadata reads JSON metadata from the BPF metadata map.
func LoadMetadata(metadataMap BPFMap) (*SwitchMetadata, error) {
	buf := make([]byte, bpf.MetadataMaxSize)
	key := uint32(0)
	if err := metadataMap.Lookup(key, &buf); err != nil {
		return nil, fmt.Errorf("failed to read metadata map: %w", err)
	}
	// Trim trailing null bytes
	trimmed := bytes.TrimRight(buf, "\x00")
	if len(trimmed) == 0 {
		return &SwitchMetadata{}, nil
	}
	var meta SwitchMetadata
	if err := json.Unmarshal(trimmed, &meta); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}
	return &meta, nil
}

// UpdateSwitchMetadata writes metadata from Config to the BPF map (JSON format).
func UpdateSwitchMetadata(metadataMap BPFMap, cfg *Config) error {
	meta := &SwitchMetadata{
		SwitchNetNS: cfg.SwitchNetNS,
		PortNetNS:   cfg.PortNetNS,
		TransitDev:  cfg.TransitDev,
	}
	if cfg.TransitAddr != nil {
		meta.TransitDevAddr = cfg.TransitAddr.String()
	}
	if cfg.TransitNexthop != nil {
		meta.TransitDevNexthop = cfg.TransitNexthop.String()
	}
	for _, me := range cfg.MgmtExtracts {
		routes := make([]string, len(me.ServiceRoutes))
		for i, r := range me.ServiceRoutes {
			routes[i] = r.String()
		}
		meta.MgmtExtracts = append(meta.MgmtExtracts, MgmtExtractMeta{
			NetNS:         me.NetNS,
			Dev:           me.Dev,
			ServiceRoutes: routes,
		})
	}
	for _, svc := range cfg.MgmtServices {
		meta.MgmtServices = append(meta.MgmtServices, svc.String())
	}
	return SaveMetadata(metadataMap, meta)
}

// updateSwitchMetadataFields reads current metadata, applies the update function, and writes back.
func updateSwitchMetadataFields(metadataMap BPFMap, update func(*SwitchMetadata)) error {
	meta, err := LoadMetadata(metadataMap)
	if err != nil {
		return err
	}
	update(meta)
	return SaveMetadata(metadataMap, meta)
}

// GetSwitchMetadata reads metadata from the BPF map (JSON format).
func GetSwitchMetadata(metadataMap BPFMap) (*SwitchMetadata, error) {
	return LoadMetadata(metadataMap)
}
