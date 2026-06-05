package vswitch

import (
	"net"

	"github.com/kuasar-sandbox/sandbox-vswitch/pkg/internal/bpf"
)

// Interface is the interface for operating on an opened virtual switch.
// Use Open() to obtain an instance.
type Interface interface {
	// Name returns the switch name.
	Name() string
	// Config returns the switch configuration.
	Config() *SwitchConfig
	// Metadata returns the switch metadata (userspace-only fields).
	Metadata() *SwitchMetadata
	// Maps returns the underlying BPF maps.
	Maps() *bpf.Maps
	// MmapSlots returns the mmapped slots for direct access.
	MmapSlots() *MmappedSlots
	// Close releases handle resources (maps, mmap).
	// The switch remains running.
	Close() error

	// Attach allocates a port to a sandbox.
	Attach(opts AttachOptions) (*AttachOutput, error)
	// Reserve reserves a port slot.
	Reserve(opts ReserveOptions) (*ReserveOutput, error)
	// Detach releases a port from a sandbox.
	Detach(opts DetachOptions) error
	// Status returns the switch status.
	Status() (*StatusOutput, error)
	// Stats returns port statistics.
	Stats(ports []int) (*StatsOutput, error)

	// Ports returns port slot information.
	// If allocatedOnly is true, returns only allocated ports.
	Ports(allocatedOnly bool) []PortSlot
}

// DetachOptions holds options for the detach command.
type DetachOptions struct {
	Port       int    // Port number to detach
	FromNetNS  string // Source namespace (where the device currently is)
	SkipDevice bool   // Skip device movement/checks (pure BPF slot operation)
}

// AttachOptions holds options for the attach command.
type AttachOptions struct {
	Port             int              // Requested port number (0 for auto)
	ToNetNS          string           // Target namespace
	InnerIP          net.IP           // Sandbox internal IP
	TransitGatewayIP net.IP           // GENEVE gateway IP
	TransitGeneveVNI uint32           // GENEVE VNI
	TransitMAC       net.HardwareAddr // Transit destination MAC (nil for broadcast)
	SkipDevice       bool             // --skip-device: pure BPF slot operation, skip all device movement/checks
}

// ReserveOptions holds options for the reserve command.
type ReserveOptions struct {
	Port  int  // Port number to reserve (required)
	Force bool // Force-reserve: overwrite any state
}

// AttachOutput represents the JSON output of the attach command.
type AttachOutput struct {
	Port             uint32 `json:"port"`
	PortDev          string `json:"port_dev"`
	PortNetNS        string `json:"port_netns"`
	PortMAC          string `json:"port_mac"`
	InnerIP          string `json:"inner_ip"`
	FloatingIP       string `json:"floating_ip"`
	Mode             string `json:"mode"` // "veth" or "tap"
	TransitType      string `json:"transit_type"`
	TransitGatewayIP string `json:"transit_gateway_ip,omitempty"`
	GenevePort       uint16 `json:"geneve_port,omitempty"`
	TransitGeneveVNI uint32 `json:"transit_geneve_vni,omitempty"`
	// TapSentTo is populated when attach was invoked with --open-port; it
	// echoes the TAPFD_SOCKET destination that received the fd via SCM_RIGHTS.
	TapSentTo string `json:"tap_sent_to,omitempty"`
	// TapNetnsSent is true when the tap's netns fd was also delivered alongside
	// the tap fd (requested via TAPFD_WANT_NETNS).
	TapNetnsSent bool `json:"tap_netns_sent,omitempty"`
}

// StatusOutput represents the JSON output of the status command.
type StatusOutput struct {
	Switch         string          `json:"switch"`
	State          string          `json:"state"`
	SwitchNetNS    string          `json:"switch_netns"`
	PortNetNS      string          `json:"port_netns"`
	Ports          uint32          `json:"ports"`
	PortsUsed      uint32          `json:"ports_used"`
	PortsAvailable uint32          `json:"ports_available"`
	PortsReserved  uint32          `json:"ports_reserved"`
	MgmtPlanes     []MgmtPlaneInfo `json:"mgmt_planes,omitempty"`
	TransitDev     string          `json:"transit_dev,omitempty"`
	TransitDevIP   string          `json:"transit_dev_ip,omitempty"`
	Conditions     []Condition     `json:"conditions,omitempty"`
}

// Condition represents a health check condition (Kubernetes-style).
type Condition struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

// PortIngressBlockID is the TC shared block index used for port ingress filters.
const PortIngressBlockID uint32 = 100

// PortLinkGroup is the link group assigned to port veth devices in the switch namespace.
// Used for batch deletion via RTM_DELLINK + IFLA_GROUP (kernel rtnl_group_dellink).
// Each switch has its own network namespace, so a fixed group value is safe.
const PortLinkGroup uint32 = 100

// MgmtLinkGroup is the link group assigned to mgmt veth devices in the switch namespace.
// Used for batch deletion via RTM_DELLINK + IFLA_GROUP, same as PortLinkGroup but with
// a different group value to allow independent batch deletion.
const MgmtLinkGroup uint32 = 101

// Condition status values
const (
	ConditionTrue    = "True"
	ConditionFalse   = "False"
	ConditionUnknown = "Unknown"
)

// Condition type constants
const (
	ConditionReady              = "Ready"
	ConditionPortDevicesReady   = "PortDevicesReady"
	ConditionMgmtDevicesReady   = "MgmtDevicesReady"
	ConditionTransitDeviceReady = "TransitDeviceReady"
	ConditionPortReserved       = "PortReserved"
)

// PortStatsOutput represents per-port traffic statistics.
type PortStatsOutput struct {
	Port             uint32 `json:"port"`
	InnerIP          string `json:"inner_ip"`
	FloatingIP       string `json:"floating_ip"`
	PortMAC          string `json:"port_mac"`
	MgmtRxPackets    uint64 `json:"mgmt_rx_packets"`
	MgmtRxBytes      uint64 `json:"mgmt_rx_bytes"`
	MgmtTxPackets    uint64 `json:"mgmt_tx_packets"`
	MgmtTxBytes      uint64 `json:"mgmt_tx_bytes"`
	TransitRxPackets uint64 `json:"transit_rx_packets"`
	TransitRxBytes   uint64 `json:"transit_rx_bytes"`
	TransitTxPackets uint64 `json:"transit_tx_packets"`
	TransitTxBytes   uint64 `json:"transit_tx_bytes"`
}

// StatsOutput represents the JSON output of the stats command.
type StatsOutput struct {
	Switch string            `json:"switch"`
	Ports  []PortStatsOutput `json:"ports"`
}

// PortSlot wraps SlotItem with port metadata.
type PortSlot struct {
	SlotItem       // Embedded
	Port      int  // 1-based port number
	Allocated bool // true if slot is allocated (not Free, not Reserved)
}

// ReleaseOptions controls how ReleasePorts behaves.
type ReleaseOptions struct {
	Force bool // true: release all ports including Allocated; false: safe mode
}

// ReleaseOutput represents the result of a release operation.
type ReleaseOutput struct {
	Released  int `json:"released"`  // Number of port devices deleted
	Total     int `json:"total"`     // Total number of ports
	Remaining int `json:"remaining"` // Ports still with devices (ifindex != 0)
}

// ProvisionOptions holds options for the provision command.
type ProvisionOptions struct {
	Count int      // Create N ports (0 for all Reserved ports)
	Port  int      // Create specific port (mutually exclusive with Count)
	Mode  PortKind // Device kind to provision (PortKindVeth default, PortKindTap for tap)
}

// ProvisionOutput represents the result of a provision operation.
type ProvisionOutput struct {
	Provisioned int `json:"provisioned"` // Number of ports successfully provisioned
	Total       int `json:"total"`       // Total number of ports
	Available   int `json:"available"`   // Currently available (Free) ports
}

// ReserveOutput represents the result of a reserve operation.
type ReserveOutput struct {
	Port   uint32 `json:"port"`
	Status string `json:"status"` // "reserved" or "already_reserved"
}

// MgmtPlaneInfo represents management plane information.
type MgmtPlaneInfo struct {
	Index             int      `json:"index"`
	MgmtNetNS         string   `json:"mgmt_netns"`
	MgmtDev           string   `json:"mgmt_dev"`
	ServiceRoutes     []string `json:"service_routes"`
	ReturnRouteMetric int      `json:"return_route_metric"`
}
