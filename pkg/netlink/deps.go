package netlink

import (
	"github.com/vishvananda/netlink"
)

// NetNS is an interface for network namespace operations.
// This allows mocking in tests.
type NetNS interface {
	Do(f func() error) error
}

// BPFProgram is an interface for eBPF program operations.
// This allows mocking in tests.
type BPFProgram interface {
	FD() int
	String() string
}

// Link is re-exported from vishvananda/netlink for use by consumers.
type Link = netlink.Link

// OperUp is the operationally-up link state, re-exported for consumers.
const OperUp = netlink.OperUp

// Function variables for netlink operations, can be replaced with mocks in tests.
var (
	// Link operations
	netlinkLinkByName          = netlink.LinkByName
	netlinkLinkList            = netlink.LinkList
	netlinkLinkByIndex         = netlink.LinkByIndex
	netlinkLinkAdd             = netlink.LinkAdd
	netlinkLinkDel             = netlink.LinkDel
	netlinkLinkSetUp           = netlink.LinkSetUp
	netlinkLinkSetHardwareAddr = netlink.LinkSetHardwareAddr
	netlinkLinkSetNsFd         = netlink.LinkSetNsFd
	netlinkLinkSetMTU          = netlink.LinkSetMTU

	// Address operations
	netlinkAddrAdd  = netlink.AddrAdd
	netlinkAddrList = netlink.AddrList

	// Route operations
	netlinkRouteAdd = netlink.RouteAdd

	// Qdisc operations
	netlinkQdiscList = netlink.QdiscList
	netlinkQdiscAdd  = netlink.QdiscAdd
	netlinkQdiscDel  = netlink.QdiscDel

	// Filter operations
	netlinkFilterList = netlink.FilterList
	netlinkFilterAdd  = netlink.FilterAdd
	netlinkFilterDel  = netlink.FilterDel
)
