package vswitch

import (
	"os"

	"golang.org/x/sys/unix"

	"github.com/fullof-work/sandbox-vswitch/pkg/dhcp"
	"github.com/fullof-work/sandbox-vswitch/pkg/internal/bpf"
	"github.com/fullof-work/sandbox-vswitch/pkg/internal/bpfmap"
	"github.com/fullof-work/sandbox-vswitch/pkg/netlink"
	"github.com/fullof-work/sandbox-vswitch/pkg/netns"
)

// BPFMap and BPFArrayMap are re-exports of the mocking interfaces defined in
// pkg/internal/bpfmap. They live here as aliases so vswitch tests and
// callers can refer to them without importing the bpfmap path directly.
type (
	BPFMap      = bpfmap.BPFMap
	BPFArrayMap = bpfmap.BPFArrayMap
)

// Function variables for external dependencies.
// These can be replaced with mocks in tests.
var (
	// netns operations
	netnsGetByName   = netns.GetByName
	netnsGetCurrent  = netns.GetCurrent
	netnsMoveDevice  = netns.MoveDevice
	netnsGetLinkInNs = netns.GetLinkInNs
	// netnsDoFn wraps NetNS.Do() for testing - allows mocking namespace switching
	netnsDoFn = func(ns *netns.NetNS, f func() error) error { return ns.Do(f) }

	// bpf operations
	bpfPinPathExists  = bpf.PinPathExists
	bpfLoadObjects    = bpf.LoadObjects
	bpfLoadPinnedMaps = bpf.LoadPinnedMaps
	bpfUnpinMaps      = bpf.UnpinMaps

	// dhcp operations
	dhcpRequest = dhcp.Request

	// internal operations (for testing)
	getSwitchConfigFn            = GetSwitchConfig
	getSwitchMetadataFn          = GetSwitchMetadata
	newMmappedSlotsFn            = NewMmappedSlots
	newStatsManagerFn            = NewStatsManager
	updateSwitchConfigFn         = UpdateSwitchConfig
	updateSwitchMetadataFn       = UpdateSwitchMetadata
	updateSwitchConfigFieldsFn   = updateSwitchConfigFields
	updateSwitchMetadataFieldsFn = updateSwitchMetadataFields
	openSwitchFn                 = openSwitch

	// filesystem operations (for testing)
	osMkdir = os.Mkdir

	// flock operations (for testing)
	acquireControlLockFn = AcquireControlLock

	// bpf.Objects method wrappers (for testing)
	bpfObjectsPinMaps = func(objects *bpf.Objects, name string) error { return objects.PinMaps(name) }
	bpfEnsureBPFFS    = bpf.EnsureBPFFS

	// unix mmap operations (for testing NewMmappedSlots)
	unixMmap   = unix.Mmap
	unixMunmap = unix.Munmap

	// netlink operations (for check* functions)
	netlinkLinkList      = netlink.LinkList
	netlinkLinkByName    = netlink.LinkByName
	netlinkLinkExists    = netlink.LinkExists
	netlinkIsLinkUp      = netlink.IsLinkUp
	netlinkIsLinkAdminUp = netlink.IsLinkAdminUp
	netlinkIsLinkDown    = netlink.IsLinkDown
	netlinkHasTCFilter   = netlink.HasTCFilter

	// netlink operations (for core functions)
	netlinkGetMTUInNs           = netlink.GetMTUInNs
	netlinkSetMTUInNs           = netlink.SetMTUInNs
	netlinkSetMTU               = netlink.SetMTU
	netlinkDeleteVethPairInNs   = netlink.DeleteVethPairInNs
	netlinkDeleteVethPair       = netlink.DeleteVethPair
	netlinkDelLinkByIndex       = netlink.DeleteLinkByIndex
	netlinkDelLinkByIndexInNs   = netlink.DeleteLinkByIndexInNs
	netlinkCreateVethPairs      = netlink.CreateVethPairs
	netlinkCreateVethPair       = netlink.CreateVethPair
	netlinkSetLinkUp            = netlink.SetLinkUp
	netlinkAttachTC             = netlink.AttachTC
	netlinkSetHardwareAddr      = netlink.SetHardwareAddr
	netlinkAddAddr              = netlink.AddAddr
	netlinkAddDefaultRoute      = netlink.AddDefaultRoute
	netlinkAddDeviceRoute       = netlink.AddDeviceRoute
	netlinkGetLinkIndexInNs     = netlink.GetLinkIndexInNs
	netlinkCreateDummyLink      = netlink.CreateDummyLink
	netlinkDeleteLinkByNameInNs = netlink.DeleteLinkByNameInNs
	netlinkAddClsactWithBlock   = netlink.AddClsactWithBlock
	netlinkAddBlockFilter       = netlink.AddBlockFilter
	netlinkHasBlockFilter       = netlink.HasBlockFilter
	netlinkCreateTapInNs        = netlink.CreateTapInNs
	netlinkDeleteTapInNs        = netlink.DeleteTapInNs
)
