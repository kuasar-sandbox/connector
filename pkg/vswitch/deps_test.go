package vswitch

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/kuasar-sandbox/connector/pkg/dhcp"
	"github.com/kuasar-sandbox/connector/pkg/internal/bpf"
	"github.com/kuasar-sandbox/connector/pkg/netlink"
	"github.com/kuasar-sandbox/connector/pkg/netns"
)

// resetDeps resets all function variables to their original implementations.
// This should be called in test cleanup to avoid affecting other tests.
func resetDeps() {
	netnsGetByName = netns.GetByName
	netnsGetCurrent = netns.GetCurrent
	netnsMoveDevice = netns.MoveDevice
	netnsGetLinkInNs = netns.GetLinkInNs
	netnsDoFn = func(ns *netns.NetNS, f func() error) error { return ns.Do(f) }

	bpfPinPathExists = bpf.PinPathExists
	bpfLoadObjects = bpf.LoadObjects
	bpfLoadPinnedMaps = bpf.LoadPinnedMaps
	bpfUnpinMaps = bpf.UnpinMaps

	dhcpRequest = dhcp.Request

	getSwitchConfigFn = GetSwitchConfig
	getSwitchMetadataFn = GetSwitchMetadata
	newMmappedSlotsFn = NewMmappedSlots
	newStatsManagerFn = NewStatsManager
	updateSwitchConfigFn = UpdateSwitchConfig
	updateSwitchMetadataFn = UpdateSwitchMetadata
	writeGeneveOptsFn = writeGeneveOpts
	validateAttachMTUFn = validateAttachMTU
	updateSwitchConfigFieldsFn = updateSwitchConfigFields
	updateSwitchMetadataFieldsFn = updateSwitchMetadataFields
	openSwitchFn = openSwitch
	bpfObjectsPinMaps = func(objects *bpf.Objects, name string) error { return objects.PinMaps(name) }
	bpfEnsureBPFFS = bpf.EnsureBPFFS
	acquireControlLockFn = AcquireControlLock
	verifyCurrentSwitchFn = verifyCurrentSwitch

	unixMmap = unix.Mmap
	unixMunmap = unix.Munmap

	osMkdir = os.Mkdir
	osOpen = os.Open
	syscallFlock = syscall.Flock

	netlinkLinkList = netlink.LinkList
	netlinkLinkByName = netlink.LinkByName
	netlinkLinkExists = netlink.LinkExists
	netlinkIsLinkUp = netlink.IsLinkUp
	netlinkIsLinkAdminUp = netlink.IsLinkAdminUp
	netlinkIsLinkDown = netlink.IsLinkDown
	netlinkHasTCFilter = netlink.HasTCFilter

	netlinkGetMTUInNs = netlink.GetMTUInNs
	netlinkSetMTUInNs = netlink.SetMTUInNs
	netlinkSetMTU = netlink.SetMTU
	netlinkDeleteVethPairInNs = netlink.DeleteVethPairInNs
	netlinkDeleteVethPair = netlink.DeleteVethPair
	netlinkDelLinkByIndex = netlink.DeleteLinkByIndex
	netlinkDelLinkByIndexInNs = netlink.DeleteLinkByIndexInNs
	netlinkCreateVethPairs = netlink.CreateVethPairs
	netlinkCreateVethPair = netlink.CreateVethPair
	netlinkSetLinkUp = netlink.SetLinkUp
	netlinkAttachTC = netlink.AttachTC
	netlinkSetHardwareAddr = netlink.SetHardwareAddr
	netlinkAddAddr = netlink.AddAddr
	netlinkAddDefaultRoute = netlink.AddDefaultRoute
	netlinkAddDeviceRoute = netlink.AddDeviceRoute
	netlinkGetLinkIndexInNs = netlink.GetLinkIndexInNs
	netlinkCreateDummyLink = netlink.CreateDummyLink
	netlinkDeleteLinkByNameInNs = netlink.DeleteLinkByNameInNs
	netlinkAddClsactWithBlock = netlink.AddClsactWithBlock
	netlinkAddBlockFilter = netlink.AddBlockFilter
	netlinkHasBlockFilter = netlink.HasBlockFilter
}
