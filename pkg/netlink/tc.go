package netlink

import (
	"errors"
	"fmt"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

const (
	// TC filter priority for our programs
	TCFilterPriority = 1
)

// Direction represents TC hook direction.
type Direction int

const (
	Ingress Direction = iota
	Egress
)

// tcParent returns the TC parent handle for the given direction.
func tcParent(direction Direction) uint32 {
	if direction == Ingress {
		return netlink.HANDLE_MIN_INGRESS
	}
	return netlink.HANDLE_MIN_EGRESS
}

// newClsactQdisc creates a clsact qdisc for the given link index.
func newClsactQdisc(linkIndex int) *netlink.GenericQdisc {
	return &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: linkIndex,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_INGRESS,
		},
		QdiscType: "clsact",
	}
}

// newBpfFilter creates a BPF TC filter.
func newBpfFilter(ifIndex int, direction Direction, prog *ebpf.Program) *netlink.BpfFilter {
	return &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifIndex,
			Parent:    tcParent(direction),
			Priority:  TCFilterPriority,
			Protocol:  3, // ETH_P_ALL
		},
		Fd:           prog.FD(),
		Name:         prog.String(),
		DirectAction: true,
	}
}

// AttachTC attaches a BPF program to a TC hook on the given interface.
func AttachTC(ifName string, prog *ebpf.Program, direction Direction) error {
	link, err := netlinkLinkByName(ifName)
	if err != nil {
		return fmt.Errorf("failed to get link %s: %w", ifName, err)
	}

	return attachTCToLink(link, prog, direction)
}

func attachTCToLink(link netlink.Link, prog *ebpf.Program, direction Direction) error {
	ifIndex := link.Attrs().Index
	ifName := link.Attrs().Name

	// Ensure clsact qdisc exists
	if err := ensureClsactQdisc(link); err != nil {
		return fmt.Errorf("failed to ensure clsact qdisc on %s: %w", ifName, err)
	}

	if err := netlinkFilterAdd(newBpfFilter(ifIndex, direction, prog)); err != nil {
		return fmt.Errorf("failed to add TC filter to %s: %w", ifName, err)
	}

	return nil
}

// ensureClsactQdisc ensures that a clsact qdisc exists on the link.
func ensureClsactQdisc(link netlink.Link) error {
	qdiscs, err := netlinkQdiscList(link)
	if err != nil {
		return fmt.Errorf("failed to list qdiscs: %w", err)
	}

	// Check if clsact already exists
	for _, qdisc := range qdiscs {
		if qdisc.Type() == "clsact" {
			return nil // Already exists
		}
	}

	if err := netlinkQdiscAdd(newClsactQdisc(link.Attrs().Index)); err != nil {
		return fmt.Errorf("failed to add clsact qdisc: %w", err)
	}

	return nil
}

// DetachTC removes all TC BPF filters from a link.
func DetachTC(ifName string) error {
	link, err := netlinkLinkByName(ifName)
	if err != nil {
		return fmt.Errorf("failed to get link %s: %w", ifName, err)
	}

	return detachTCFromLink(link)
}

func detachTCFromLink(link netlink.Link) error {
	// Remove ingress filters
	filters, err := netlinkFilterList(link, netlink.HANDLE_MIN_INGRESS)
	if err == nil {
		for _, f := range filters {
			_ = netlinkFilterDel(f)
		}
	}

	// Remove egress filters
	filters, err = netlinkFilterList(link, netlink.HANDLE_MIN_EGRESS)
	if err == nil {
		for _, f := range filters {
			_ = netlinkFilterDel(f)
		}
	}

	return nil
}

// RemoveClsactQdisc removes the clsact qdisc from a link.
func RemoveClsactQdisc(ifName string) error {
	link, err := netlinkLinkByName(ifName)
	if err != nil {
		return fmt.Errorf("failed to get link %s: %w", ifName, err)
	}

	return netlinkQdiscDel(newClsactQdisc(link.Attrs().Index))
}

// HasTCFilter checks if a BPF TC filter exists on the given link.
func HasTCFilter(link Link, direction Direction) bool {
	filters, err := netlinkFilterList(link, tcParent(direction))
	if err != nil {
		return false
	}

	for _, f := range filters {
		if _, ok := f.(*netlink.BpfFilter); ok {
			return true
		}
	}
	return false
}

// TCM_IFINDEX_MAGIC_BLOCK is the magic ifindex value that tells the kernel
// to interpret tcm_parent as a block index instead of a qdisc handle.
// See: include/uapi/linux/rtnetlink.h
const TCM_IFINDEX_MAGIC_BLOCK = -1

// newClsactWithBlock creates a clsact qdisc with an ingress_block binding.
func newClsactWithBlock(ifIndex int, blockIndex uint32) *netlink.GenericQdisc {
	block := blockIndex
	return &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex:    ifIndex,
			Handle:       netlink.MakeHandle(0xffff, 0),
			Parent:       netlink.HANDLE_INGRESS,
			IngressBlock: &block,
		},
		QdiscType: "clsact",
	}
}

// AddClsactWithBlock adds a clsact qdisc with ingress_block to a link.
// "file exists" errors are ignored (idempotent).
func AddClsactWithBlock(ifIndex int, blockIndex uint32) error {
	if err := netlinkQdiscAdd(newClsactWithBlock(ifIndex, blockIndex)); err != nil {
		if !errors.Is(err, syscall.EEXIST) {
			return fmt.Errorf("failed to add clsact with block: %w", err)
		}
	}
	return nil
}

// AddBlockFilter adds a BPF filter to a shared TC block.
func AddBlockFilter(blockIndex uint32, prog *ebpf.Program) error {
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: TCM_IFINDEX_MAGIC_BLOCK,
			Parent:    blockIndex,
			Priority:  TCFilterPriority,
			Protocol:  3, // ETH_P_ALL
		},
		Fd:           prog.FD(),
		Name:         prog.String(),
		DirectAction: true,
	}
	return netlinkFilterAdd(filter)
}

// HasBlockFilter checks if a BPF filter exists on a shared TC block.
func HasBlockFilter(blockIndex uint32) bool {
	dummyLink := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: TCM_IFINDEX_MAGIC_BLOCK}}
	filters, err := netlinkFilterList(dummyLink, blockIndex)
	if err != nil {
		return false
	}
	for _, f := range filters {
		if _, ok := f.(*netlink.BpfFilter); ok {
			return true
		}
	}
	return false
}

// CreateDummyLink creates a dummy network device to serve as a block anchor.
// Falls back to a tap device if the kernel lacks the dummy module (EOPNOTSUPP, e.g. WSL2).
func CreateDummyLink(name string) error {
	err := netlinkLinkAdd(&netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{Name: name},
	})
	if err == nil || !errors.Is(err, syscall.EOPNOTSUPP) {
		return err
	}
	// Fallback: dummy module not available, use tap device instead.
	// tap is lighter than veth (single device, no peer) and CONFIG_TUN
	// is built-in on virtually all kernels.
	return netlinkLinkAdd(&netlink.Tuntap{
		LinkAttrs: netlink.LinkAttrs{Name: name},
		Mode:      netlink.TUNTAP_MODE_TAP,
	})
}

// deleteLinkByName deletes a network device by name.
func deleteLinkByName(name string) error {
	link, err := netlinkLinkByName(name)
	if err != nil {
		return fmt.Errorf("failed to get link %s: %w", name, err)
	}
	return netlinkLinkDel(link)
}

// DeleteLinkByNameInNs deletes a network device by name in the given namespace.
func DeleteLinkByNameInNs(ns NetNS, name string) error {
	return ns.Do(func() error {
		return deleteLinkByName(name)
	})
}
