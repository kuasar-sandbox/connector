package netlink

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

// TapSpec describes a persistent tap device to create.
//
// The tap device is created in the *current* namespace at call time, so callers
// that need it in a specific namespace must run inside that namespace (e.g. via
// netns.Do). It is created persistent (TUNTAP_PERSIST) so that it survives
// process exits — its lifecycle is owned by the switch, not by any fd holder.
//
// Multi-queue support is intentionally not exposed in v1 (single-queue only).
type TapSpec struct {
	Name    string           // Device name (e.g. "<sw>-t1")
	MTU     int              // MTU (default 0 = kernel default)
	MACAddr net.HardwareAddr // HW address (nil = let kernel pick)
	Group   uint32           // Link group for batch deletion (default 0)
}

// CreateTap creates a persistent tap device with the given spec in the current
// namespace and brings it up. Returns the ifindex of the created device.
//
// On error, no partial state is left behind: the device is removed if creation
// got past LinkAdd but subsequent setup (MAC / up) failed.
func CreateTap(spec TapSpec) (int, error) {
	la := netlink.NewLinkAttrs()
	la.Name = spec.Name
	if spec.MTU > 0 {
		la.MTU = spec.MTU
	}
	if spec.Group > 0 {
		la.Group = spec.Group
	}
	if spec.MACAddr != nil {
		la.HardwareAddr = spec.MACAddr
	}

	tap := &netlink.Tuntap{
		LinkAttrs: la,
		Mode:      netlink.TUNTAP_MODE_TAP,
		Flags:     netlink.TUNTAP_DEFAULTS | netlink.TUNTAP_NO_PI,
		// Persist keeps the device alive when no fd is open — required for
		// the "provision creates, VMM opens later" model.
		NonPersist: false,
	}

	if err := netlinkLinkAdd(tap); err != nil {
		return 0, fmt.Errorf("create tap %s: %w", spec.Name, err)
	}

	// Re-query: netlink.LinkAdd does not always populate Attrs().Index.
	link, err := netlinkLinkByName(spec.Name)
	if err != nil {
		// Best-effort cleanup; do not mask the original error.
		_ = netlinkLinkDel(tap)
		return 0, fmt.Errorf("look up created tap %s: %w", spec.Name, err)
	}
	ifindex := link.Attrs().Index

	// Apply MAC explicitly in case LinkAttrs.HardwareAddr was ignored by the kernel
	// for the create path (vishvananda/netlink doesn't always forward it for TUN).
	if spec.MACAddr != nil {
		if err := netlinkLinkSetHardwareAddr(link, spec.MACAddr); err != nil {
			_ = netlinkLinkDel(link)
			return 0, fmt.Errorf("set hwaddr on tap %s: %w", spec.Name, err)
		}
	}

	if err := netlinkLinkSetUp(link); err != nil {
		_ = netlinkLinkDel(link)
		return 0, fmt.Errorf("bring up tap %s: %w", spec.Name, err)
	}
	return ifindex, nil
}

// CreateTapInNs creates a persistent tap inside the given namespace.
func CreateTapInNs(ns NetNS, spec TapSpec) (int, error) {
	var ifindex int
	var err error
	doErr := ns.Do(func() error {
		ifindex, err = CreateTap(spec)
		return err
	})
	if doErr != nil {
		return 0, doErr
	}
	return ifindex, err
}

// DeleteTap removes a tap device by name in the current namespace.
// Returns nil if the device does not exist (idempotent).
func DeleteTap(name string) error {
	link, err := netlinkLinkByName(name)
	if err != nil {
		if IsLinkNotExist(err) {
			return nil
		}
		return fmt.Errorf("look up tap %s: %w", name, err)
	}
	if err := netlinkLinkDel(link); err != nil {
		if IsLinkNotExist(err) {
			return nil
		}
		return fmt.Errorf("delete tap %s: %w", name, err)
	}
	return nil
}

// DeleteTapInNs removes a tap device by name in the given namespace.
func DeleteTapInNs(ns NetNS, name string) error {
	return ns.Do(func() error {
		return DeleteTap(name)
	})
}
