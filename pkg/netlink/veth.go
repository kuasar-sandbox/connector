// Package netlink provides network device management utilities.
package netlink

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

// VethPair represents a veth device pair.
type VethPair struct {
	Name     string // Name of this end
	PeerName string // Name of the other end
}

// CreateVethPair creates a veth pair with the given names.
// Both ends are created in the current namespace and brought up.
func CreateVethPair(name, peerName string) (*VethPair, error) {
	la := netlink.NewLinkAttrs()
	la.Name = name

	veth := &netlink.Veth{
		LinkAttrs: la,
		PeerName:  peerName,
	}

	if err := netlinkLinkAdd(veth); err != nil {
		return nil, fmt.Errorf("failed to create veth pair %s<->%s: %w", name, peerName, err)
	}

	// Bring up both ends
	link, err := netlinkLinkByName(name)
	if err != nil {
		netlinkLinkDel(veth)
		return nil, fmt.Errorf("failed to get veth %s: %w", name, err)
	}
	if err := netlinkLinkSetUp(link); err != nil {
		netlinkLinkDel(veth)
		return nil, fmt.Errorf("failed to bring up %s: %w", name, err)
	}

	peerLink, err := netlinkLinkByName(peerName)
	if err != nil {
		netlinkLinkDel(veth)
		return nil, fmt.Errorf("failed to get veth peer %s: %w", peerName, err)
	}
	if err := netlinkLinkSetUp(peerLink); err != nil {
		netlinkLinkDel(veth)
		return nil, fmt.Errorf("failed to bring up %s: %w", peerName, err)
	}

	return &VethPair{Name: name, PeerName: peerName}, nil
}

// CreateVethPairInNs creates a veth pair within the given namespace.
func CreateVethPairInNs(ns NetNS, name, peerName string) (*VethPair, error) {
	var pair *VethPair
	var err error

	err = ns.Do(func() error {
		pair, err = CreateVethPair(name, peerName)
		return err
	})

	return pair, err
}

// DeleteVethPair deletes a veth pair by deleting one end.
func DeleteVethPair(name string) error {
	link, err := netlinkLinkByName(name)
	if err != nil {
		return fmt.Errorf("failed to get veth %s: %w", name, err)
	}
	return netlinkLinkDel(link)
}

// DeleteVethPairInNs deletes a veth pair within the given namespace.
func DeleteVethPairInNs(ns NetNS, name string) error {
	return ns.Do(func() error {
		return DeleteVethPair(name)
	})
}

// SetLinkUp brings up a network device.
func SetLinkUp(name string) error {
	link, err := netlinkLinkByName(name)
	if err != nil {
		return fmt.Errorf("failed to get link %s: %w", name, err)
	}
	return netlinkLinkSetUp(link)
}

// SetLinkUpInNs brings up a network device in the given namespace.
func SetLinkUpInNs(ns NetNS, name string) error {
	return ns.Do(func() error {
		return SetLinkUp(name)
	})
}

// GetLinkIndex returns the ifindex of a network device.
func GetLinkIndex(name string) (int, error) {
	link, err := netlinkLinkByName(name)
	if err != nil {
		return 0, fmt.Errorf("failed to get link %s: %w", name, err)
	}
	return link.Attrs().Index, nil
}

// GetLinkIndexInNs returns the ifindex of a network device in the given namespace.
func GetLinkIndexInNs(ns NetNS, name string) (int, error) {
	var index int
	var err error

	err = ns.Do(func() error {
		index, err = GetLinkIndex(name)
		return err
	})

	return index, err
}

// AddAddr adds an IP address to a network device.
func AddAddr(name string, addr *net.IPNet) error {
	link, err := netlinkLinkByName(name)
	if err != nil {
		return fmt.Errorf("failed to get link %s: %w", name, err)
	}

	nlAddr := &netlink.Addr{IPNet: addr}
	if err := netlinkAddrAdd(link, nlAddr); err != nil {
		return fmt.Errorf("failed to add address to %s: %w", name, err)
	}
	return nil
}

// AddAddrInNs adds an IP address to a network device in the given namespace.
func AddAddrInNs(ns NetNS, name string, addr *net.IPNet) error {
	return ns.Do(func() error {
		return AddAddr(name, addr)
	})
}

// AddDeviceRoute adds a direct route (no gateway) to dst via the given device
// with the specified metric, equivalent to:
//
//	ip route add <dst> dev <name> metric <metric>
//
// A nil dst is treated as the default route (0.0.0.0/0).
func AddDeviceRoute(name string, dst *net.IPNet, metric int) error {
	link, err := netlinkLinkByName(name)
	if err != nil {
		return fmt.Errorf("failed to get link %s: %w", name, err)
	}

	if dst == nil {
		dst = &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
	}
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dst,
		Priority:  metric,
	}

	if err := netlinkRouteAdd(route); err != nil {
		return fmt.Errorf("failed to add route %s via %s metric %d: %w", dst, name, metric, err)
	}
	return nil
}

// AddDefaultRoute adds a default route via the given device with the specified
// metric. Equivalent to AddDeviceRoute(name, nil, metric):
//
//	ip route add default dev <name> metric <metric>
func AddDefaultRoute(name string, metric int) error {
	return AddDeviceRoute(name, nil, metric)
}

// SetHardwareAddr sets the MAC address of a network device.
func SetHardwareAddr(name string, mac net.HardwareAddr) error {
	link, err := netlinkLinkByName(name)
	if err != nil {
		return fmt.Errorf("failed to get link %s: %w", name, err)
	}
	return netlinkLinkSetHardwareAddr(link, mac)
}

// SetHardwareAddrInNs sets the MAC address of a network device in the given namespace.
func SetHardwareAddrInNs(ns NetNS, name string, mac net.HardwareAddr) error {
	return ns.Do(func() error {
		return SetHardwareAddr(name, mac)
	})
}

// SetMTU sets the MTU of a network device.
func SetMTU(name string, mtu int) error {
	link, err := netlinkLinkByName(name)
	if err != nil {
		return fmt.Errorf("failed to get link %s: %w", name, err)
	}
	return netlinkLinkSetMTU(link, mtu)
}

// SetMTUInNs sets the MTU of a network device in the given namespace.
func SetMTUInNs(ns NetNS, name string, mtu int) error {
	return ns.Do(func() error {
		return SetMTU(name, mtu)
	})
}

// GetMTU returns the MTU of a network device.
func GetMTU(name string) (int, error) {
	link, err := netlinkLinkByName(name)
	if err != nil {
		return 0, fmt.Errorf("failed to get link %s: %w", name, err)
	}
	return link.Attrs().MTU, nil
}

// GetMTUInNs returns the MTU of a network device in the given namespace.
func GetMTUInNs(ns NetNS, name string) (int, error) {
	var mtu int
	var err error

	err = ns.Do(func() error {
		mtu, err = GetMTU(name)
		return err
	})

	return mtu, err
}

// IsLinkDown returns true if the link is in DOWN state (operationally down).
// This is used as a safety check before moving a device to another namespace.
func IsLinkDown(name string) (bool, error) {
	link, err := netlinkLinkByName(name)
	if err != nil {
		return false, fmt.Errorf("failed to get link %s: %w", name, err)
	}
	return link.Attrs().OperState == netlink.OperDown, nil
}

// VethSpec describes a veth pair to create.
type VethSpec struct {
	Name        string           // Name of this end
	PeerName    string           // Name of the other end
	MTU         int              // MTU for both ends (default 0)
	PeerNsFd    int              // Peer namespace fd (0 for same namespace)
	PeerMACAddr net.HardwareAddr // Peer MAC address (nil for default)
	Group       uint32           // Link group for batch deletion (default 0)
}

// CreateVethPairs creates multiple veth pairs in the current namespace.
// All pairs are created and brought up before returning. MTU is set during
// creation if specified, avoiding separate netlink calls.
// If PeerNsFd is specified, the peer end is created directly in that namespace.
func CreateVethPairs(specs []VethSpec) error {
	for _, spec := range specs {
		la := netlink.NewLinkAttrs()
		la.Name = spec.Name
		if spec.MTU > 0 {
			la.MTU = spec.MTU
		}
		if spec.Group > 0 {
			la.Group = spec.Group
		}

		veth := &netlink.Veth{
			LinkAttrs: la,
			PeerName:  spec.PeerName,
		}
		if spec.MTU > 0 {
			veth.PeerMTU = uint32(spec.MTU)
		}
		if spec.PeerNsFd > 0 {
			veth.PeerNamespace = netlink.NsFd(spec.PeerNsFd)
		}
		if spec.PeerMACAddr != nil {
			veth.PeerHardwareAddr = spec.PeerMACAddr
		}

		if err := netlinkLinkAdd(veth); err != nil {
			return fmt.Errorf("create veth %s<->%s: %w", spec.Name, spec.PeerName, err)
		}

		// Bring up this end (peer end needs to be brought up in its namespace)
		if err := setLinkUpByName(spec.Name); err != nil {
			return err
		}

		// Only bring up peer if in same namespace
		if spec.PeerNsFd == 0 {
			if err := setLinkUpByName(spec.PeerName); err != nil {
				return err
			}
		}
	}
	return nil
}

// setLinkUpByName brings up a link by name.
func setLinkUpByName(name string) error {
	link, err := netlinkLinkByName(name)
	if err != nil {
		return fmt.Errorf("get link %s: %w", name, err)
	}
	if err := netlinkLinkSetUp(link); err != nil {
		return fmt.Errorf("bring up %s: %w", name, err)
	}
	return nil
}

// LinkList returns all links in the current namespace.
func LinkList() ([]Link, error) {
	return netlinkLinkList()
}

// LinkByName returns the link with the given name.
func LinkByName(name string) (Link, error) {
	return netlinkLinkByName(name)
}

// LinkExists returns true if the link exists in the current namespace.
func LinkExists(name string) bool {
	_, err := netlinkLinkByName(name)
	return err == nil
}

// IsLinkUp returns true if the link is operationally UP.
// Use this for physical/transit devices where carrier state matters.
func IsLinkUp(name string) bool {
	link, err := netlinkLinkByName(name)
	if err != nil {
		return false
	}
	return link.Attrs().OperState == netlink.OperUp
}

// IsLinkAdminUp returns true if the link is administratively UP (IFF_UP flag set).
// Use this for veth devices where we care about admin state, not carrier.
func IsLinkAdminUp(name string) bool {
	link, err := netlinkLinkByName(name)
	if err != nil {
		return false
	}
	return link.Attrs().Flags&net.FlagUp != 0
}

// DeleteLinkByIndex deletes a network link by its ifindex.
// This is useful when cleaning up interfaces where only the ifindex is known.
func DeleteLinkByIndex(ifindex int) error {
	link, err := netlinkLinkByIndex(ifindex)
	if err != nil {
		return fmt.Errorf("failed to get link by index %d: %w", ifindex, err)
	}
	return netlinkLinkDel(link)
}

// DeleteLinkByIndexInNs deletes a network link by its ifindex within the given namespace.
func DeleteLinkByIndexInNs(ns NetNS, ifindex int) error {
	return ns.Do(func() error {
		return DeleteLinkByIndex(ifindex)
	})
}
