package vswitch

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/fullof-work/sandbox-vswitch/pkg/internal/bpf"
	"github.com/fullof-work/sandbox-vswitch/pkg/netlink"
	"github.com/fullof-work/sandbox-vswitch/pkg/netns"
)

func countAllocatedSlots(mmapSlots *MmappedSlots, nPorts uint32) uint32 {
	var count uint32
	for i := uint32(0); i < nPorts; i++ {
		if IsSlotAllocated(mmapSlots.GetInnerIP(i)) {
			count++
		}
	}
	return count
}

// reserveFreeSlots reserves only Free slots via CAS. Returns ErrPortsInUse if a CAS
// conflict reveals new Allocated ports (concurrent attach happened during reserve).
func reserveFreeSlots(mmapSlots *MmappedSlots, nPorts uint32) error {
RESERVE_FREE:
	for {
		for i := uint32(0); i < nPorts; i++ {
			innerIP := mmapSlots.GetInnerIP(i)
			if innerIP == InnerIPFree {
				if !mmapSlots.TryReserve(i, InnerIPFree) {
					// CAS failed — check if a concurrent attach created a new used port
					if countAllocatedSlots(mmapSlots, nPorts) > 0 {
						return fmt.Errorf("%w: concurrent attach detected during reserve", ErrPortsInUse)
					}
					continue RESERVE_FREE // CAS failed for other reason, restart
				}
			}
			// Skip Allocated and already-Reserved slots
		}
		break
	}
	return nil
}

// reserveAllSlots reserves all non-Reserved slots (Free and Allocated).
func reserveAllSlots(mmapSlots *MmappedSlots, nPorts uint32) {
RESERVE_ALL:
	for {
		for i := uint32(0); i < nPorts; i++ {
			innerIP := mmapSlots.GetInnerIP(i)
			if innerIP != InnerIPReserved {
				if !mmapSlots.TryReserve(i, innerIP) {
					continue RESERVE_ALL // CAS failed, restart
				}
			}
		}
		break
	}
}

// collectPortInterfaces collects port interfaces with non-zero ifindex.
// It also collects unique mgmt ifindexes into mgmtSet.
func collectPortInterfaces(mmapSlots *MmappedSlots, nPorts uint32, mgmtSet map[uint32]bool) []portIfaceToDel {
	var portIfaces []portIfaceToDel
	for i := uint32(0); i < nPorts; i++ {
		slot := mmapSlots.GetSlot(i)

		if slot.Ifindex != 0 {
			portIfaces = append(portIfaces, portIfaceToDel{
				slotID:  i,
				ifindex: slot.Ifindex,
			})
		}

		if slot.MgmtCidrCount > 0 {
			if slot.MgmtCidrs0.Ifindex != 0 && mgmtSet != nil {
				mgmtSet[slot.MgmtCidrs0.Ifindex] = true
			}
			for j := uint32(1); j < slot.MgmtCidrCount && j <= uint32(MaxMgmtCIDRExt); j++ {
				if slot.MgmtCidrsExt[j-1].Ifindex != 0 && mgmtSet != nil {
					mgmtSet[slot.MgmtCidrsExt[j-1].Ifindex] = true
				}
			}
		}
	}
	return portIfaces
}

// deletePortInterfaces deletes port veth pairs and clears BPF/slot state.
func deletePortInterfaces(ctx *switchContext, ifaces []portIfaceToDel, delLinkByIndex func(int) error) error {
	startTime := time.Now()
	lastProgressTime := startTime
	const progressInterval = 5 * time.Second

	for i, item := range ifaces {
		if err := delLinkByIndex(int(item.ifindex)); err != nil {
			if !netlink.IsLinkNotExist(err) {
				return fmt.Errorf("delete port veth ifindex %d: %w", item.ifindex, err)
			}
		}

		if ctx.maps.IfindexToSlot != nil {
			if err := ctx.maps.IfindexToSlot.Delete(item.ifindex); err != nil {
				if !bpf.IsKeyNotExist(err) {
					return fmt.Errorf("delete ifindex_to_slot entry %d: %w", item.ifindex, err)
				}
			}
		}
		ctx.mmapSlots.UpdateSlotFields(item.slotID, func(s *SlotItem) {
			s.Ifindex = 0
		})

		if now := time.Now(); now.Sub(lastProgressTime) >= progressInterval {
			elapsed := now.Sub(startTime).Seconds()
			fmt.Fprintf(os.Stderr, "[info] stop progress: %d/%d ports deleted (%.1fs elapsed)\n", i+1, len(ifaces), elapsed)
			lastProgressTime = now
		}
	}
	return nil
}

// validateAllReleased checks that all slots are Reserved with ifindex=0.
func validateAllReleased(mmapSlots *MmappedSlots, nPorts uint32) error {
	for i := uint32(0); i < nPorts; i++ {
		slot := mmapSlots.GetSlot(i)
		innerIP := mmapSlots.GetInnerIP(i)
		if innerIP != InnerIPReserved || slot.Ifindex != 0 {
			return fmt.Errorf("slot %d not released (innerIP=%#x, ifindex=%d): %w",
				i, innerIP, slot.Ifindex, ErrPortsNotReleased)
		}
	}
	return nil
}

// countPortsWithDevices counts slots with ifindex != 0.
func countPortsWithDevices(mmapSlots *MmappedSlots, nPorts uint32) int {
	count := 0
	for i := uint32(0); i < nPorts; i++ {
		if mmapSlots.GetSlot(i).Ifindex != 0 {
			count++
		}
	}
	return count
}

// ReleasePorts releases port devices without touching mgmt/transit/BPF.
//
// Safe mode (opts.Force == false): refuses if there are Allocated ports,
// returning ErrPortsInUse. Reserves Free slots and deletes port devices.
//
// Force mode (opts.Force == true): two-round cleanup — first free/reserved ports,
// then used ports. Both rounds reserve-then-delete.
func ReleasePorts(switchName string, opts ReleaseOptions) (*ReleaseOutput, error) {
	lock, err := acquireControlLockFn(switchName)
	if err != nil {
		return nil, fmt.Errorf("failed to acquire control lock: %w", err)
	}
	defer lock.Release()

	sw, err := Open(switchName)
	if err != nil {
		return nil, err
	}
	defer sw.Close()

	ctx, ok := sw.(*switchContext)
	if !ok {
		return nil, fmt.Errorf("unexpected switch context type")
	}

	nPorts := ctx.cfg.N_ports

	// Get switch namespace for device operations
	switchNs, delLinkByIndex, err := stopGetSwitchNs(ctx)
	if err != nil {
		return nil, err
	}
	if switchNs != nil {
		defer switchNs.Close()
	}

	beforeDevices := countPortsWithDevices(ctx.mmapSlots, nPorts)

	if opts.Force {
		// === Round 1: Free/Reserved ports ===
		if err := reserveFreeSlots(ctx.mmapSlots, nPorts); err != nil {
			// In force mode, ignore ErrPortsInUse from concurrent attach
		}
		mgmtSet := make(map[uint32]bool) // not used by ReleasePorts, but required by collectPortInterfaces
		portIfaces := collectPortInterfaces(ctx.mmapSlots, nPorts, mgmtSet)
		if err := deletePortInterfaces(ctx, portIfaces, delLinkByIndex); err != nil {
			return nil, err
		}

		// === Round 2: Used (Allocated) ports ===
		reserveAllSlots(ctx.mmapSlots, nPorts)
		portIfaces2 := collectPortInterfaces(ctx.mmapSlots, nPorts, mgmtSet)
		if err := deletePortInterfaces(ctx, portIfaces2, delLinkByIndex); err != nil {
			return nil, err
		}
	} else {
		// Safe mode: check for Allocated ports first
		if used := countAllocatedSlots(ctx.mmapSlots, nPorts); used > 0 {
			return nil, fmt.Errorf("switch %s has %d allocated port(s): %w", switchName, used, ErrPortsInUse)
		}

		if err := reserveFreeSlots(ctx.mmapSlots, nPorts); err != nil {
			return nil, err
		}

		mgmtSet := make(map[uint32]bool)
		portIfaces := collectPortInterfaces(ctx.mmapSlots, nPorts, mgmtSet)
		if err := deletePortInterfaces(ctx, portIfaces, delLinkByIndex); err != nil {
			return nil, err
		}
	}

	remaining := countPortsWithDevices(ctx.mmapSlots, nPorts)
	return &ReleaseOutput{
		Released:  beforeDevices - remaining,
		Total:     int(nPorts),
		Remaining: remaining,
	}, nil
}

// StopReleased performs the final cleanup of a switch whose ports have already
// been released via ReleasePorts. It validates that all slots are Reserved with
// ifindex=0, then cleans up mgmt devices, transit device, dummy device, and BPF maps.
func StopReleased(switchName string) error {
	lock, err := acquireControlLockFn(switchName)
	if err != nil {
		return fmt.Errorf("failed to acquire control lock: %w", err)
	}
	defer lock.Release()

	sw, err := Open(switchName)
	if err != nil {
		return err
	}
	defer sw.Close()

	ctx, ok := sw.(*switchContext)
	if !ok {
		return fmt.Errorf("unexpected switch context type")
	}

	nPorts := ctx.cfg.N_ports

	// Validate all ports are released
	if err := validateAllReleased(ctx.mmapSlots, nPorts); err != nil {
		return err
	}

	// Collect mgmt ifindexes (port ifindexes are all 0 at this point)
	mgmtIfaceSet := make(map[uint32]bool)
	collectPortInterfaces(ctx.mmapSlots, nPorts, mgmtIfaceSet)

	switchNs, delLinkByIndex, err := stopGetSwitchNs(ctx)
	if err != nil {
		return err
	}
	if switchNs != nil {
		defer switchNs.Close()
	}

	return stopCommonCleanup(ctx, switchName, switchNs, mgmtIfaceSet, delLinkByIndex)
}

// Stop stops and cleans up a virtual switch.
// It is a convenience wrapper that calls ReleasePorts followed by StopReleased.
func Stop(switchName string, opts StopOptions) error {
	_, err := ReleasePorts(switchName, ReleaseOptions{Force: opts.Force})
	if err != nil {
		return err
	}
	return StopReleased(switchName)
}

// stopGetSwitchNs gets the switch namespace and returns a delLinkByIndex closure.
func stopGetSwitchNs(ctx *switchContext) (*netns.NetNS, func(int) error, error) {
	switchNsName := ctx.meta.SwitchNetnsName()
	var switchNs *netns.NetNS
	if switchNsName != "" {
		var nsErr error
		switchNs, nsErr = netnsGetByName(switchNsName)
		if nsErr != nil {
			if !errors.Is(nsErr, netns.ErrNotExist) {
				return nil, nil, fmt.Errorf("get switch netns %s: %w", switchNsName, nsErr)
			}
			switchNs = nil
		}
	}
	delLinkByIndex := func(ifindex int) error {
		if switchNs != nil {
			return netlinkDelLinkByIndexInNs(switchNs, ifindex)
		}
		return netlinkDelLinkByIndex(ifindex)
	}
	return switchNs, delLinkByIndex, nil
}

// stopCommonCleanup performs the common cleanup steps: delete mgmt interfaces,
// move transit device, delete dummy device, and unpin BPF maps.
func stopCommonCleanup(ctx *switchContext, switchName string, switchNs *netns.NetNS, mgmtIfaceSet map[uint32]bool, delLinkByIndex func(int) error) error {
	nPorts := ctx.cfg.N_ports

	// Delete mgmt interfaces
	for ifindex := range mgmtIfaceSet {
		if err := delLinkByIndex(int(ifindex)); err != nil {
			if !netlink.IsLinkNotExist(err) {
				return fmt.Errorf("delete mgmt veth ifindex %d: %w", ifindex, err)
			}
		}
	}

	// Clear mgmt CIDR fields in all slots
	for i := uint32(0); i < nPorts; i++ {
		slot := ctx.mmapSlots.GetSlot(i)
		if slot.MgmtCidrCount > 0 || slot.MgmtCidrs0.Ifindex != 0 {
			ctx.mmapSlots.UpdateSlotFields(i, func(s *SlotItem) {
				s.MgmtCidrCount = 0
				s.MgmtCidrs0 = MgmtCIDR{}
				for j := range s.MgmtCidrsExt {
					s.MgmtCidrsExt[j] = MgmtCIDR{}
				}
			})
		}
	}

	// Move transit device back
	transitDevName := ctx.meta.TransitDevName()
	if switchNs != nil && transitDevName != "" {
		callerNs, err := netnsGetCurrent()
		if err != nil {
			return fmt.Errorf("get current netns: %w", err)
		}
		defer callerNs.Close()

		if err := netnsMoveDevice(transitDevName, switchNs, callerNs); err != nil {
			if !netlink.IsLinkNotExist(err) && !errors.Is(err, syscall.EEXIST) {
				return fmt.Errorf("move transit device %s: %w", transitDevName, err)
			}
		}
	}

	// Delete block anchor dummy device
	dummyDevName := fmt.Sprintf("%s-dummy", switchName)
	if switchNs != nil {
		if err := netlinkDeleteLinkByNameInNs(switchNs, dummyDevName); err != nil {
			if !netlink.IsLinkNotExist(err) {
				return fmt.Errorf("delete block device %s: %w", dummyDevName, err)
			}
		}
	}

	// Unpin BPF maps
	return bpfUnpinMaps(switchName)
}

// Cleanup retry constants
