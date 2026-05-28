package vswitch

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/cilium/ebpf"

	"github.com/kuasar-sandbox/sandbox-vswitch/pkg/internal/bpf"
	"github.com/kuasar-sandbox/sandbox-vswitch/pkg/netlink"
	"github.com/kuasar-sandbox/sandbox-vswitch/pkg/netns"
)

// mgmtInfo holds per-mgmt-extract device info for slot writes.
type mgmtInfo struct {
	ifindex int
	mac     net.HardwareAddr
	cidrs   []MgmtCIDR
}

// writeSlotDeviceInfo writes port ifindex, mgmt CIDRs, and transit info to a slot.
func writeSlotDeviceInfo(mmapSlots *MmappedSlots, slotID uint32, ifindex int, mgmtInfos []mgmtInfo, transitIfindex int, transitIP uint32) {
	mmapSlots.UpdateSlotFields(slotID, func(slot *SlotItem) {
		slot.Ifindex = uint32(ifindex)
		slot.MgmtCidrCount = 0
		for _, mi := range mgmtInfos {
			for _, cidr := range mi.cidrs {
				if slot.MgmtCidrCount >= MaxMgmtCIDRPerSlot {
					break
				}
				if slot.MgmtCidrCount == 0 {
					slot.MgmtCidrs0 = cidr
				} else {
					slot.MgmtCidrsExt[slot.MgmtCidrCount-1] = cidr
				}
				slot.MgmtCidrCount++
			}
		}
		slot.TransitIfindex = uint32(transitIfindex)
		slot.TransitIp = transitIP
	})
}

// provisionVethSlot creates (or reuses) a veth pair for a single slot in the
// switch namespace and attaches the shared TC ingress block. Returns the switch-
// side peer ifindex. Idempotent: if the peer device already exists with the
// expected name, the existing ifindex is reused and clsact is ensured.
//
// Requires the port netns to exist; caller must have set it up via openPortNetns.
func provisionVethSlot(switchNs, portNs *netns.NetNS, switchName string, slotID uint32, cfg *SwitchConfig) (int, error) {
	portName := fmt.Sprintf("%s-p%d", switchName, slotID+1)
	peerName := fmt.Sprintf("%s-n%d", switchName, slotID+1)
	peerMAC := GetPortMAC(cfg.SwitchMac[:], cfg.PortMac[:], slotID)

	// Idempotent: reuse existing peer if present.
	if existing, err := netlinkGetLinkIndexInNs(switchNs, peerName); err == nil {
		if err := netnsDoFn(switchNs, func() error {
			return netlinkAddClsactWithBlock(existing, PortIngressBlockID)
		}); err != nil {
			return 0, fmt.Errorf("ensure clsact on existing veth peer: %w", err)
		}
		return existing, nil
	}

	spec := netlink.VethSpec{
		Name:        peerName,
		PeerName:    portName,
		PeerNsFd:    int(portNs.Handle()),
		PeerMACAddr: peerMAC,
		Group:       PortLinkGroup,
	}
	if err := netnsDoFn(switchNs, func() error {
		return netlinkCreateVethPairs([]netlink.VethSpec{spec})
	}); err != nil {
		return 0, fmt.Errorf("failed to create veth: %w", err)
	}

	var newIfindex int
	if err := netnsDoFn(switchNs, func() error {
		link, err := netlinkLinkByName(peerName)
		if err != nil {
			return err
		}
		newIfindex = link.Attrs().Index
		return netlinkAddClsactWithBlock(newIfindex, PortIngressBlockID)
	}); err != nil {
		return 0, fmt.Errorf("failed to add clsact: %w", err)
	}
	return newIfindex, nil
}

// provisionTapSlot creates (or reuses) a persistent tap device for a single
// slot in the switch namespace and attaches the shared TC ingress block.
// Returns the tap's ifindex. The tap is created persistent so that
// vswitch-ctl owns its lifecycle (provision creates, stop deletes).
//
// Idempotent: if the tap already exists with the expected name, the existing
// ifindex is reused and clsact is ensured.
func provisionTapSlot(switchNs *netns.NetNS, switchName string, slotID uint32, cfg *SwitchConfig) (int, error) {
	tapName := fmt.Sprintf("%s-t%d", switchName, slotID+1)
	portMAC := GetPortMAC(cfg.SwitchMac[:], cfg.PortMac[:], slotID)

	// Idempotent: reuse existing tap if present.
	if existing, err := netlinkGetLinkIndexInNs(switchNs, tapName); err == nil {
		if err := netnsDoFn(switchNs, func() error {
			return netlinkAddClsactWithBlock(existing, PortIngressBlockID)
		}); err != nil {
			return 0, fmt.Errorf("ensure clsact on existing tap: %w", err)
		}
		return existing, nil
	}

	ifindex, err := netlinkCreateTapInNs(switchNs, netlink.TapSpec{
		Name:    tapName,
		MACAddr: portMAC,
		// MTU intentionally not set here: SwitchConfig (BPF map) does not carry
		// the user-facing MTU. The tap inherits the kernel default (1500),
		// matching how veth provision behaves when --mtu is unspecified.
		// MTU is reported in open-port metadata by reading it back from the
		// netdev, which is the single source of truth.
		Group: PortLinkGroup,
	})
	if err != nil {
		return 0, fmt.Errorf("create tap: %w", err)
	}
	if err := netnsDoFn(switchNs, func() error {
		return netlinkAddClsactWithBlock(ifindex, PortIngressBlockID)
	}); err != nil {
		// Tap was created but we couldn't attach clsact — clean up so the next
		// retry sees a clean state instead of a half-provisioned device.
		_ = netlinkDeleteTapInNs(switchNs, tapName)
		return 0, fmt.Errorf("add clsact on tap: %w", err)
	}
	return ifindex, nil
}

// deleteOldSlotDeviceByIfindex removes a stale device left over from a
// previous mode by ifindex. Called AFTER the new-mode device is successfully
// created and the slot points at the new ifindex; this ordering means a
// transient error during create leaves the old device intact (slot stays
// usable in its previous mode for a retry) instead of corrupting state.
//
// The slot.Ifindex field is NOT modified here — the caller has already
// overwritten it with the new device's ifindex in the unified tail.
func deleteOldSlotDeviceByIfindex(sw Interface, switchNs *netns.NetNS, slotID, oldIfindex uint32) error {
	if oldIfindex == 0 {
		return nil
	}
	// Clear the reverse map entry first, but only if it still points at THIS
	// slot — guards against the old ifindex having been reassigned to an
	// unrelated slot in between.
	if sw.Maps().IfindexToSlot != nil {
		var stored uint32
		if err := sw.Maps().IfindexToSlot.Lookup(oldIfindex, &stored); err == nil && stored == slotID {
			_ = sw.Maps().IfindexToSlot.Delete(oldIfindex)
		}
	}
	// Delete the device. For veth this also auto-deletes the sandbox-side
	// peer (kernel pairs them); for tap this fully removes the device.
	if err := netnsDoFn(switchNs, func() error {
		if err := netlinkDelLinkByIndex(int(oldIfindex)); err != nil {
			if netlink.IsLinkNotExist(err) {
				return nil
			}
			return err
		}
		return nil
	}); err != nil {
		return fmt.Errorf("delete stale device ifindex=%d: %w", oldIfindex, err)
	}
	return nil
}

// ProvisionPorts creates veth devices for Reserved slots and transitions them to Free.
// It operates incrementally: successfully provisioned slots remain Free even if a later
// slot fails. Failed slots stay Reserved and can be retried by calling ProvisionPorts again.
// Each slot transitions: Reserved → (create veth + TC attach + write ifindex) → Free.
// This is idempotent: already-Free/Allocated slots are skipped.
func ProvisionPorts(switchName string, opts ProvisionOptions) (*ProvisionOutput, error) {
	// Acquire control lock (ensures bpffs is mounted)
	lock, err := acquireControlLockFn(switchName)
	if err != nil {
		return nil, fmt.Errorf("failed to acquire control lock: %w", err)
	}
	defer lock.Release()

	// Open switch context
	sw, err := Open(switchName)
	if err != nil {
		return nil, err
	}
	defer sw.Close()

	cfg := sw.Config()
	meta := sw.Metadata()
	mmapSlots := sw.MmapSlots()

	// Get switch namespace
	switchNs, err := netnsGetByName(meta.SwitchNetnsName())
	if err != nil {
		return nil, fmt.Errorf("failed to get switch netns: %w", err)
	}
	defer switchNs.Close()

	// Port namespace is only required for veth mode. Open it lazily so that
	// tap-only provisioning works without --port-netns being configured.
	// portNsName == "" means no port netns; lookup is deferred until we hit
	// a veth slot in the loop.
	portNsName := meta.PortNetnsName()
	var portNs *netns.NetNS
	defer func() {
		if portNs != nil {
			portNs.Close()
		}
	}()
	openPortNetns := func() error {
		if portNs != nil {
			return nil
		}
		if portNsName == "" {
			return fmt.Errorf("port-netns is required for veth-mode provision but switch has none configured")
		}
		ns, err := netnsGetByName(portNsName)
		if err != nil {
			return fmt.Errorf("failed to get port netns: %w", err)
		}
		portNs = ns
		return nil
	}

	// Pre-query mgmt info for slot writes
	var mgmtInfos []mgmtInfo
	for i, me := range meta.MgmtExtracts {
		mgmtName := fmt.Sprintf("%s-m%d", switchName, i)
		mgmtIfindex, err := netlinkGetLinkIndexInNs(switchNs, mgmtName)
		if err != nil {
			return nil, fmt.Errorf("failed to get ifindex for mgmt device %s: %w", mgmtName, err)
		}
		mgmtDevMAC := MgmtMAC(cfg.SwitchMac[:], i)

		var cidrs []MgmtCIDR
		for _, routeStr := range me.ServiceRoutes {
			_, ipnet, err := net.ParseCIDR(routeStr)
			if err != nil {
				return nil, fmt.Errorf("failed to parse mgmt service route %s: %w", routeStr, err)
			}
			cidr := MgmtCIDR{
				Ip:      bpf.IPToUint32(ipnet.IP),
				Mask:    bpf.MaskToUint32(ipnet.Mask),
				Ifindex: uint32(mgmtIfindex),
			}
			cidr.SetMgmtMacAddr(mgmtDevMAC)
			cidrs = append(cidrs, cidr)
		}
		mgmtInfos = append(mgmtInfos, mgmtInfo{
			ifindex: mgmtIfindex,
			mac:     mgmtDevMAC,
			cidrs:   cidrs,
		})
	}

	// Pre-query transit info for slot writes
	var transitIfindex int
	var transitIP uint32
	if meta.TransitDevName() != "" {
		var err error
		transitIfindex, err = netlinkGetLinkIndexInNs(switchNs, meta.TransitDevName())
		if err != nil {
			return nil, fmt.Errorf("failed to get ifindex for transit device %s: %w", meta.TransitDevName(), err)
		}
		// Read transit IP from metadata (CIDR format, e.g. "192.168.1.2/24")
		if meta.TransitDevAddrStr() == "" {
			return nil, fmt.Errorf("transit device %s configured but transit address missing in metadata", meta.TransitDevName())
		}
		ip, _, err := net.ParseCIDR(meta.TransitDevAddrStr())
		if err != nil {
			return nil, fmt.Errorf("failed to parse transit address %s from metadata: %w", meta.TransitDevAddrStr(), err)
		}
		transitIP = bpf.IPToUint32(ip)
	}

	provisioned := 0
	startTime := time.Now()
	lastProgressTime := startTime
	const progressInterval = 5 * time.Second

	for slotID := uint32(0); slotID < cfg.N_ports; slotID++ {
		// Filter by specific port if requested
		if opts.Port > 0 && slotID != uint32(opts.Port-1) {
			continue
		}

		// Only provision Reserved slots
		if mmapSlots.GetInnerIP(slotID) != InnerIPReserved {
			continue
		}

		// Mode-switch handling: record the existing device's ifindex (if any)
		// so we can delete it AFTER the new-mode device is up and the slot
		// points to it. This ordering means a transient error during create
		// leaves the slot in its previous mode (recoverable) instead of
		// in a half-state with no device.
		existingSlot := mmapSlots.GetSlot(slotID)
		existingMode := SlotPortKind(existingSlot)
		oldIfindex := existingSlot.Ifindex
		isModeSwitch := oldIfindex != 0 && existingMode != opts.Mode

		// Create (or reuse, if idempotent) the device for the requested mode.
		// Names of veth (<sw>-pX/-nX) and tap (<sw>-tX) don't collide, so the
		// old and new devices can coexist briefly during a mode switch.
		var newIfindex int
		var err error
		switch opts.Mode {
		case PortKindVeth:
			if err := openPortNetns(); err != nil {
				return nil, err
			}
			newIfindex, err = provisionVethSlot(switchNs, portNs, switchName, slotID, cfg)
		case PortKindTap:
			newIfindex, err = provisionTapSlot(switchNs, switchName, slotID, cfg)
		default:
			return nil, fmt.Errorf("slot %d: unsupported mode %s", slotID, opts.Mode)
		}
		if err != nil {
			// Create failed before we touched anything else → old device (if
			// any) is intact, slot still points at it. Caller can retry.
			return nil, fmt.Errorf("slot %d: %w", slotID, err)
		}

		// ── Unified tail: update slot and reverse index in correct order ──

		// Step 1: Delete stale reverse entry (avoid old mapping lingering)
		if uint32(newIfindex) != oldIfindex && sw.Maps().IfindexToSlot != nil {
			if oldIfindex != 0 {
				var storedSlot uint32
				if err := sw.Maps().IfindexToSlot.Lookup(oldIfindex, &storedSlot); err == nil && storedSlot == slotID {
					_ = sw.Maps().IfindexToSlot.Delete(oldIfindex)
				}
			}
		}

		// Step 2: Write slot device info (port + mgmt + transit + mode)
		writeSlotDeviceInfo(mmapSlots, slotID, newIfindex, mgmtInfos, transitIfindex, transitIP)
		mmapSlots.UpdateSlotFields(slotID, func(s *SlotItem) {
			s.Mode = uint8(opts.Mode)
		})

		// Step 3: Insert new reverse entry
		if uint32(newIfindex) != oldIfindex && sw.Maps().IfindexToSlot != nil {
			ifindexKey := uint32(newIfindex)
			slotIDVal := slotID
			if err := sw.Maps().IfindexToSlot.Update(ifindexKey, &slotIDVal, ebpf.UpdateAny); err != nil {
				return nil, fmt.Errorf("failed to update ifindex_to_slot for slot %d: %w", slotID, err)
			}
		}

		// Step 4: For mode switches, now that the new device is the active
		// one in the slot, tear down the leftover old-mode device. Failure to
		// delete here is logged but not fatal — the slot is already in the
		// right mode; the orphaned device just costs kernel memory until
		// 'stop' reaps it.
		if isModeSwitch {
			if err := deleteOldSlotDeviceByIfindex(sw, switchNs, slotID, oldIfindex); err != nil {
				fmt.Fprintf(os.Stderr, "[warn] slot %d: stale %s device cleanup failed (orphan ifindex=%d): %v\n",
					slotID, existingMode, oldIfindex, err)
			}
		}

		// CAS(Reserved → Free) with retry
		for {
			if mmapSlots.TryUnreserve(slotID) {
				break
			}
			current := mmapSlots.GetInnerIP(slotID)
			if current == InnerIPFree {
				break // Already free
			}
			if current != InnerIPReserved {
				return nil, fmt.Errorf("slot %d: unexpected state %#x during provision", slotID, current)
			}
			// Still Reserved, retry
		}

		provisioned++

		// Progress reporting
		if now := time.Now(); now.Sub(lastProgressTime) >= progressInterval {
			elapsed := now.Sub(startTime).Seconds()
			fmt.Fprintf(os.Stderr, "[info] provision progress: %d ports (%.1fs elapsed)\n", provisioned, elapsed)
			lastProgressTime = now
		}

		if opts.Count > 0 && provisioned >= opts.Count {
			break
		}
	}

	// Count available (Free) slots
	available := 0
	for i := uint32(0); i < cfg.N_ports; i++ {
		if mmapSlots.GetInnerIP(i) == InnerIPFree {
			available++
		}
	}

	return &ProvisionOutput{
		Provisioned: provisioned,
		Total:       int(cfg.N_ports),
		Available:   available,
	}, nil
}

// getExistingSwitch returns StartOutput for an existing switch after validating config.
