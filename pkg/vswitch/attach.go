package vswitch

import (
	"fmt"

	"github.com/cilium/ebpf"

	"github.com/kuasar-sandbox/connector/pkg/internal/bpf"
)

// Attach allocates a port to a sandbox.
// Uses atomic CAS on mmap'd BPF map for concurrent-safe slot allocation.
func Attach(switchName string, opts AttachOptions) (*AttachOutput, error) {
	sw, err := Open(switchName)
	if err != nil {
		return nil, err
	}
	defer sw.Close()
	return sw.Attach(opts)
}

// Attach implements Interface.Attach.
// Allocates a port to a sandbox using the pre-loaded context.
func (s *switchContext) Attach(opts AttachOptions) (*AttachOutput, error) {
	cfg := s.cfg
	locator := geneveLocatorFromConfig(cfg)
	if !locator.valid() {
		return nil, fmt.Errorf("switch has invalid GENEVE locator value %d; rebuild the switch", cfg.GeneveLocator)
	}
	if err := validateTransitGeneveVNI(locator, opts.TransitGeneveVNI); err != nil {
		return nil, err
	}

	var tlvLocator *GeneveTLVLocator
	if locator == GeneveLocatorTLV {
		value := geneveTLVLocatorFromConfig(cfg)
		tlvLocator = &value
	}
	geneveOptsValue, totalGeneveOptsLen, err := marshalGeneveOptions(locator, tlvLocator, opts.TransitGeneveOpts)
	if err != nil {
		return nil, err
	}
	hasGeneveOptsMap := s.maps != nil && s.maps.GeneveOpts != nil
	if !hasGeneveOptsMap && (locator != GeneveLocatorPort || geneveOptsValue.Len != 0) {
		return nil, fmt.Errorf("switch lacks the geneve_opts map required by geneve_locator=%s or non-empty transit_geneve_opts; rebuild the switch", locator)
	}

	innerIP := bpf.IPToUint32(opts.InnerIP)
	if innerIP == 0 {
		return nil, fmt.Errorf("inner-ip cannot be 0.0.0.0")
	}

	var slotID uint32

	// Allocate slot using atomic CAS
	if opts.Port > 0 {
		// Specific slot requested
		slotID = uint32(opts.Port - 1)
		if slotID >= cfg.N_ports {
			return nil, fmt.Errorf("port %d: %w (max %d)", opts.Port, ErrPortOutOfRange, cfg.N_ports)
		}
		if !s.mmapSlots.TryAllocate(slotID, innerIP) {
			return nil, fmt.Errorf("port %d: %w", opts.Port, ErrPortAllocated)
		}
	} else {
		// Auto-allocate: find first free slot
		var err error
		slotID, err = s.mmapSlots.FindFreeSlot(innerIP)
		if err != nil {
			return nil, err
		}
	}

	// From this point the claim is ours. Suppress option lookup immediately so
	// an old slot value can never be observed under the new owner. Rollback
	// leaves the fixed map value untouched and clears only the fast-path hint.
	s.mmapSlots.UpdateSlotFields(slotID, func(slot *SlotItem) {
		slot.GeneveOptsLen = 0
	})
	rollbackClaim := func() {
		// Reclaim this attachment before touching its non-atomic fields. If a
		// concurrent Detach already freed and reattached the slot, the CAS fails
		// and the new owner's state must remain untouched.
		if !s.mmapSlots.TryReserve(slotID, innerIP) {
			return
		}
		s.mmapSlots.UpdateSlotFields(slotID, func(slot *SlotItem) {
			slot.GeneveOptsLen = 0
		})
		s.mmapSlots.TryUnreserve(slotID)
	}

	// Mode-specific validation: tap ports must have been provisioned (have a
	// real ifindex) before attach because attach does not create devices. For
	// veth this is enforced implicitly by the netns move below failing.
	portKind := SlotPortKind(s.mmapSlots.GetSlot(slotID))
	if portKind == PortKindTap && s.mmapSlots.GetSlot(slotID).Ifindex == 0 {
		rollbackClaim()
		return nil, fmt.Errorf("port %d: %w (tap mode requires provision first)", slotID+1, ErrPortNotProvisioned)
	}

	// A new switch always has the map. Overwrite the entire fixed-size value,
	// including the zero value for empty options, before publishing any hint.
	if hasGeneveOptsMap {
		if err := writeGeneveOptsFn(s.maps.GeneveOpts, slotID, &geneveOptsValue); err != nil {
			rollbackClaim()
			return nil, fmt.Errorf("write GENEVE options for port %d: %w", slotID+1, err)
		}
	}

	// Fixed locator overhead was checked at switch start. Recheck every non-zero
	// wire option budget (including the generated TLV locator) against the
	// selected port's actual MTU before moving a device or delivering a tap FD.
	if totalGeneveOptsLen != 0 {
		if err := validateAttachMTUFn(s, slotID, portKind, int(totalGeneveOptsLen)); err != nil {
			rollbackClaim()
			return nil, err
		}
	}

	// CAS succeeded - slot is now ours. Update other fields via mmap.
	// Note: We must unconditionally overwrite ALL transit fields because
	// Detach does not clear them (to avoid race with concurrent Attach).
	s.mmapSlots.UpdateSlotFields(slotID, func(slot *SlotItem) {
		if opts.TransitGatewayIP != nil {
			slot.TransitGatewayIp = bpf.IPToUint32(opts.TransitGatewayIP)
		} else {
			slot.TransitGatewayIp = 0
		}
		slot.TransitGeneveVni = opts.TransitGeneveVNI
		slot.ClearTransitMac() // Clear first
		if len(opts.TransitMAC) >= 6 {
			slot.SetTransitMacAddr(opts.TransitMAC)
		}
	})
	// Publish the opaque length only after the map value and every transit field
	// are complete. A zero value retains the legacy no-lookup hot path.
	s.mmapSlots.UpdateSlotFields(slotID, func(slot *SlotItem) {
		slot.GeneveOptsLen = geneveOptsValue.Len
	})

	// Reset stats for this slot on attach
	if err := s.statsMgr.ResetStats(slotID); err != nil {
		// Stats reset failure is not critical, log and continue
		// The slot is already allocated, so we don't roll back
	}

	// Move port device from port namespace to target sandbox namespace.
	// Tap-mode ports stay in the switch namespace (the sandbox process receives
	// a file descriptor via 'open-port' instead of a kernel netdev), so the
	// netns-move step is skipped entirely.
	portName := fmt.Sprintf("%s-p%d", s.name, slotID+1)

	if portKind == PortKindVeth && !opts.SkipDevice && opts.ToNetNS != "" {
		portNsName := s.meta.PortNetnsName()
		portNs, err := netnsGetByName(portNsName)
		if err != nil {
			// Rollback: release the slot
			rollbackClaim()
			return nil, fmt.Errorf("failed to get port netns %s: %w", portNsName, err)
		}
		defer portNs.Close()

		toNs, err := netnsGetByName(opts.ToNetNS)
		if err != nil {
			// Rollback: release the slot
			rollbackClaim()
			return nil, fmt.Errorf("failed to get target netns %s: %w", opts.ToNetNS, err)
		}
		defer toNs.Close()

		if err := netnsMoveDevice(portName, portNs, toNs); err != nil {
			// Rollback: release the slot
			rollbackClaim()
			return nil, fmt.Errorf("failed to move %s to %s: %w", portName, opts.ToNetNS, err)
		}
	}

	// Calculate derived values
	floatingIP := bpf.Uint32ToIP(cfg.FloatingIpBase + slotID)
	genevePort := geneveWirePort(locator, cfg.GenevePortBase, slotID)
	wireGeneveVNI := geneveWireVNI(locator, slotID, opts.TransitGeneveVNI)

	// Use GetPortMAC to get fixed or per-port derived MAC
	portMAC := GetPortMAC(cfg.SwitchMac[:], cfg.PortMac[:], slotID)

	out := &AttachOutput{
		Port:       slotID + 1,
		PortDev:    portName,
		PortNetNS:  opts.ToNetNS,
		PortMAC:    portMAC.String(),
		InnerIP:    opts.InnerIP.String(),
		FloatingIP: floatingIP.String(),
		Mode:       portKind.String(),
	}
	if portKind == PortKindTap {
		// Tap ports live in the switch netns; the sandbox holds an fd via
		// open-port. Surface the tap device name and its actual location.
		out.PortDev = fmt.Sprintf("%s-t%d", s.name, slotID+1)
		out.PortNetNS = s.meta.SwitchNetnsName()
	}

	transitDev := s.meta.TransitDevName()
	if opts.TransitGatewayIP != nil && transitDev != "" {
		out.TransitType = "overlay-geneve"
		out.TransitGatewayIP = opts.TransitGatewayIP.String()
		out.GenevePort = genevePort
		out.GeneveLocator = locator.String()
		out.TransitGeneveVNI = opts.TransitGeneveVNI
		out.WireGeneveVNI = wireGeneveVNI
		out.GeneveOptsLen = totalGeneveOptsLen
	} else {
		out.TransitType = "none"
	}
	return out, nil
}

func writeGeneveOpts(optionsMap BPFMap, slotID uint32, value *GeneveOptsValue) error {
	if err := optionsMap.Update(slotID, value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update geneve_opts map: %w", err)
	}
	return nil
}

func validateAttachMTU(s *switchContext, slotID uint32, portKind PortKind, optionsOverhead int) error {
	if s.meta == nil || s.meta.TransitDevName() == "" {
		return nil
	}
	switchNs, err := netnsGetByName(s.meta.SwitchNetnsName())
	if err != nil {
		return fmt.Errorf("validate GENEVE options MTU: get switch netns %s: %w", s.meta.SwitchNetnsName(), err)
	}
	defer switchNs.Close()

	portName := PeerDeviceName(s.name, slotID)
	if portKind == PortKindTap {
		portName = TapDeviceName(s.name, slotID)
	}
	portMTU, err := netlinkGetMTUInNs(switchNs, portName)
	if err != nil {
		return fmt.Errorf("validate GENEVE options MTU: get port %s MTU: %w", portName, err)
	}
	transitDev := s.meta.TransitDevName()
	transitMTU, err := netlinkGetMTUInNs(switchNs, transitDev)
	if err != nil {
		return fmt.Errorf("validate GENEVE options MTU: get transit device %s MTU: %w", transitDev, err)
	}

	baseOverhead := GeneveIPOverhead
	if s.cfg.GeneveEncapEth != 0 {
		baseOverhead = GeneveEthOverhead
	}
	requiredMTU := portMTU + baseOverhead + optionsOverhead
	if transitMTU < requiredMTU {
		return fmt.Errorf("transit device %s MTU %d is too small for port %s: port MTU %d + base GENEVE overhead %d + options overhead %d = required MTU %d",
			transitDev, transitMTU, portName, portMTU, baseOverhead, optionsOverhead, requiredMTU)
	}
	return nil
}

// Reserve reserves a port slot.
func Reserve(switchName string, opts ReserveOptions) (*ReserveOutput, error) {
	sw, err := Open(switchName)
	if err != nil {
		return nil, err
	}
	defer sw.Close()
	return sw.Reserve(opts)
}

// Reserve implements Interface.Reserve.
func (s *switchContext) Reserve(opts ReserveOptions) (*ReserveOutput, error) {
	if opts.Port <= 0 {
		return nil, fmt.Errorf("--port is required for reserve operations")
	}
	slotID := uint32(opts.Port - 1)
	if slotID >= s.cfg.N_ports {
		return nil, fmt.Errorf("port %d: %w (max %d)", opts.Port, ErrPortOutOfRange, s.cfg.N_ports)
	}

	status := "reserved"

	if opts.Force {
		// Force reserve: CAS loop until we set Reserved
		for {
			current := s.mmapSlots.GetInnerIP(slotID)
			if current == InnerIPReserved {
				status = "already_reserved"
				break
			}
			if s.mmapSlots.TryReserve(slotID, current) {
				break
			}
			// CAS failed, retry
		}
	} else {
		// Normal reserve: CAS(Free → Reserved)
		if !s.mmapSlots.TryAllocate(slotID, InnerIPReserved) {
			current := s.mmapSlots.GetInnerIP(slotID)
			if current == InnerIPReserved {
				return nil, fmt.Errorf("port %d: already reserved", opts.Port)
			}
			return nil, fmt.Errorf("port %d: %w", opts.Port, ErrPortAllocated)
		}
	}

	return &ReserveOutput{
		Port:   slotID + 1,
		Status: status,
	}, nil
}

// Detach releases a port from a sandbox.
// Uses atomic CAS on the mmap'd BPF map for concurrent-safe slot release.
// The device move is idempotent and performed before claiming the slot for
// release.
func Detach(switchName string, opts DetachOptions) error {
	sw, err := Open(switchName)
	if err != nil {
		return err
	}
	defer sw.Close()
	return sw.Detach(opts)
}

// Detach implements Interface.Detach.
// Releases a port from a sandbox using the pre-loaded context.
func (s *switchContext) Detach(opts DetachOptions) error {
	if opts.Port <= 0 {
		return fmt.Errorf("port number is required")
	}

	cfg := s.cfg
	slotID := uint32(opts.Port - 1) // Convert to 0-based
	if slotID >= cfg.N_ports {
		return fmt.Errorf("port %d: %w", opts.Port, ErrPortOutOfRange)
	}

	// Read current InnerIP atomically
	currentIP := s.mmapSlots.GetInnerIP(slotID)
	if IsSlotFreeOrReserved(currentIP) {
		return fmt.Errorf("port %d: %w", opts.Port, ErrPortNotAttached)
	}

	// Tap-mode ports never move between namespaces (the sandbox holds an fd,
	// not a kernel netdev), so detach is a pure slot operation for tap.
	// For veth, optionally move the port device back to the port namespace.
	portKind := SlotPortKind(s.mmapSlots.GetSlot(slotID))
	if portKind == PortKindVeth && !opts.SkipDevice {
		// Move port device back to port namespace first (idempotent operation)
		// This ensures the device is returned even if CAS fails
		portName := fmt.Sprintf("%s-p%d", s.name, slotID+1)
		portNsName := s.meta.PortNetnsName()

		portNs, err := netnsGetByName(portNsName)
		if err != nil {
			return fmt.Errorf("failed to get port netns %s: %w", portNsName, err)
		}
		defer portNs.Close()

		// Check if device is already in port namespace (idempotent check)
		_, alreadyInPortNs := netnsGetLinkInNs(portNs, portName)

		if alreadyInPortNs != nil {
			// Device not in port namespace, need to move it
			if opts.FromNetNS == "" {
				return fmt.Errorf("port device %s not found in %s (use --from-netns if the device was moved): %w", portName, portNsName, alreadyInPortNs)
			}

			fromNs, err := netnsGetByName(opts.FromNetNS)
			if err != nil {
				return fmt.Errorf("failed to get source netns %s: %w", opts.FromNetNS, err)
			}
			defer fromNs.Close()

			if err := netnsMoveDevice(portName, fromNs, portNs); err != nil {
				return fmt.Errorf("failed to move %s back to %s: %w", portName, portNsName, err)
			}
		}
		// else: device already in port namespace, skip move (idempotent)
	}

	// Claim the current attachment as Reserved before changing the non-atomic
	// hint. This prevents a concurrent Attach from acquiring the slot between
	// clearing the hint and releasing ownership, and leaves rollback paths such
	// as failed tap FD delivery with geneve_opts_len=0 as required.
	if !s.mmapSlots.TryReserve(slotID, currentIP) {
		// Another process may have detached or detached and reattached the slot
		// while the device operation was in progress.
		newIP := s.mmapSlots.GetInnerIP(slotID)
		if newIP == InnerIPFree || newIP == InnerIPReserved {
			return nil
		}
		return fmt.Errorf("port %d was reattached by another process", opts.Port)
	}

	// Suppress per-slot option lookup while the slot is exclusively Reserved.
	// The fixed map value and other transit fields remain untouched; the next
	// Attach atomically overwrites the full option value before publishing its
	// new hint.
	s.mmapSlots.UpdateSlotFields(slotID, func(slot *SlotItem) {
		slot.GeneveOptsLen = 0
	})

	if !s.mmapSlots.TryUnreserve(slotID) {
		return fmt.Errorf("port %d: failed to release reserved slot", opts.Port)
	}

	return nil
}
