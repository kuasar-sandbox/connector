package vswitch

import (
	"fmt"

	"github.com/kuasar-sandbox/sandbox-vswitch/pkg/internal/bpf"
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

	// Mode-specific validation: tap ports must have been provisioned (have a
	// real ifindex) before attach because attach does not create devices. For
	// veth this is enforced implicitly by the netns move below failing.
	portKind := SlotPortKind(s.mmapSlots.GetSlot(slotID))
	if portKind == PortKindTap && s.mmapSlots.GetSlot(slotID).Ifindex == 0 {
		s.mmapSlots.TryRelease(slotID, innerIP)
		return nil, fmt.Errorf("port %d: %w (tap mode requires provision first)", slotID+1, ErrPortNotProvisioned)
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
			s.mmapSlots.TryRelease(slotID, innerIP)
			return nil, fmt.Errorf("failed to get port netns %s: %w", portNsName, err)
		}
		defer portNs.Close()

		toNs, err := netnsGetByName(opts.ToNetNS)
		if err != nil {
			// Rollback: release the slot
			s.mmapSlots.TryRelease(slotID, innerIP)
			return nil, fmt.Errorf("failed to get target netns %s: %w", opts.ToNetNS, err)
		}
		defer toNs.Close()

		if err := netnsMoveDevice(portName, portNs, toNs); err != nil {
			// Rollback: release the slot
			s.mmapSlots.TryRelease(slotID, innerIP)
			return nil, fmt.Errorf("failed to move %s to %s: %w", portName, opts.ToNetNS, err)
		}
	}

	// Calculate derived values
	floatingIP := bpf.Uint32ToIP(cfg.FloatingIpBase + slotID)
	genevePort := uint16(cfg.GenevePortBase) + uint16(slotID)

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
		out.TransitGeneveVNI = opts.TransitGeneveVNI
	} else {
		out.TransitType = "none"
	}
	return out, nil
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
// Uses atomic CAS on mmap'd BPF map for concurrent-safe slot release.
// The device move is idempotent and performed before the atomic release.
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

	// Atomically release the slot using CAS (currentIP → 0)
	// Note: transit fields are not cleared here to avoid race with concurrent Attach.
	// When InnerIP=0, eBPF ignores these fields; next Attach will overwrite them.
	if !s.mmapSlots.TryRelease(slotID, currentIP) {
		// CAS failed - another process may have detached/reattached
		// Re-read and check if slot is now free or has different IP
		newIP := s.mmapSlots.GetInnerIP(slotID)
		if newIP == 0 {
			// Slot is already free - another detach succeeded
			return nil
		}
		// Slot has different IP - concurrent reattach happened
		return fmt.Errorf("port %d was reattached by another process", opts.Port)
	}

	return nil
}
