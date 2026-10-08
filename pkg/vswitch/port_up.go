package vswitch

import (
	"fmt"
	"sync/atomic"

	"github.com/kuasar-sandbox/connector/pkg/internal/bpf"
)

// SetPortUp replaces a completed down attachment's entire network configuration.
// Nil gateway/MAC and empty options clear provisional values; they are not a patch.
// Calls for one attachment are ordered by its owner; this takes no lifecycle lock.
// Failed preparation leaves down intact. Transport failure after success is not
// rollback: inspect the port instead of assuming a lost reply means it is down.
func SetPortUp(switchName string, opts PortUpOptions) error {
	sw, err := Open(switchName)
	if err != nil {
		return err
	}
	defer sw.Close()
	return sw.SetPortUp(opts)
}

func (s *switchContext) SetPortUp(opts PortUpOptions) error {
	if opts.Port <= 0 || uint64(opts.Port) > uint64(s.cfg.N_ports) {
		return fmt.Errorf("port %d: %w", opts.Port, ErrPortOutOfRange)
	}
	if err := s.requireDeferredAttachmentABI(); err != nil {
		return err
	}
	id := uint32(opts.Port - 1)
	current := s.mmapSlots.GetInnerIP(id)
	if !IsSlotAllocated(current) {
		return fmt.Errorf("port %d: %w", opts.Port, ErrPortNotAttached)
	}
	slot := s.mmapSlots.GetSlot(id)
	if atomic.LoadUint32(&slot.Flags)&PortFUp != 0 {
		return fmt.Errorf("port %d is already up", opts.Port)
	}
	newIP, err := validateAttachmentAddresses(opts.InnerIP, opts.TransitGatewayIP, opts.TransitMAC)
	if err != nil {
		return err
	}
	locator := geneveLocatorFromConfig(s.cfg)
	if !locator.valid() {
		return fmt.Errorf("invalid GENEVE locator %d", s.cfg.GeneveLocator)
	}
	if err := validateTransitGeneveVNI(locator, opts.TransitGeneveVNI); err != nil {
		return err
	}
	var tlv *GeneveTLVLocator
	if locator == GeneveLocatorTLV {
		value := geneveTLVLocatorFromConfig(s.cfg)
		tlv = &value
	}
	value, wireLen, err := marshalGeneveOptions(locator, tlv, opts.TransitGeneveOpts)
	if err != nil {
		return err
	}
	// Match Attach's wire-option MTU rules; no new netns dependency for an
	// option-free configuration. The switch-side peer remains in switch-netns.
	if wireLen != 0 {
		if err := validateAttachMTUFn(s, id, SlotPortKind(slot), int(wireLen)); err != nil {
			return err
		}
	}
	if s.mmapSlots.GetInnerIP(id) != current {
		return fmt.Errorf("port %d was taken over during set-port-up", opts.Port)
	}
	if err := writeGeneveOptsFn(s.maps.GeneveOpts, id, &value); err != nil {
		return err
	}
	// Administrative takeover may occur during a map syscall. Do not continue
	// after observing it; Reserved reopening is a separate management boundary.
	if s.mmapSlots.GetInnerIP(id) != current {
		return fmt.Errorf("port %d was taken over during set-port-up", opts.Port)
	}
	s.mmapSlots.UpdateSlotFields(id, func(item *SlotItem) {
		item.GeneveOptsLen = value.Len
		item.TransitGatewayIp = bpf.IPToUint32(opts.TransitGatewayIP)
		item.TransitGeneveVni = opts.TransitGeneveVNI
		item.ClearTransitMac()
		if len(opts.TransitMAC) >= 6 {
			item.SetTransitMacAddr(opts.TransitMAC)
		}
	})
	// Changing InnerIP within Allocated/down does not release the slot.
	if !s.mmapSlots.TryUpdateInnerIP(id, current, newIP) {
		return fmt.Errorf("port %d ownership changed during set-port-up", opts.Port)
	}
	if s.mmapSlots.GetInnerIP(id) != newIP {
		return fmt.Errorf("port %d was taken over during set-port-up", opts.Port)
	}
	// Neither attachment generation nor stats readiness/counter generation is
	// reset: this is the same attachment. Up is the only forwarding publication.
	atomic.StoreUint32(&slot.Flags, PortFUp)
	return nil
}

// The #81 dataplane understands up/down but may cache InnerIP before testing
// up. Deferred A-to-B commit requires an ordered publication reader as well.
// This bit is in the existing config capability byte; no map/slot layout grows.
func (s *switchContext) requireDeferredAttachmentABI() error {
	if err := s.requireAttachmentABI(); err != nil {
		return err
	}
	if s.cfg.Features&SwitchFDeferredUp == 0 {
		return fmt.Errorf("switch %s lacks deferred-port publication support; rebuild the switch", s.name)
	}
	return nil
}
