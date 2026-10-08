package vswitch

import (
	"fmt"
	"sync/atomic"

	"github.com/kuasar-sandbox/connector/pkg/internal/bpf"
)

// SetPortUp commits a down attachment's final network parameters and enables traffic.
func SetPortUp(switchName string, opts PortUpOptions) error {
	sw, err := Open(switchName)
	if err != nil {
		return err
	}
	defer sw.Close()
	return sw.SetPortUp(opts)
}

func (s *switchContext) SetPortUp(opts PortUpOptions) error {
	if opts.Port <= 0 || uint32(opts.Port) > s.cfg.N_ports {
		return fmt.Errorf("port %d: %w", opts.Port, ErrPortOutOfRange)
	}
	if err := s.requireAttachmentABI(); err != nil {
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
	newIP := bpf.IPToUint32(opts.InnerIP)
	if newIP == InnerIPFree || newIP == InnerIPReserved {
		return fmt.Errorf("invalid final inner-ip")
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
	if err := validateAttachMTUFn(s, id, SlotPortKind(slot), int(wireLen)); err != nil {
		return err
	}
	if s.mmapSlots.GetInnerIP(id) != current {
		return fmt.Errorf("port %d was taken over during set-port-up", opts.Port)
	}
	if err := writeGeneveOptsFn(s.maps.GeneveOpts, id, &value); err != nil {
		return err
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
	atomic.StoreUint32(&s.mmapSlots.GetSlot(id).Flags, PortFUp)
	return nil
}
