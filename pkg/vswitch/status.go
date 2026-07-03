package vswitch

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/kuasar-sandbox/connector/pkg/internal/bpf"
	"github.com/kuasar-sandbox/connector/pkg/netlink"
	"github.com/kuasar-sandbox/connector/pkg/netns"
)

// Status returns the status of a virtual switch.
func Status(switchName string) (*StatusOutput, error) {
	sw, err := Open(switchName)
	if err != nil {
		return nil, err
	}
	defer sw.Close()
	return sw.Status()
}

// Status implements Interface.Status.
// Returns the switch status using the pre-loaded context.
func (s *switchContext) Status() (*StatusOutput, error) {
	cfg := s.cfg
	meta := s.meta
	used := s.mmapSlots.CountAllocatedSlots()
	reserved := s.mmapSlots.CountReservedSlots()
	free := s.mmapSlots.CountFreeSlots()

	output := &StatusOutput{
		Switch:         s.name,
		State:          "running",
		SwitchNetNS:    meta.SwitchNetnsName(),
		PortNetNS:      meta.PortNetnsName(),
		Ports:          cfg.N_ports,
		PortsUsed:      used,
		PortsAvailable: free,
		PortsReserved:  reserved,
		MgmtPlanes:     meta.MgmtPlaneInfos(),
		MgmtServices:   meta.MgmtServiceInfos(),
		TransitDev:     meta.TransitDevName(),
		TransitDevIP:   meta.TransitDevAddrStr(),
	}

	// Check conditions in switch namespace
	switchNetNSName := meta.SwitchNetnsName()
	transitDevName := meta.TransitDevName()

	if switchNetNSName != "" {
		switchNs, err := netnsGetByName(switchNetNSName)
		if err == nil {
			defer switchNs.Close()
			conditions, err := checkConditions(s.name, cfg, meta, switchNs, transitDevName, s.mmapSlots)
			if err != nil {
				return nil, fmt.Errorf("check conditions: %w", err)
			}
			output.Conditions = conditions
		} else {
			// Switch namespace not found - all conditions unknown
			output.Conditions = []Condition{
				{Type: ConditionReady, Status: ConditionUnknown, Reason: "NamespaceNotFound", Message: fmt.Sprintf("switch netns %s not found", switchNetNSName)},
			}
		}
	}

	return output, nil
}

// portCheck holds slot ID and port ifindex for status checking.
type portCheck struct {
	slotID      uint32
	portIfindex int // 0 = device missing (no ifindex in slot)
}

// buildPortsToCheck reads slot states and extracts ifindex info for non-Reserved slots.
// Returns port checks, deduplicated mgmt ifindexes, and deduplicated transit ifindexes.
// All slot reads happen BEFORE netnsDoFn/LinkList to avoid race with provisioning.
func buildPortsToCheck(numPorts uint32, mmapSlots *MmappedSlots) ([]portCheck, map[int]struct{}, map[int]struct{}) {
	var ports []portCheck
	mgmtIfindexes := make(map[int]struct{})
	transitIfindexes := make(map[int]struct{})

	for i := uint32(0); i < numPorts; i++ {
		if mmapSlots != nil && mmapSlots.GetInnerIP(i) == InnerIPReserved {
			continue
		}

		pc := portCheck{slotID: i}
		if mmapSlots != nil {
			slot := mmapSlots.GetSlot(i)
			pc.portIfindex = int(slot.Ifindex)

			// Collect mgmt ifindexes from MgmtCidrs0 and MgmtCidrsExt
			if slot.MgmtCidrCount > 0 && slot.MgmtCidrs0.Ifindex != 0 {
				mgmtIfindexes[int(slot.MgmtCidrs0.Ifindex)] = struct{}{}
			}
			for j := uint32(1); j < slot.MgmtCidrCount && j <= uint32(MaxMgmtCIDRExt); j++ {
				if slot.MgmtCidrsExt[j-1].Ifindex != 0 {
					mgmtIfindexes[int(slot.MgmtCidrsExt[j-1].Ifindex)] = struct{}{}
				}
			}

			// Collect transit ifindex
			if slot.TransitIfindex != 0 {
				transitIfindexes[int(slot.TransitIfindex)] = struct{}{}
			}
		}
		ports = append(ports, pc)
	}

	return ports, mgmtIfindexes, transitIfindexes
}

// checkConditions performs all health checks in the switch namespace.
// All netlink operations are done inside a single netnsDoFn call: one LinkList
// builds nsIfindexMap, then all check functions use it — avoiding per-port netlink queries.
func checkConditions(switchName string, cfg *SwitchConfig, meta *SwitchMetadata, switchNs *netns.NetNS, transitDev string, mmapSlots *MmappedSlots) ([]Condition, error) {
	var portCond, mgmtCond, transitCond Condition

	// Read slot states BEFORE LinkList to avoid race with provisioning.
	// Provisioning order: create device → CAS(Reserved→Free).
	// By reading slots first, a non-Reserved slot guarantees its device already exists.
	portsToCheck, mgmtIfindexes, transitIfindexes := buildPortsToCheck(cfg.N_ports, mmapSlots)
	hasMgmt := len(mgmtIfindexes) > 0
	hasTransit := len(transitIfindexes) > 0

	var reservedCount uint32
	if mmapSlots != nil {
		reservedCount = mmapSlots.CountReservedSlots()
	}

	if err := netnsDoFn(switchNs, func() error {
		// One LinkList for all checks
		links, err := netlinkLinkList()
		if err != nil && !errors.Is(err, netlink.ErrDumpInterrupted) {
			return err
		}
		// err == ErrDumpInterrupted: use partial links and continue
		nsIfindexMap := make(map[int]netlink.Link, len(links))
		for _, l := range links {
			nsIfindexMap[l.Attrs().Index] = l
		}

		// All checks use nsIfindexMap (TC FilterList calls also happen here, in ns context)
		portCond = checkPortDevices(portsToCheck, nsIfindexMap)
		if hasMgmt {
			mgmtCond = checkMgmtDevices(mgmtIfindexes, nsIfindexMap)
		}
		if hasTransit {
			transitCond = checkTransitDevice(transitIfindexes, nsIfindexMap)
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("check devices in switch namespace: %w", err)
	}

	var conditions []Condition
	allReady := true

	conditions = append(conditions, portCond)
	if portCond.Status != ConditionTrue {
		allReady = false
	}

	if hasMgmt {
		conditions = append(conditions, mgmtCond)
		if mgmtCond.Status != ConditionTrue {
			allReady = false
		}
	}

	if hasTransit {
		conditions = append(conditions, transitCond)
		if transitCond.Status != ConditionTrue {
			allReady = false
		}
	}

	// PortReserved condition (informational, does not affect Ready)
	if reservedCount > 0 {
		conditions = append(conditions, Condition{
			Type:    ConditionPortReserved,
			Status:  ConditionTrue,
			Message: fmt.Sprintf("%d ports reserved", reservedCount),
		})
	}

	// Build Ready condition (summary) - prepend to list
	readyCondition := Condition{Type: ConditionReady}
	if allReady {
		readyCondition.Status = ConditionTrue
	} else {
		readyCondition.Status = ConditionFalse
	}
	conditions = append([]Condition{readyCondition}, conditions...)

	return conditions, nil
}

// checkPortDevices checks port devices by ifindex from slot data.
// Uses nsIfindexMap for existence/state checks and shared block filter for TC check.
func checkPortDevices(portsToCheck []portCheck, nsIfindexMap map[int]netlink.Link) Condition {
	if len(portsToCheck) == 0 {
		return Condition{Type: ConditionPortDevicesReady, Status: ConditionTrue, Message: "0 ports to check (all reserved)"}
	}

	var missingDevices, downDevices []string
	upCount := 0

	for _, pc := range portsToCheck {
		if pc.portIfindex == 0 {
			missingDevices = append(missingDevices, fmt.Sprintf("port%d(no ifindex)", pc.slotID+1))
			continue
		}
		link, ok := nsIfindexMap[pc.portIfindex]
		if !ok {
			missingDevices = append(missingDevices, fmt.Sprintf("port%d(ifindex=%d)", pc.slotID+1, pc.portIfindex))
			continue
		}
		if link.Attrs().Flags&net.FlagUp == 0 {
			downDevices = append(downDevices, link.Attrs().Name)
			continue
		}
		upCount++
	}

	total := len(portsToCheck)
	if len(missingDevices) > 0 {
		return Condition{
			Type:    ConditionPortDevicesReady,
			Status:  ConditionFalse,
			Reason:  "DevicesMissing",
			Message: fmt.Sprintf("%d/%d ready, %s", total-len(missingDevices)-len(downDevices), total, formatMissingList("missing", missingDevices)),
		}
	}
	if len(downDevices) > 0 {
		return Condition{
			Type:    ConditionPortDevicesReady,
			Status:  ConditionFalse,
			Reason:  "DevicesDown",
			Message: fmt.Sprintf("%d/%d ready, %s", total-len(downDevices), total, formatMissingList("DOWN", downDevices)),
		}
	}

	// Check shared block filter (1 FilterList instead of N per-port checks)
	if upCount > 0 && !netlinkHasBlockFilter(PortIngressBlockID) {
		return Condition{
			Type:    ConditionPortDevicesReady,
			Status:  ConditionFalse,
			Reason:  "TCFilterMissing",
			Message: "shared ingress block filter missing",
		}
	}

	return Condition{Type: ConditionPortDevicesReady, Status: ConditionTrue}
}

// checkMgmtDevices checks mgmt devices by ifindex using nsIfindexMap.
func checkMgmtDevices(mgmtIfindexes map[int]struct{}, nsIfindexMap map[int]netlink.Link) Condition {
	var missingDevices, downDevices, missingTC []string

	for ifindex := range mgmtIfindexes {
		link, ok := nsIfindexMap[ifindex]
		if !ok {
			missingDevices = append(missingDevices, fmt.Sprintf("mgmt(ifindex=%d)", ifindex))
			continue
		}
		devName := link.Attrs().Name
		if link.Attrs().Flags&net.FlagUp == 0 {
			downDevices = append(downDevices, devName)
			continue
		}
		if !netlinkHasTCFilter(link, netlink.Ingress) {
			missingTC = append(missingTC, devName)
		}
	}

	if len(missingDevices) > 0 {
		return Condition{
			Type:    ConditionMgmtDevicesReady,
			Status:  ConditionFalse,
			Reason:  "DevicesMissing",
			Message: formatMissingList("missing", missingDevices),
		}
	}
	if len(downDevices) > 0 {
		return Condition{
			Type:    ConditionMgmtDevicesReady,
			Status:  ConditionFalse,
			Reason:  "DevicesDown",
			Message: formatMissingList("DOWN", downDevices),
		}
	}
	if len(missingTC) > 0 {
		return Condition{
			Type:    ConditionMgmtDevicesReady,
			Status:  ConditionFalse,
			Reason:  "TCFilterMissing",
			Message: formatMissingList("missing TC", missingTC),
		}
	}
	return Condition{Type: ConditionMgmtDevicesReady, Status: ConditionTrue}
}

// checkTransitDevice checks transit devices by ifindex using nsIfindexMap.
func checkTransitDevice(transitIfindexes map[int]struct{}, nsIfindexMap map[int]netlink.Link) Condition {
	var missingDevices, downDevices, missingTC []string

	for ifindex := range transitIfindexes {
		link, ok := nsIfindexMap[ifindex]
		if !ok {
			missingDevices = append(missingDevices, fmt.Sprintf("transit(ifindex=%d)", ifindex))
			continue
		}
		devName := link.Attrs().Name
		if link.Attrs().OperState != netlink.OperUp {
			downDevices = append(downDevices, devName)
			continue
		}
		if !netlinkHasTCFilter(link, netlink.Ingress) {
			missingTC = append(missingTC, devName)
		}
	}

	if len(missingDevices) > 0 {
		return Condition{
			Type:    ConditionTransitDeviceReady,
			Status:  ConditionFalse,
			Reason:  "DeviceMissing",
			Message: formatMissingList("missing", missingDevices),
		}
	}
	if len(downDevices) > 0 {
		return Condition{
			Type:    ConditionTransitDeviceReady,
			Status:  ConditionFalse,
			Reason:  "DeviceDown",
			Message: formatMissingList("DOWN", downDevices),
		}
	}
	if len(missingTC) > 0 {
		return Condition{
			Type:    ConditionTransitDeviceReady,
			Status:  ConditionFalse,
			Reason:  "TCFilterMissing",
			Message: formatMissingList("missing TC", missingTC),
		}
	}
	return Condition{Type: ConditionTransitDeviceReady, Status: ConditionTrue}
}

// formatMissingList formats a list of missing items for condition message.
func formatMissingList(prefix string, items []string) string {
	if len(items) <= 3 {
		return fmt.Sprintf("%d %s: %s", len(items), prefix, strings.Join(items, ", "))
	}
	return fmt.Sprintf("%d %s: %s, ... (+%d more)", len(items), prefix, strings.Join(items[:3], ", "), len(items)-3)
}

// IsReady returns true if all conditions are True.
func (s *StatusOutput) IsReady() bool {
	for _, c := range s.Conditions {
		if c.Type == ConditionReady {
			return c.Status == ConditionTrue
		}
	}
	return false
}

// GetNotReadyReasons returns a summary of why the switch is not ready.
func (s *StatusOutput) GetNotReadyReasons() string {
	var reasons []string
	for _, c := range s.Conditions {
		if c.Type != ConditionReady && c.Status != ConditionTrue {
			reasons = append(reasons, fmt.Sprintf("%s=%s", c.Type, c.Status))
		}
	}
	return strings.Join(reasons, ", ")
}

// Stats returns traffic statistics for the specified ports.
// If ports is empty, returns stats for all allocated ports.
func Stats(switchName string, ports []int) (*StatsOutput, error) {
	sw, err := Open(switchName)
	if err != nil {
		return nil, err
	}
	defer sw.Close()
	return sw.Stats(ports)
}

// Stats implements Interface.Stats.
// Returns port statistics using the pre-loaded context.
func (s *switchContext) Stats(ports []int) (*StatsOutput, error) {
	cfg := s.cfg

	// Determine which slots to query
	var slotIDs []uint32
	if len(ports) > 0 {
		for _, p := range ports {
			sid := uint32(p - 1)
			if sid >= cfg.N_ports {
				return nil, fmt.Errorf("port %d out of range (max %d)", p, cfg.N_ports)
			}
			slotIDs = append(slotIDs, sid)
		}
	} else {
		// All allocated ports
		for i := uint32(0); i < cfg.N_ports; i++ {
			if s.mmapSlots.GetInnerIP(i) != 0 {
				slotIDs = append(slotIDs, i)
			}
		}
	}

	out := &StatsOutput{
		Switch: s.name,
		Ports:  []PortStatsOutput{},
	}

	for _, sid := range slotIDs {
		slot := s.mmapSlots.GetSlot(sid)
		st, err := s.statsMgr.GetStats(sid)
		if err != nil {
			return nil, err
		}
		// Use GetPortMAC to get fixed or per-port derived MAC
		portMAC := GetPortMAC(cfg.SwitchMac[:], cfg.PortMac[:], sid)
		out.Ports = append(out.Ports, PortStatsOutput{
			Port:             sid + 1,
			InnerIP:          bpf.Uint32ToIP(slot.InnerIp).String(),
			FloatingIP:       bpf.Uint32ToIP(cfg.FloatingIpBase + sid).String(),
			PortMAC:          portMAC.String(),
			MgmtRxPackets:    st.MgmtRxPackets,
			MgmtRxBytes:      st.MgmtRxBytes,
			MgmtTxPackets:    st.MgmtTxPackets,
			MgmtTxBytes:      st.MgmtTxBytes,
			TransitRxPackets: st.TransitRxPackets,
			TransitRxBytes:   st.TransitRxBytes,
			TransitTxPackets: st.TransitTxPackets,
			TransitTxBytes:   st.TransitTxBytes,
		})
	}

	return out, nil
}
