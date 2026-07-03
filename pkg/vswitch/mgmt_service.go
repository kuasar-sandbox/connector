package vswitch

import (
	"fmt"

	"github.com/cilium/ebpf"

	"github.com/kuasar-sandbox/connector/pkg/internal/bpf"
)

// Type aliases for the management-service NAT map entries.
type (
	SvcKey = bpf.SvcKey
	SvcVal = bpf.SvcVal
)

// svcProtos is the set of L4 protocols a service is installed for. The CLI
// syntax carries no protocol, so each service translates both TCP and UDP.
var svcProtos = []uint8{svcProtoTCP, svcProtoUDP}

const (
	svcProtoTCP = 6  // IPPROTO_TCP
	svcProtoUDP = 17 // IPPROTO_UDP
)

// toInfo converts a MgmtService to its output view.
func (s *MgmtService) toInfo() MgmtServiceInfo {
	return MgmtServiceInfo{
		VIP:        s.VIP.String(),
		VPort:      s.VPort,
		TargetIP:   s.TargetIP.String(),
		TargetPort: s.TargetPort,
		Protocols:  "tcp,udp",
	}
}

// MgmtServiceInfos builds output views from a parsed service list (start path).
func MgmtServiceInfos(svcs []*MgmtService) []MgmtServiceInfo {
	if len(svcs) == 0 {
		return nil
	}
	out := make([]MgmtServiceInfo, 0, len(svcs))
	for _, s := range svcs {
		out = append(out, s.toInfo())
	}
	return out
}

// MgmtServiceInfosFromStrings builds output views from the canonical service
// strings stored in switch metadata (status / show / re-open paths). Malformed
// entries are skipped rather than failing the whole listing.
func MgmtServiceInfosFromStrings(ss []string) []MgmtServiceInfo {
	if len(ss) == 0 {
		return nil
	}
	out := make([]MgmtServiceInfo, 0, len(ss))
	for _, s := range ss {
		svc, err := ParseMgmtService(s)
		if err != nil {
			continue
		}
		out = append(out, svc.toInfo())
	}
	return out
}

// WriteMgmtServices populates the egress (fwd) and ingress (rev) management
// service NAT maps from the configured services. Keys and values are stored in
// host byte order (matching the mgmt_cidr convention); the datapath converts at
// the packet boundary. Each service is installed for both TCP and UDP.
//
// fwd: {VIP, vport, proto}        -> {targetIP, targetPort}
// rev: {targetIP, targetPort, proto} -> {VIP, vport}
func WriteMgmtServices(fwd, rev BPFMap, services []*MgmtService) error {
	for _, svc := range services {
		vip := bpf.IPToUint32(svc.VIP)
		target := bpf.IPToUint32(svc.TargetIP)

		for _, proto := range svcProtos {
			fwdKey := SvcKey{Ip: vip, Port: svc.VPort, Proto: proto}
			fwdVal := SvcVal{Ip: target, Port: svc.TargetPort}
			if err := fwd.Update(&fwdKey, &fwdVal, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("write mgmt-service fwd %s proto=%d: %w", svc.String(), proto, err)
			}

			revKey := SvcKey{Ip: target, Port: svc.TargetPort, Proto: proto}
			revVal := SvcVal{Ip: vip, Port: svc.VPort}
			if err := rev.Update(&revKey, &revVal, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("write mgmt-service rev %s proto=%d: %w", svc.String(), proto, err)
			}
		}
	}
	return nil
}
