package vswitch

import (
	"fmt"

	"github.com/cilium/ebpf"

	"github.com/kuasar-sandbox/sandbox-vswitch/pkg/internal/bpf"
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
