//go:build integration

package bpf_test

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/kuasar-sandbox/connector/pkg/internal/bpf"
	"github.com/kuasar-sandbox/connector/pkg/vswitch"
)

// Exercise the public SDK against the same real maps read by production TC.
func TestDeferredAttachmentDataPlaneCommit(t *testing.T) {
	ensureBPFEnv(t)
	objs, err := bpf.LoadObjects()
	if err != nil {
		t.Fatal(err)
	}
	defer objs.Close()
	testSetupMaps(t, objs)
	name := fmt.Sprintf("test-i80-packets-%d", os.Getpid())
	createPinDir(t, name)
	defer bpf.UnpinMaps(name)
	if err := objs.PinMaps(name); err != nil {
		t.Fatal(err)
	}
	if err := vswitch.SaveMetadata(objs.Maps.Metadata, &vswitch.SwitchMetadata{}); err != nil {
		t.Fatal(err)
	}
	var cfg vswitch.SwitchConfig
	if err := objs.Maps.Config.Lookup(uint32(0), &cfg); err != nil {
		t.Fatal(err)
	}
	cfg.GenerationBits = 4
	cfg.Features |= vswitch.SwitchFDeferredUp
	if err := objs.Maps.Config.Update(uint32(0), &cfg, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	var provisioned vswitch.SlotItem
	if err := objs.Maps.Slots.Lookup(uint32(0), &provisioned); err != nil {
		t.Fatal(err)
	}
	provisioned.InnerIp = vswitch.InnerIPFree
	provisioned.Flags = 0
	if err := objs.Maps.Slots.Update(uint32(0), &provisioned, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	sw, err := vswitch.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer sw.Close()
	initial := net.ParseIP("169.254.1.1")
	final := net.ParseIP("169.254.2.2")
	out, err := sw.Attach(vswitch.AttachOptions{Port: 1, Generation: 3, InnerIP: initial, AdminDown: true, SkipDevice: true})
	if err != nil || !out.AdminDown {
		t.Fatal(out, err)
	}
	floating := net.ParseIP(out.FloatingIP)
	if !floating.Equal(bpf.Uint32ToIP(vswitch.FloatingIPForAttachment(cfg.FloatingIpBase, 0, 3))) {
		t.Fatal("floating generation lost", out)
	}
	counters := func() vswitch.SlotStats {
		t.Helper()
		var v vswitch.SlotStats
		if err := objs.Maps.Stats.LookupWithFlags(uint32(0), &v, ebpf.LookupLock); err != nil {
			t.Fatal(err)
		}
		return v
	}
	before := counters()
	if result, err := sw.Stats([]int{1}); result != nil || !errors.Is(err, vswitch.ErrStatsUnavailable) {
		t.Fatal("down port returned live stats", result, err)
	}
	mgmt := net.ParseIP("169.254.169.254")
	external := net.ParseIP("8.8.8.8")
	mac := [6]byte{2, 0, 0, 0, 0, 1}
	inner := buildIPv4UDPPacket(mac, testSwitchMAC, external, initial, 53, 1234, []byte("reply"))
	paths := []struct {
		name string
		prog *ebpf.Program
		pkt  []byte
	}{
		{"sandbox egress", objs.Programs.IngressNX, buildIPv4UDPPacket(mac, testSwitchMAC, initial, external, 1234, 53, []byte("query"))},
		{"management ARP", objs.Programs.IngressMX, buildARPRequest(mac, mgmt, floating)},
		{"management IPv4", objs.Programs.IngressMX, buildIPv4UDPPacket(mac, testSwitchMAC, mgmt, floating, 80, 1234, []byte("reply"))},
		{"transit ingress", objs.Programs.IngressTransit, buildGenevePacket(mac, testSwitchMAC, net.ParseIP("192.168.10.2"), net.ParseIP("192.168.10.1"), 49152, testGenevePortBase, 12345, GeneveProtoTEB, inner)},
	}
	for _, p := range paths {
		t.Run(p.name, func(t *testing.T) {
			ret, _, err := p.prog.Test(p.pkt)
			if err != nil || ret != TCActShot {
				t.Fatal("deferred traffic not dropped", ret, err)
			}
		})
	}
	if after := counters(); after != before {
		t.Fatal("down traffic changed counters", before, after)
	}
	option := vswitch.GeneveOption{Class: 0x102, Type: 2, Data: []byte{1, 2, 3, 4}}
	gateway := net.ParseIP("192.168.10.3")
	lock, err := vswitch.AcquireControlLock(name)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	done := make(chan error, 1)
	go func() {
		done <- sw.SetPortUp(vswitch.PortUpOptions{Port: 1, InnerIP: final, TransitGatewayIP: gateway, TransitGeneveVNI: 4242, TransitGeneveOpts: []vswitch.GeneveOption{option}, TransitMAC: net.HardwareAddr{2, 0, 0, 0, 0, 9}})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		lock.Release()
		<-done
		t.Fatal("SetPortUp blocked on management EX")
	}
	lock.Release()
	if after := counters(); after != before {
		t.Fatal("SetPortUp reset counter instance", before, after)
	}
	slot := sw.MmapSlots().GetSlot(0)
	if slot.Ifindex != provisioned.Ifindex || slot.Generation != 3 || slot.Flags != vswitch.PortFUp {
		t.Fatal("identity/publication changed", slot)
	}
	// The first permitted management packet must target final B, never provisional A.
	ret, packet, err := objs.Programs.IngressMX.Test(paths[2].pkt)
	if err != nil || ret != TCActRedirect {
		t.Fatal("management not enabled", ret, err)
	}
	ip, err := parseIPHeader(packet)
	if err != nil || !ip.DstIP.Equal(final) {
		t.Fatal("DNAT did not use final InnerIP", ip, err)
	}
	// Check actual final GENEVE wire bytes, not only the userspace slot values.
	_, packet, err = objs.Programs.IngressNX.Test(buildIPv4UDPPacket(mac, testSwitchMAC, final, external, 1234, 53, []byte("query")))
	if err != nil {
		t.Fatal(err)
	}
	outer, err := parseIPHeader(packet)
	if err != nil || !outer.DstIP.Equal(gateway) {
		t.Fatal("final gateway", outer, err)
	}
	geneve, err := parseGeneveHeader(packet)
	if err != nil || geneve.VNI != 4242 {
		t.Fatal("final VNI", geneve, err)
	}
	offset := EthHdrLen + IPHdrLen + UDPHdrLen + GeneveHdrLen
	expected := wireGeneveOption(option.Class, option.Type, option.Data)
	if len(packet) < offset+len(expected) || !bytes.Equal(packet[offset:offset+len(expected)], expected) {
		t.Fatal("final GENEVE options missing")
	}
	if result, err := sw.Stats([]int{1}); err != nil || result.Ports[0].InnerIP != final.String() || result.Ports[0].Generation != 3 {
		t.Fatal("final stats identity", result, err)
	}
	if err := sw.Detach(vswitch.DetachOptions{Port: 1, SkipDevice: true}); err != nil {
		t.Fatal(err)
	}
	if sw.MmapSlots().GetInnerIP(0) != vswitch.InnerIPFree {
		t.Fatal("detach after address change")
	}
}
