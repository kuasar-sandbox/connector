//go:build integration

package bpf_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/kuasar-sandbox/connector/pkg/internal/bpf"
	"github.com/kuasar-sandbox/connector/pkg/vswitch"
)

func TestGeneveTransitFencing(t *testing.T) {
	ensureBPFEnv(t)
	objects, err := bpf.LoadObjects()
	if err != nil {
		t.Fatal(err)
	}
	defer objects.Close()
	for _, locator := range []vswitch.GeneveLocator{vswitch.GeneveLocatorPort, vswitch.GeneveLocatorVNI, vswitch.GeneveLocatorTLV} {
		for _, generation := range []uint32{0, 1, 15, 1048575} {
			t.Run(fmt.Sprintf("locator-%d/generation-%d", locator, generation), func(t *testing.T) {
				logicalVNI := uint32(7)
				wireVNI := logicalVNI
				port := uint16(testGenevePortBase + geneveTestSlotID)
				var options []byte
				if locator == vswitch.GeneveLocatorVNI {
					port = vswitch.GeneveStandardPort
					wireVNI = geneveTestSlotID<<12 | logicalVNI
				}
				if locator == vswitch.GeneveLocatorTLV {
					port = vswitch.GeneveStandardPort
					options = wireGeneveLocator(0x102, 0x81, geneveTestSlotID)
				}
				testSetupGeneveMaps(t, objects, locator, 0x102, 0x81, true, logicalVNI, nil, false)
				var cfg vswitch.SwitchConfig
				if err := objects.Maps.Config.Lookup(uint32(0), &cfg); err != nil {
					t.Fatal(err)
				}
				cfg.GenerationBits = 20
				if err := objects.Maps.Config.Update(uint32(0), &cfg, ebpf.UpdateAny); err != nil {
					t.Fatal(err)
				}
				var slot vswitch.SlotItem
				if err := objects.Maps.Slots.Lookup(geneveTestSlotID, &slot); err != nil {
					t.Fatal(err)
				}
				slot.Generation = generation
				if err := objects.Maps.Slots.Update(geneveTestSlotID, &slot, ebpf.UpdateAny); err != nil {
					t.Fatal(err)
				}
				guestMAC := [6]byte{2, 0, 0, 0, 0x80, 1}
				packet := buildIPv4UDPPacket(guestMAC, testSwitchMAC, net.ParseIP("10.1.0.2"), net.ParseIP("8.8.8.8"), 31000, 53, []byte("fenced"))
				original := bytes.Clone(packet)
				action, out, err := objects.Programs.IngressNX.Test(packet)
				if err != nil || action != TCActRedirect {
					t.Fatalf("outbound action %d: %v", action, err)
				}
				offset := EthHdrLen + IPHdrLen + UDPHdrLen + GeneveHdrLen + len(options)
				alias := []byte{2, 0xfe, 0, 0, 0, 0}
				binary.BigEndian.PutUint32(alias[2:], generation)
				if !bytes.Equal(out[offset+6:offset+12], alias) {
					t.Fatalf("wrong wire generation MAC %x", out[offset+6:offset+12])
				}
				if !bytes.Equal(packet, original) {
					t.Fatal("modified caller's Guest frame")
				}
				reply := buildGeneveReturnPacket(port, wireVNI, locator == vswitch.GeneveLocatorTLV, options, net.ParseIP("192.0.2.2"), true)
				copy(reply[offset:offset+6], alias)
				action, out, err = objects.Programs.IngressTransit.Test(reply)
				if err != nil || action != TCActRedirect {
					t.Fatalf("current return action %d: %v", action, err)
				}
				expectedMAC := portMAC(testSwitchMAC, geneveTestSlotID)
				if !bytes.Equal(out[:6], expectedMAC[:]) {
					t.Fatalf("Guest MAC not restored: %x", out[:6])
				}
				binary.BigEndian.PutUint32(reply[offset+2:offset+6], generation^1)
				action, _, err = objects.Programs.IngressTransit.Test(reply)
				if err != nil || action != TCActShot {
					t.Fatalf("stale return action %d: %v", action, err)
				}
				copy(reply[offset:offset+6], guestMAC[:])
				action, _, err = objects.Programs.IngressTransit.Test(reply)
				if err != nil || action != TCActRedirect {
					t.Fatalf("legacy return action %d: %v", action, err)
				}
			})
		}
	}
}
