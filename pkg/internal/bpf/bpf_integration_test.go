//go:build integration

package bpf_test

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/kuasar-sandbox/connector/pkg/internal/bpf"
	"github.com/kuasar-sandbox/connector/pkg/vswitch"
)

// ensureBPFEnv checks that the BPF integration test environment is ready:
// root privileges, bpffs mounted, memlock rlimit removed.
// Skips the test (instead of failing) when the environment is not available.
func ensureBPFEnv(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	ensureBPFFS(t)
	ensureMemlock(t)
}

// ensureMemlock tries to remove the memlock rlimit. If that fails (e.g. in
// containers), it creates a minimal BPF array map as a probe: on kernel >=5.11
// BPF memory is charged to cgroup, so memlock doesn't matter. Only if the
// probe also fails do we skip.
func ensureMemlock(t *testing.T) {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err == nil {
		return
	}
	// RemoveMemlock failed; probe whether BPF is actually usable.
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	})
	if err != nil {
		t.Skipf("BPF not available (memlock insufficient): %v", err)
	}
	m.Close()
}

// ensureBPFFS ensures /sys/fs/bpf is a mounted bpffs, attempting to mount it if not.
func ensureBPFFS(t *testing.T) {
	t.Helper()
	const bpfFSMagic = 0xCAFE4A11
	var st unix.Statfs_t
	if err := unix.Statfs(bpf.BPFPath, &st); err == nil && st.Type == bpfFSMagic {
		return // already mounted
	}
	// Not mounted — try to create and mount
	if err := os.MkdirAll(bpf.BPFPath, 0755); err != nil {
		t.Skipf("cannot create %s: %v", bpf.BPFPath, err)
	}
	if err := unix.Mount("bpf", bpf.BPFPath, "bpf", 0, ""); err != nil {
		t.Skipf("cannot mount bpffs: %v", err)
	}
}

// TestSlotsMapRoundTrip verifies that SlotItem struct matches BPF slots map layout.
func TestSlotsMapRoundTrip(t *testing.T) {
	ensureBPFEnv(t)

	objs, err := bpf.LoadObjects()
	if err != nil {
		t.Fatalf("LoadObjects: %v", err)
	}
	defer objs.Close()

	// Create a SlotItem with various fields set
	original := vswitch.SlotItem{
		Ifindex:          42,
		InnerIp:          0x0a000001, // 10.0.0.1
		MgmtCidrCount:    1,
		TransitIfindex:   100,
		TransitIp:        0xc0a80001, // 192.168.0.1
		TransitGatewayIp: 0xc0a80101, // 192.168.1.1
		TransitGeneveVni: 12345,
		TransitMac:       [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
	}
	original.MgmtCidrs0 = vswitch.MgmtCIDR{
		Ip:      0x0a000000, // 10.0.0.0
		Mask:    0xff000000, // /8
		Ifindex: 5,
		MgmtMac: [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02},
	}

	// Write to map
	key := uint32(0)
	if err := objs.Maps.Slots.Update(key, &original, ebpf.UpdateAny); err != nil {
		t.Fatalf("Update slots map: %v", err)
	}

	// Read back
	var readBack vswitch.SlotItem
	if err := objs.Maps.Slots.Lookup(key, &readBack); err != nil {
		t.Fatalf("Lookup slots map: %v", err)
	}

	// Verify all fields match
	if readBack.Ifindex != original.Ifindex {
		t.Errorf("Ifindex: got %d, want %d", readBack.Ifindex, original.Ifindex)
	}
	if readBack.InnerIp != original.InnerIp {
		t.Errorf("InnerIp: got %#x, want %#x", readBack.InnerIp, original.InnerIp)
	}
	if readBack.MgmtCidrCount != original.MgmtCidrCount {
		t.Errorf("MgmtCidrCount: got %d, want %d", readBack.MgmtCidrCount, original.MgmtCidrCount)
	}
	if readBack.MgmtCidrs0.Ip != original.MgmtCidrs0.Ip {
		t.Errorf("MgmtCidrs0.Ip: got %#x, want %#x", readBack.MgmtCidrs0.Ip, original.MgmtCidrs0.Ip)
	}
	if readBack.MgmtCidrs0.Mask != original.MgmtCidrs0.Mask {
		t.Errorf("MgmtCidrs0.Mask: got %#x, want %#x", readBack.MgmtCidrs0.Mask, original.MgmtCidrs0.Mask)
	}
	if readBack.MgmtCidrs0.Ifindex != original.MgmtCidrs0.Ifindex {
		t.Errorf("MgmtCidrs0.Ifindex: got %d, want %d", readBack.MgmtCidrs0.Ifindex, original.MgmtCidrs0.Ifindex)
	}
	if readBack.MgmtCidrs0.MgmtMac != original.MgmtCidrs0.MgmtMac {
		t.Errorf("MgmtCidrs0.MgmtMac: got %v, want %v", readBack.MgmtCidrs0.MgmtMac, original.MgmtCidrs0.MgmtMac)
	}
	if readBack.TransitIfindex != original.TransitIfindex {
		t.Errorf("TransitIfindex: got %d, want %d", readBack.TransitIfindex, original.TransitIfindex)
	}
	if readBack.TransitIp != original.TransitIp {
		t.Errorf("TransitIp: got %#x, want %#x", readBack.TransitIp, original.TransitIp)
	}
	if readBack.TransitGatewayIp != original.TransitGatewayIp {
		t.Errorf("TransitGatewayIp: got %#x, want %#x", readBack.TransitGatewayIp, original.TransitGatewayIp)
	}
	if readBack.TransitGeneveVni != original.TransitGeneveVni {
		t.Errorf("TransitGeneveVni: got %d, want %d", readBack.TransitGeneveVni, original.TransitGeneveVni)
	}
	if readBack.TransitMac != original.TransitMac {
		t.Errorf("TransitMac: got %v, want %v", readBack.TransitMac, original.TransitMac)
	}
}

// TestConfigMapRoundTrip verifies that SwitchConfig struct matches BPF config map layout.
func TestConfigMapRoundTrip(t *testing.T) {
	ensureBPFEnv(t)

	objs, err := bpf.LoadObjects()
	if err != nil {
		t.Fatalf("LoadObjects: %v", err)
	}
	defer objs.Close()

	// Create a SwitchConfig with various fields set
	// Note: SwitchNetNS, PortNetNS, TransitDev, MgmtCount moved to SwitchMetadata
	original := vswitch.SwitchConfig{
		SwitchMac:      [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		N_ports:        64,
		FloatingIpBase: 0x64640001, // 100.100.0.1
		GenevePortBase: 6081,
		GeneveEncapEth: 1,
	}

	// Write to map
	key := uint32(0)
	if err := objs.Maps.Config.Update(key, &original, ebpf.UpdateAny); err != nil {
		t.Fatalf("Update config map: %v", err)
	}

	// Read back
	var readBack vswitch.SwitchConfig
	if err := objs.Maps.Config.Lookup(key, &readBack); err != nil {
		t.Fatalf("Lookup config map: %v", err)
	}

	// Verify all fields match
	if readBack.SwitchMac != original.SwitchMac {
		t.Errorf("SwitchMac: got %v, want %v", readBack.SwitchMac, original.SwitchMac)
	}
	if readBack.N_ports != original.N_ports {
		t.Errorf("N_ports: got %d, want %d", readBack.N_ports, original.N_ports)
	}
	if readBack.FloatingIpBase != original.FloatingIpBase {
		t.Errorf("FloatingIpBase: got %#x, want %#x", readBack.FloatingIpBase, original.FloatingIpBase)
	}
	if readBack.GenevePortBase != original.GenevePortBase {
		t.Errorf("GenevePortBase: got %d, want %d", readBack.GenevePortBase, original.GenevePortBase)
	}
	if readBack.GeneveEncapEth != original.GeneveEncapEth {
		t.Errorf("GeneveEncapEth: got %d, want %d", readBack.GeneveEncapEth, original.GeneveEncapEth)
	}

	// Test SwitchMetadata separately (JSON-based)
	originalMeta := &vswitch.SwitchMetadata{
		SwitchNetNS: "test-switch-ns",
		PortNetNS:   "test-port-ns",
		TransitDev:  "eth0",
		MgmtExtracts: []vswitch.MgmtExtractMeta{
			{NetNS: "mgmt-ns-1", Dev: "mgmt0"},
			{NetNS: "mgmt-ns-2", Dev: "mgmt1"},
		},
	}

	if err := vswitch.SaveMetadata(objs.Maps.Metadata, originalMeta); err != nil {
		t.Fatalf("SaveMetadata: %v", err)
	}

	readBackMeta, err := vswitch.LoadMetadata(objs.Maps.Metadata)
	if err != nil {
		t.Fatalf("LoadMetadata: %v", err)
	}

	if readBackMeta.MgmtCount() != 2 {
		t.Errorf("MgmtCount: got %d, want %d", readBackMeta.MgmtCount(), 2)
	}
	if readBackMeta.SwitchNetnsName() != "test-switch-ns" {
		t.Errorf("SwitchNetnsName: got %q, want %q", readBackMeta.SwitchNetnsName(), "test-switch-ns")
	}
	if readBackMeta.PortNetnsName() != "test-port-ns" {
		t.Errorf("PortNetnsName: got %q, want %q", readBackMeta.PortNetnsName(), "test-port-ns")
	}
	if readBackMeta.TransitDevName() != "eth0" {
		t.Errorf("TransitDevName: got %q, want %q", readBackMeta.TransitDevName(), "eth0")
	}
}
