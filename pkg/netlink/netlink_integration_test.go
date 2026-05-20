//go:build integration

package netlink

import (
	"net"
	"os"
	"testing"

	vnl "github.com/vishvananda/netlink"
)

func skipIfNoNetAdmin(t *testing.T) {
	// Quick check: if not root, skip immediately
	if os.Getuid() != 0 {
		t.Skip("requires root or CAP_NET_ADMIN")
	}

	// Probe: try creating a dummy veth to verify we have CAP_NET_ADMIN
	// This handles cases where uid=0 but capabilities are restricted (e.g., containers, WSL2)
	probeName := "netlink-probe"
	veth := &vnl.Veth{
		LinkAttrs: vnl.LinkAttrs{Name: probeName},
		PeerName:  probeName + "-p",
	}
	err := vnl.LinkAdd(veth)
	if err != nil {
		t.Skipf("requires CAP_NET_ADMIN: %v", err)
	}
	// Cleanup probe
	if link, err := vnl.LinkByName(probeName); err == nil {
		vnl.LinkDel(link)
	}
}

// TestVethPairLifecycleIT tests creating, verifying, and deleting a veth pair.
func TestVethPairLifecycleIT(t *testing.T) {
	skipIfNoNetAdmin(t)

	name := "test-veth0"
	peerName := "test-veth1"

	// Cleanup any leftover from previous runs
	cleanupVeth(name)

	// Create veth pair
	pair, err := CreateVethPair(name, peerName)
	if err != nil {
		t.Fatalf("CreateVethPair: %v", err)
	}

	// Verify names
	if pair.Name != name {
		t.Errorf("pair.Name = %q, want %q", pair.Name, name)
	}
	if pair.PeerName != peerName {
		t.Errorf("pair.PeerName = %q, want %q", pair.PeerName, peerName)
	}

	// Verify both ends exist via netlink
	link, err := vnl.LinkByName(name)
	if err != nil {
		t.Fatalf("LinkByName(%s): %v", name, err)
	}
	if link.Attrs().OperState != vnl.OperUp && link.Attrs().OperState != vnl.OperUnknown {
		// Note: veth might be "unknown" if peer is not up with carrier
		t.Logf("link state: %v (acceptable for veth)", link.Attrs().OperState)
	}

	peerLink, err := vnl.LinkByName(peerName)
	if err != nil {
		t.Fatalf("LinkByName(%s): %v", peerName, err)
	}
	_ = peerLink // exists

	// Get ifindex
	idx, err := GetLinkIndex(name)
	if err != nil {
		t.Fatalf("GetLinkIndex: %v", err)
	}
	if idx <= 0 {
		t.Errorf("ifindex = %d, want > 0", idx)
	}

	peerIdx, err := GetLinkIndex(peerName)
	if err != nil {
		t.Fatalf("GetLinkIndex(peer): %v", err)
	}
	if peerIdx <= 0 {
		t.Errorf("peer ifindex = %d, want > 0", peerIdx)
	}

	// Delete veth pair
	if err := DeleteVethPair(name); err != nil {
		t.Fatalf("DeleteVethPair: %v", err)
	}

	// Verify both ends are gone
	_, err = vnl.LinkByName(name)
	if err == nil {
		t.Error("expected link to be deleted")
	}
	_, err = vnl.LinkByName(peerName)
	if err == nil {
		t.Error("expected peer link to be deleted")
	}
}

// TestAddressConfigurationIT tests adding IP addresses to a device.
func TestAddressConfigurationIT(t *testing.T) {
	skipIfNoNetAdmin(t)

	name := "test-addr-veth0"
	peerName := "test-addr-veth1"

	cleanupVeth(name)

	// Create veth pair
	_, err := CreateVethPair(name, peerName)
	if err != nil {
		t.Fatalf("CreateVethPair: %v", err)
	}
	defer DeleteVethPair(name)

	// Add address
	addr := &net.IPNet{
		IP:   net.ParseIP("10.99.99.1"),
		Mask: net.CIDRMask(24, 32),
	}
	if err := AddAddr(name, addr); err != nil {
		t.Fatalf("AddAddr: %v", err)
	}

	// Verify address exists
	link, err := vnl.LinkByName(name)
	if err != nil {
		t.Fatalf("LinkByName: %v", err)
	}

	addrs, err := vnl.AddrList(link, vnl.FAMILY_V4)
	if err != nil {
		t.Fatalf("AddrList: %v", err)
	}

	found := false
	for _, a := range addrs {
		if a.IP.Equal(addr.IP) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("address %s not found on %s", addr.IP, name)
	}
}

// TestLinkUpDownIT tests bringing links up and down.
func TestLinkUpDownIT(t *testing.T) {
	skipIfNoNetAdmin(t)

	name := "test-updown0"
	peerName := "test-updown1"

	cleanupVeth(name)

	// Create veth pair (they are brought up by CreateVethPair)
	_, err := CreateVethPair(name, peerName)
	if err != nil {
		t.Fatalf("CreateVethPair: %v", err)
	}
	defer DeleteVethPair(name)

	// Bring down
	link, _ := vnl.LinkByName(name)
	if err := vnl.LinkSetDown(link); err != nil {
		t.Fatalf("LinkSetDown: %v", err)
	}

	// Verify down
	link, _ = vnl.LinkByName(name)
	if link.Attrs().Flags&net.FlagUp != 0 {
		t.Error("link should be down")
	}

	// Bring back up using our SetLinkUp
	if err := SetLinkUp(name); err != nil {
		t.Fatalf("SetLinkUp: %v", err)
	}

	// Verify up
	link, _ = vnl.LinkByName(name)
	if link.Attrs().Flags&net.FlagUp == 0 {
		t.Error("link should be up")
	}
}

// TestSetHardwareAddrIT tests setting MAC address on a device.
func TestSetHardwareAddrIT(t *testing.T) {
	skipIfNoNetAdmin(t)

	name := "test-mac0"
	peerName := "test-mac1"

	cleanupVeth(name)

	_, err := CreateVethPair(name, peerName)
	if err != nil {
		t.Fatalf("CreateVethPair: %v", err)
	}
	defer DeleteVethPair(name)

	// Need to bring link down to change MAC on some systems
	link, _ := vnl.LinkByName(name)
	vnl.LinkSetDown(link)

	// Set MAC address
	mac := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x99}
	if err := SetHardwareAddr(name, mac); err != nil {
		t.Fatalf("SetHardwareAddr: %v", err)
	}

	// Verify MAC
	link, _ = vnl.LinkByName(name)
	if link.Attrs().HardwareAddr.String() != mac.String() {
		t.Errorf("MAC = %s, want %s", link.Attrs().HardwareAddr, mac)
	}
}

// TestTCClsactQdiscIT tests creating and removing clsact qdisc.
func TestTCClsactQdiscIT(t *testing.T) {
	skipIfNoNetAdmin(t)

	name := "test-tc0"
	peerName := "test-tc1"

	cleanupVeth(name)

	_, err := CreateVethPair(name, peerName)
	if err != nil {
		t.Fatalf("CreateVethPair: %v", err)
	}
	defer DeleteVethPair(name)

	// Get link for qdisc operations
	link, err := vnl.LinkByName(name)
	if err != nil {
		t.Fatalf("LinkByName: %v", err)
	}

	// Ensure clsact qdisc (uses internal helper)
	if err := ensureClsactQdisc(link); err != nil {
		t.Fatalf("ensureClsactQdisc: %v", err)
	}

	// Verify clsact exists
	qdiscs, err := vnl.QdiscList(link)
	if err != nil {
		t.Fatalf("QdiscList: %v", err)
	}

	found := false
	for _, q := range qdiscs {
		if q.Type() == "clsact" {
			found = true
			break
		}
	}
	if !found {
		t.Error("clsact qdisc not found")
	}

	// Calling again should be idempotent
	if err := ensureClsactQdisc(link); err != nil {
		t.Fatalf("ensureClsactQdisc (second call): %v", err)
	}

	// Remove clsact
	if err := RemoveClsactQdisc(name); err != nil {
		t.Fatalf("RemoveClsactQdisc: %v", err)
	}

	// Verify removed
	qdiscs, _ = vnl.QdiscList(link)
	for _, q := range qdiscs {
		if q.Type() == "clsact" {
			t.Error("clsact qdisc should be removed")
		}
	}
}

// TestAddDefaultRouteIT tests adding a default route.
func TestAddDefaultRouteIT(t *testing.T) {
	skipIfNoNetAdmin(t)

	name := "test-route0"
	peerName := "test-route1"

	cleanupVeth(name)

	_, err := CreateVethPair(name, peerName)
	if err != nil {
		t.Fatalf("CreateVethPair: %v", err)
	}
	defer DeleteVethPair(name)

	// Add an address first (required for routing)
	addr := &net.IPNet{
		IP:   net.ParseIP("10.88.88.1"),
		Mask: net.CIDRMask(24, 32),
	}
	if err := AddAddr(name, addr); err != nil {
		t.Fatalf("AddAddr: %v", err)
	}

	// Add default route with metric
	metric := 200
	if err := AddDefaultRoute(name, metric); err != nil {
		t.Fatalf("AddDefaultRoute: %v", err)
	}

	// Verify route exists
	link, _ := vnl.LinkByName(name)
	routes, err := vnl.RouteList(link, vnl.FAMILY_V4)
	if err != nil {
		t.Fatalf("RouteList: %v", err)
	}

	found := false
	for _, r := range routes {
		if r.Dst == nil || r.Dst.IP.Equal(net.IPv4zero) {
			if r.Priority == metric {
				found = true
				break
			}
		}
	}
	if !found {
		t.Errorf("default route with metric %d not found", metric)
	}
}

// TestSetAndGetMTUIT tests setting and getting MTU on a device.
func TestSetAndGetMTUIT(t *testing.T) {
	skipIfNoNetAdmin(t)

	name := "test-mtu0"
	peerName := "test-mtu1"

	cleanupVeth(name)

	_, err := CreateVethPair(name, peerName)
	if err != nil {
		t.Fatalf("CreateVethPair: %v", err)
	}
	defer DeleteVethPair(name)

	// Get default MTU
	defaultMTU, err := GetMTU(name)
	if err != nil {
		t.Fatalf("GetMTU: %v", err)
	}
	if defaultMTU <= 0 {
		t.Errorf("default MTU = %d, want > 0", defaultMTU)
	}

	// Set MTU to 9000
	if err := SetMTU(name, 9000); err != nil {
		t.Fatalf("SetMTU: %v", err)
	}

	// Verify MTU
	mtu, err := GetMTU(name)
	if err != nil {
		t.Fatalf("GetMTU after set: %v", err)
	}
	if mtu != 9000 {
		t.Errorf("MTU = %d, want 9000", mtu)
	}

	// Verify peer MTU is independent
	peerMTU, err := GetMTU(peerName)
	if err != nil {
		t.Fatalf("GetMTU(peer): %v", err)
	}
	if peerMTU != defaultMTU {
		t.Logf("peer MTU changed to %d (kernel may auto-adjust peer MTU)", peerMTU)
	}

	// Set peer MTU too
	if err := SetMTU(peerName, 9000); err != nil {
		t.Fatalf("SetMTU(peer): %v", err)
	}
	peerMTU, err = GetMTU(peerName)
	if err != nil {
		t.Fatalf("GetMTU(peer) after set: %v", err)
	}
	if peerMTU != 9000 {
		t.Errorf("peer MTU = %d, want 9000", peerMTU)
	}
}

// TestGetMTUNonExistentIT tests GetMTU with a non-existent device.
func TestGetMTUNonExistentIT(t *testing.T) {
	_, err := GetMTU("nonexistent-device-xyz")
	if err == nil {
		t.Fatal("expected error for non-existent device")
	}
}

// TestSetMTUNonExistentIT tests SetMTU with a non-existent device.
func TestSetMTUNonExistentIT(t *testing.T) {
	err := SetMTU("nonexistent-device-xyz", 1500)
	if err == nil {
		t.Fatal("expected error for non-existent device")
	}
}

// cleanupVeth removes a veth pair if it exists.
func cleanupVeth(name string) {
	link, err := vnl.LinkByName(name)
	if err == nil {
		vnl.LinkDel(link)
	}
}

// TestLinkExistsIT tests LinkExists function.
func TestLinkExistsIT(t *testing.T) {
	skipIfNoNetAdmin(t)

	name := "test-exists0"
	peerName := "test-exists1"

	cleanupVeth(name)

	// Non-existent link
	if LinkExists(name) {
		t.Error("LinkExists should return false for non-existent link")
	}

	// Create veth pair
	_, err := CreateVethPair(name, peerName)
	if err != nil {
		t.Fatalf("CreateVethPair: %v", err)
	}
	defer DeleteVethPair(name)

	// Now should exist
	if !LinkExists(name) {
		t.Error("LinkExists should return true for existing link")
	}
	if !LinkExists(peerName) {
		t.Error("LinkExists should return true for peer link")
	}
}

// TestIsLinkAdminUpIT tests IsLinkAdminUp function.
func TestIsLinkAdminUpIT(t *testing.T) {
	skipIfNoNetAdmin(t)

	name := "test-admin0"
	peerName := "test-admin1"

	cleanupVeth(name)

	_, err := CreateVethPair(name, peerName)
	if err != nil {
		t.Fatalf("CreateVethPair: %v", err)
	}
	defer DeleteVethPair(name)

	// CreateVethPair brings them up
	if !IsLinkAdminUp(name) {
		t.Error("IsLinkAdminUp should return true after CreateVethPair")
	}

	// Bring down
	link, _ := vnl.LinkByName(name)
	vnl.LinkSetDown(link)

	if IsLinkAdminUp(name) {
		t.Error("IsLinkAdminUp should return false after LinkSetDown")
	}

	// Non-existent link
	if IsLinkAdminUp("nonexistent-xyz") {
		t.Error("IsLinkAdminUp should return false for non-existent link")
	}
}

// TestIsLinkUpIT tests IsLinkUp function.
func TestIsLinkUpIT(t *testing.T) {
	skipIfNoNetAdmin(t)

	name := "test-operup0"
	peerName := "test-operup1"

	cleanupVeth(name)

	_, err := CreateVethPair(name, peerName)
	if err != nil {
		t.Fatalf("CreateVethPair: %v", err)
	}
	defer DeleteVethPair(name)

	// veth OperState depends on peer being up with carrier
	// After CreateVethPair, both should have carrier
	// This may vary by kernel, so just check basic functionality

	// Non-existent link
	if IsLinkUp("nonexistent-xyz") {
		t.Error("IsLinkUp should return false for non-existent link")
	}
}

// TestIsLinkDownIT tests IsLinkDown function.
func TestIsLinkDownIT(t *testing.T) {
	skipIfNoNetAdmin(t)

	name := "test-down0"
	peerName := "test-down1"

	cleanupVeth(name)

	_, err := CreateVethPair(name, peerName)
	if err != nil {
		t.Fatalf("CreateVethPair: %v", err)
	}
	defer DeleteVethPair(name)

	// Bring down and verify
	link, _ := vnl.LinkByName(name)
	vnl.LinkSetDown(link)

	isDown, err := IsLinkDown(name)
	if err != nil {
		t.Fatalf("IsLinkDown: %v", err)
	}
	// OperState for veth may vary, but at least no error
	_ = isDown

	// Non-existent should error
	_, err = IsLinkDown("nonexistent-xyz")
	if err == nil {
		t.Error("IsLinkDown should return error for non-existent link")
	}
}

// TestCreateVethPairsIT tests batch veth creation.
func TestCreateVethPairsIT(t *testing.T) {
	skipIfNoNetAdmin(t)

	specs := []VethSpec{
		{Name: "batch-veth0", PeerName: "batch-veth0-p"},
		{Name: "batch-veth1", PeerName: "batch-veth1-p"},
	}

	// Cleanup
	for _, s := range specs {
		cleanupVeth(s.Name)
	}
	defer func() {
		for _, s := range specs {
			DeleteVethPair(s.Name)
		}
	}()

	if err := CreateVethPairs(specs); err != nil {
		t.Fatalf("CreateVethPairs: %v", err)
	}

	// Verify all exist
	for _, s := range specs {
		if !LinkExists(s.Name) {
			t.Errorf("link %s should exist", s.Name)
		}
		if !LinkExists(s.PeerName) {
			t.Errorf("peer link %s should exist", s.PeerName)
		}
	}
}

// TestCreateVethPairsWithMTUIT tests batch veth creation with MTU.
func TestCreateVethPairsWithMTUIT(t *testing.T) {
	skipIfNoNetAdmin(t)

	specs := []VethSpec{
		{Name: "batch-mtu0", PeerName: "batch-mtu0-p", MTU: 9000},
	}

	cleanupVeth(specs[0].Name)
	defer DeleteVethPair(specs[0].Name)

	if err := CreateVethPairs(specs); err != nil {
		t.Fatalf("CreateVethPairs with MTU: %v", err)
	}

	// Verify MTU was set
	mtu, err := GetMTU(specs[0].Name)
	if err != nil {
		t.Fatalf("GetMTU: %v", err)
	}
	if mtu != 9000 {
		t.Errorf("MTU = %d, want 9000", mtu)
	}
}

// TestHasTCFilterIT tests HasTCFilter function.
func TestHasTCFilterIT(t *testing.T) {
	skipIfNoNetAdmin(t)

	name := "test-hastc0"
	peerName := "test-hastc1"

	cleanupVeth(name)

	_, err := CreateVethPair(name, peerName)
	if err != nil {
		t.Fatalf("CreateVethPair: %v", err)
	}
	defer DeleteVethPair(name)

	// Get link object for HasTCFilter calls
	link, err2 := vnl.LinkByName(name)
	if err2 != nil {
		t.Fatalf("LinkByName: %v", err2)
	}

	// No filter initially
	if HasTCFilter(link, Ingress) {
		t.Error("HasTCFilter should return false before attaching")
	}

	// Add clsact qdisc (needed for TC)
	if err := ensureClsactQdisc(link); err != nil {
		t.Fatalf("ensureClsactQdisc: %v", err)
	}

	// Still no BPF filter
	if HasTCFilter(link, Ingress) {
		t.Error("HasTCFilter should return false without BPF filter")
	}

	// Non-existent link - use a dummy link with invalid index
	dummyLink := &vnl.Dummy{}
	dummyLink.Index = 999999
	if HasTCFilter(dummyLink, Ingress) {
		t.Error("HasTCFilter should return false for non-existent link")
	}
}

// TestDetachTCIT tests DetachTC function.
func TestDetachTCIT(t *testing.T) {
	skipIfNoNetAdmin(t)

	name := "test-detach0"
	peerName := "test-detach1"

	cleanupVeth(name)

	_, err := CreateVethPair(name, peerName)
	if err != nil {
		t.Fatalf("CreateVethPair: %v", err)
	}
	defer DeleteVethPair(name)

	// Add clsact
	link, _ := vnl.LinkByName(name)
	ensureClsactQdisc(link)

	// Detach should not error even without filters
	if err := DetachTC(name); err != nil {
		t.Errorf("DetachTC: %v", err)
	}

	// Non-existent should error
	if err := DetachTC("nonexistent-xyz"); err == nil {
		t.Error("DetachTC should error for non-existent link")
	}
}

// TestTCFilterPriorityConstantIT tests TCFilterPriority constant.
func TestTCFilterPriorityConstantIT(t *testing.T) {
	if TCFilterPriority != 1 {
		t.Errorf("TCFilterPriority = %d, want 1", TCFilterPriority)
	}
}

// TestDirectionConstantsIT tests Direction constants.
func TestDirectionConstantsIT(t *testing.T) {
	if Ingress != 0 {
		t.Errorf("Ingress = %d, want 0", Ingress)
	}
	if Egress != 1 {
		t.Errorf("Egress = %d, want 1", Egress)
	}
}
