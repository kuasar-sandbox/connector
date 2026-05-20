package netlink

import (
	"errors"
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

// mockNetNS implements NetNS interface for testing
type mockNetNS struct {
	doFunc func(f func() error) error
}

func (m *mockNetNS) Do(f func() error) error {
	if m.doFunc != nil {
		return m.doFunc(f)
	}
	return f()
}

// mockLink creates a mock link using netlink.Dummy
func mockLink(name string, index int) netlink.Link {
	return &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name:  name,
			Index: index,
			MTU:   1500,
		},
	}
}

// mockLinkWithState creates a mock link with specific operational state
func mockLinkWithState(name string, index int, operState netlink.LinkOperState, flags net.Flags) netlink.Link {
	return &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name:      name,
			Index:     index,
			MTU:       1500,
			OperState: operState,
			Flags:     flags,
		},
	}
}

// saveDeps saves all netlink function variables for restoration
func saveDeps() func() {
	origLinkByName := netlinkLinkByName
	origLinkByIndex := netlinkLinkByIndex
	origLinkAdd := netlinkLinkAdd
	origLinkDel := netlinkLinkDel
	origLinkSetUp := netlinkLinkSetUp
	origLinkSetHardwareAddr := netlinkLinkSetHardwareAddr
	origLinkSetMTU := netlinkLinkSetMTU
	origAddrAdd := netlinkAddrAdd
	origRouteAdd := netlinkRouteAdd

	return func() {
		netlinkLinkByName = origLinkByName
		netlinkLinkByIndex = origLinkByIndex
		netlinkLinkAdd = origLinkAdd
		netlinkLinkDel = origLinkDel
		netlinkLinkSetUp = origLinkSetUp
		netlinkLinkSetHardwareAddr = origLinkSetHardwareAddr
		netlinkLinkSetMTU = origLinkSetMTU
		netlinkAddrAdd = origAddrAdd
		netlinkRouteAdd = origRouteAdd
	}
}

func TestSetLinkUp(t *testing.T) {
	defer saveDeps()()

	t.Run("success", func(t *testing.T) {
		mock := mockLink("eth0", 2)
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			if name != "eth0" {
				t.Errorf("unexpected name: %s", name)
			}
			return mock, nil
		}
		netlinkLinkSetUp = func(link netlink.Link) error {
			if link.Attrs().Name != "eth0" {
				t.Errorf("unexpected link: %s", link.Attrs().Name)
			}
			return nil
		}

		err := SetLinkUp("eth0")
		if err != nil {
			t.Errorf("SetLinkUp failed: %v", err)
		}
	})

	t.Run("link not found", func(t *testing.T) {
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return nil, errors.New("link not found")
		}

		err := SetLinkUp("noexist")
		if err == nil {
			t.Error("expected error for non-existent link")
		}
	})

	t.Run("set up fails", func(t *testing.T) {
		mock := mockLink("eth0", 2)
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mock, nil
		}
		netlinkLinkSetUp = func(link netlink.Link) error {
			return errors.New("permission denied")
		}

		err := SetLinkUp("eth0")
		if err == nil {
			t.Error("expected error when set up fails")
		}
	})
}

func TestGetLinkIndex(t *testing.T) {
	defer saveDeps()()

	t.Run("success", func(t *testing.T) {
		mock := mockLink("eth0", 42)
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mock, nil
		}

		index, err := GetLinkIndex("eth0")
		if err != nil {
			t.Errorf("GetLinkIndex failed: %v", err)
		}
		if index != 42 {
			t.Errorf("expected index 42, got %d", index)
		}
	})

	t.Run("link not found", func(t *testing.T) {
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return nil, errors.New("link not found")
		}

		_, err := GetLinkIndex("noexist")
		if err == nil {
			t.Error("expected error for non-existent link")
		}
	})
}

func TestDeleteVethPair(t *testing.T) {
	defer saveDeps()()

	t.Run("success", func(t *testing.T) {
		mock := mockLink("veth0", 1)
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mock, nil
		}
		netlinkLinkDel = func(link netlink.Link) error {
			return nil
		}

		err := DeleteVethPair("veth0")
		if err != nil {
			t.Errorf("DeleteVethPair failed: %v", err)
		}
	})

	t.Run("link not found", func(t *testing.T) {
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return nil, errors.New("link not found")
		}

		err := DeleteVethPair("noexist")
		if err == nil {
			t.Error("expected error for non-existent link")
		}
	})

	t.Run("delete fails", func(t *testing.T) {
		mock := mockLink("veth0", 1)
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mock, nil
		}
		netlinkLinkDel = func(link netlink.Link) error {
			return errors.New("permission denied")
		}

		err := DeleteVethPair("veth0")
		if err == nil {
			t.Error("expected error when delete fails")
		}
	})
}

func TestDeleteLinkByIndex(t *testing.T) {
	defer saveDeps()()

	t.Run("success", func(t *testing.T) {
		mock := mockLink("veth0", 123)
		netlinkLinkByIndex = func(index int) (netlink.Link, error) {
			if index != 123 {
				t.Errorf("unexpected index: %d", index)
			}
			return mock, nil
		}
		netlinkLinkDel = func(link netlink.Link) error {
			if link.Attrs().Index != 123 {
				t.Errorf("unexpected link index: %d", link.Attrs().Index)
			}
			return nil
		}

		err := DeleteLinkByIndex(123)
		if err != nil {
			t.Errorf("DeleteLinkByIndex failed: %v", err)
		}
	})

	t.Run("link not found", func(t *testing.T) {
		netlinkLinkByIndex = func(index int) (netlink.Link, error) {
			return nil, errors.New("link not found")
		}

		err := DeleteLinkByIndex(999)
		if err == nil {
			t.Error("expected error for non-existent link")
		}
	})

	t.Run("delete fails", func(t *testing.T) {
		mock := mockLink("veth0", 123)
		netlinkLinkByIndex = func(index int) (netlink.Link, error) {
			return mock, nil
		}
		netlinkLinkDel = func(link netlink.Link) error {
			return errors.New("permission denied")
		}

		err := DeleteLinkByIndex(123)
		if err == nil {
			t.Error("expected error when delete fails")
		}
	})
}

func TestDeleteLinkByIndexInNs(t *testing.T) {
	defer saveDeps()()

	t.Run("success", func(t *testing.T) {
		mock := mockLink("veth0", 123)
		netlinkLinkByIndex = func(index int) (netlink.Link, error) {
			if index != 123 {
				t.Errorf("unexpected index: %d", index)
			}
			return mock, nil
		}
		netlinkLinkDel = func(link netlink.Link) error {
			return nil
		}

		ns := &mockNetNS{}
		err := DeleteLinkByIndexInNs(ns, 123)
		if err != nil {
			t.Errorf("DeleteLinkByIndexInNs failed: %v", err)
		}
	})

	t.Run("ns do fails", func(t *testing.T) {
		ns := &mockNetNS{
			doFunc: func(f func() error) error {
				return errors.New("namespace error")
			},
		}
		err := DeleteLinkByIndexInNs(ns, 123)
		if err == nil {
			t.Error("expected error when ns.Do fails")
		}
	})

	t.Run("inner function fails", func(t *testing.T) {
		netlinkLinkByIndex = func(index int) (netlink.Link, error) {
			return nil, errors.New("link not found")
		}

		ns := &mockNetNS{}
		err := DeleteLinkByIndexInNs(ns, 999)
		if err == nil {
			t.Error("expected error when inner function fails")
		}
	})
}

func TestAddAddr(t *testing.T) {
	defer saveDeps()()

	t.Run("success", func(t *testing.T) {
		mock := mockLink("eth0", 1)
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mock, nil
		}
		netlinkAddrAdd = func(link netlink.Link, addr *netlink.Addr) error {
			return nil
		}

		_, ipNet, _ := net.ParseCIDR("192.168.1.1/24")
		err := AddAddr("eth0", ipNet)
		if err != nil {
			t.Errorf("AddAddr failed: %v", err)
		}
	})

	t.Run("link not found", func(t *testing.T) {
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return nil, errors.New("link not found")
		}

		_, ipNet, _ := net.ParseCIDR("192.168.1.1/24")
		err := AddAddr("noexist", ipNet)
		if err == nil {
			t.Error("expected error for non-existent link")
		}
	})

	t.Run("addr add fails", func(t *testing.T) {
		mock := mockLink("eth0", 1)
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mock, nil
		}
		netlinkAddrAdd = func(link netlink.Link, addr *netlink.Addr) error {
			return errors.New("address already exists")
		}

		_, ipNet, _ := net.ParseCIDR("192.168.1.1/24")
		err := AddAddr("eth0", ipNet)
		if err == nil {
			t.Error("expected error when addr add fails")
		}
	})
}

func TestAddDefaultRoute(t *testing.T) {
	defer saveDeps()()

	t.Run("success", func(t *testing.T) {
		mock := mockLink("eth0", 5)
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mock, nil
		}
		netlinkRouteAdd = func(route *netlink.Route) error {
			if route.LinkIndex != 5 {
				t.Errorf("expected LinkIndex 5, got %d", route.LinkIndex)
			}
			if route.Priority != 100 {
				t.Errorf("expected Priority 100, got %d", route.Priority)
			}
			return nil
		}

		err := AddDefaultRoute("eth0", 100)
		if err != nil {
			t.Errorf("AddDefaultRoute failed: %v", err)
		}
	})

	t.Run("link not found", func(t *testing.T) {
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return nil, errors.New("link not found")
		}

		err := AddDefaultRoute("noexist", 100)
		if err == nil {
			t.Error("expected error for non-existent link")
		}
	})

	t.Run("route add fails", func(t *testing.T) {
		mock := mockLink("eth0", 5)
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mock, nil
		}
		netlinkRouteAdd = func(route *netlink.Route) error {
			return errors.New("route already exists")
		}

		err := AddDefaultRoute("eth0", 100)
		if err == nil {
			t.Error("expected error when route add fails")
		}
	})
}

func TestAddDeviceRoute(t *testing.T) {
	defer saveDeps()()

	t.Run("scoped dst", func(t *testing.T) {
		mock := mockLink("eth0", 7)
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mock, nil
		}
		var gotDst *net.IPNet
		netlinkRouteAdd = func(route *netlink.Route) error {
			gotDst = route.Dst
			if route.LinkIndex != 7 {
				t.Errorf("expected LinkIndex 7, got %d", route.LinkIndex)
			}
			if route.Priority != 101 {
				t.Errorf("expected Priority 101, got %d", route.Priority)
			}
			return nil
		}

		_, dst, _ := net.ParseCIDR("100.100.96.0/20")
		if err := AddDeviceRoute("eth0", dst, 101); err != nil {
			t.Fatalf("AddDeviceRoute: %v", err)
		}
		if gotDst == nil || gotDst.String() != "100.100.96.0/20" {
			t.Errorf("expected Dst 100.100.96.0/20, got %v", gotDst)
		}
	})

	t.Run("nil dst is default route", func(t *testing.T) {
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mockLink("eth0", 5), nil
		}
		var gotDst *net.IPNet
		netlinkRouteAdd = func(route *netlink.Route) error {
			gotDst = route.Dst
			return nil
		}

		if err := AddDeviceRoute("eth0", nil, 100); err != nil {
			t.Fatalf("AddDeviceRoute: %v", err)
		}
		if gotDst == nil || gotDst.String() != "0.0.0.0/0" {
			t.Errorf("expected Dst 0.0.0.0/0, got %v", gotDst)
		}
	})

	t.Run("link not found", func(t *testing.T) {
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return nil, errors.New("link not found")
		}
		if err := AddDeviceRoute("noexist", nil, 100); err == nil {
			t.Error("expected error for non-existent link")
		}
	})

	t.Run("route add fails", func(t *testing.T) {
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mockLink("eth0", 5), nil
		}
		netlinkRouteAdd = func(route *netlink.Route) error {
			return errors.New("route already exists")
		}
		if err := AddDeviceRoute("eth0", nil, 100); err == nil {
			t.Error("expected error when route add fails")
		}
	})
}

func TestSetHardwareAddr(t *testing.T) {
	defer saveDeps()()

	t.Run("success", func(t *testing.T) {
		mock := mockLink("eth0", 1)
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mock, nil
		}
		netlinkLinkSetHardwareAddr = func(link netlink.Link, hwaddr net.HardwareAddr) error {
			return nil
		}

		mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
		err := SetHardwareAddr("eth0", mac)
		if err != nil {
			t.Errorf("SetHardwareAddr failed: %v", err)
		}
	})

	t.Run("link not found", func(t *testing.T) {
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return nil, errors.New("link not found")
		}

		mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
		err := SetHardwareAddr("noexist", mac)
		if err == nil {
			t.Error("expected error for non-existent link")
		}
	})

	t.Run("set hardware addr fails", func(t *testing.T) {
		mock := mockLink("eth0", 1)
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mock, nil
		}
		netlinkLinkSetHardwareAddr = func(link netlink.Link, hwaddr net.HardwareAddr) error {
			return errors.New("device busy")
		}

		mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
		err := SetHardwareAddr("eth0", mac)
		if err == nil {
			t.Error("expected error when set hardware addr fails")
		}
	})
}

func TestSetMTU(t *testing.T) {
	defer saveDeps()()

	t.Run("success", func(t *testing.T) {
		mock := mockLink("eth0", 1)
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mock, nil
		}
		netlinkLinkSetMTU = func(link netlink.Link, mtu int) error {
			if mtu != 9000 {
				t.Errorf("expected MTU 9000, got %d", mtu)
			}
			return nil
		}

		err := SetMTU("eth0", 9000)
		if err != nil {
			t.Errorf("SetMTU failed: %v", err)
		}
	})

	t.Run("link not found", func(t *testing.T) {
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return nil, errors.New("link not found")
		}

		err := SetMTU("noexist", 9000)
		if err == nil {
			t.Error("expected error for non-existent link")
		}
	})

	t.Run("set mtu fails", func(t *testing.T) {
		mock := mockLink("eth0", 1)
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mock, nil
		}
		netlinkLinkSetMTU = func(link netlink.Link, mtu int) error {
			return errors.New("invalid argument")
		}

		err := SetMTU("eth0", 65536)
		if err == nil {
			t.Error("expected error when set mtu fails")
		}
	})
}

func TestGetMTU(t *testing.T) {
	defer saveDeps()()

	t.Run("success", func(t *testing.T) {
		mock := &netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{
				Name:  "eth0",
				Index: 1,
				MTU:   9000,
			},
		}
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mock, nil
		}

		mtu, err := GetMTU("eth0")
		if err != nil {
			t.Errorf("GetMTU failed: %v", err)
		}
		if mtu != 9000 {
			t.Errorf("expected MTU 9000, got %d", mtu)
		}
	})

	t.Run("link not found", func(t *testing.T) {
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return nil, errors.New("link not found")
		}

		_, err := GetMTU("noexist")
		if err == nil {
			t.Error("expected error for non-existent link")
		}
	})
}

func TestIsLinkDown(t *testing.T) {
	defer saveDeps()()

	t.Run("link is down", func(t *testing.T) {
		mock := mockLinkWithState("eth0", 1, netlink.OperDown, 0)
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mock, nil
		}

		down, err := IsLinkDown("eth0")
		if err != nil {
			t.Errorf("IsLinkDown failed: %v", err)
		}
		if !down {
			t.Error("expected link to be down")
		}
	})

	t.Run("link is up", func(t *testing.T) {
		mock := mockLinkWithState("eth0", 1, netlink.OperUp, net.FlagUp)
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mock, nil
		}

		down, err := IsLinkDown("eth0")
		if err != nil {
			t.Errorf("IsLinkDown failed: %v", err)
		}
		if down {
			t.Error("expected link to be up")
		}
	})

	t.Run("link not found", func(t *testing.T) {
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return nil, errors.New("link not found")
		}

		_, err := IsLinkDown("noexist")
		if err == nil {
			t.Error("expected error for non-existent link")
		}
	})
}

func TestLinkExists(t *testing.T) {
	defer saveDeps()()

	t.Run("link exists", func(t *testing.T) {
		mock := mockLink("eth0", 1)
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mock, nil
		}

		if !LinkExists("eth0") {
			t.Error("expected link to exist")
		}
	})

	t.Run("link does not exist", func(t *testing.T) {
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return nil, errors.New("link not found")
		}

		if LinkExists("noexist") {
			t.Error("expected link to not exist")
		}
	})
}

func TestIsLinkUp(t *testing.T) {
	defer saveDeps()()

	t.Run("link is up", func(t *testing.T) {
		mock := mockLinkWithState("eth0", 1, netlink.OperUp, net.FlagUp)
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mock, nil
		}

		if !IsLinkUp("eth0") {
			t.Error("expected link to be up")
		}
	})

	t.Run("link is down", func(t *testing.T) {
		mock := mockLinkWithState("eth0", 1, netlink.OperDown, 0)
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mock, nil
		}

		if IsLinkUp("eth0") {
			t.Error("expected link to be down")
		}
	})

	t.Run("link not found", func(t *testing.T) {
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return nil, errors.New("link not found")
		}

		if IsLinkUp("noexist") {
			t.Error("expected false when link not found")
		}
	})
}

func TestIsLinkAdminUp(t *testing.T) {
	defer saveDeps()()

	t.Run("link is admin up", func(t *testing.T) {
		mock := mockLinkWithState("eth0", 1, netlink.OperUnknown, net.FlagUp)
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mock, nil
		}

		if !IsLinkAdminUp("eth0") {
			t.Error("expected link to be admin up")
		}
	})

	t.Run("link is admin down", func(t *testing.T) {
		mock := mockLinkWithState("eth0", 1, netlink.OperDown, 0)
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mock, nil
		}

		if IsLinkAdminUp("eth0") {
			t.Error("expected link to be admin down")
		}
	})

	t.Run("link not found", func(t *testing.T) {
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return nil, errors.New("link not found")
		}

		if IsLinkAdminUp("noexist") {
			t.Error("expected false when link not found")
		}
	})
}

func TestCreateVethPair(t *testing.T) {
	defer saveDeps()()

	t.Run("success", func(t *testing.T) {
		linkAddCalled := false
		linkByNameCalls := 0
		linkSetUpCalls := 0

		netlinkLinkAdd = func(link netlink.Link) error {
			veth, ok := link.(*netlink.Veth)
			if !ok {
				t.Error("expected Veth link")
			}
			if veth.Attrs().Name != "veth0" || veth.PeerName != "veth1" {
				t.Errorf("unexpected veth names: %s, %s", veth.Attrs().Name, veth.PeerName)
			}
			linkAddCalled = true
			return nil
		}

		netlinkLinkByName = func(name string) (netlink.Link, error) {
			linkByNameCalls++
			return mockLink(name, linkByNameCalls), nil
		}

		netlinkLinkSetUp = func(link netlink.Link) error {
			linkSetUpCalls++
			return nil
		}

		netlinkLinkDel = func(link netlink.Link) error {
			return nil
		}

		pair, err := CreateVethPair("veth0", "veth1")
		if err != nil {
			t.Errorf("CreateVethPair failed: %v", err)
		}
		if pair.Name != "veth0" || pair.PeerName != "veth1" {
			t.Errorf("unexpected pair: %+v", pair)
		}
		if !linkAddCalled {
			t.Error("LinkAdd not called")
		}
		if linkByNameCalls != 2 {
			t.Errorf("expected 2 LinkByName calls, got %d", linkByNameCalls)
		}
		if linkSetUpCalls != 2 {
			t.Errorf("expected 2 LinkSetUp calls, got %d", linkSetUpCalls)
		}
	})

	t.Run("link add fails", func(t *testing.T) {
		netlinkLinkAdd = func(link netlink.Link) error {
			return errors.New("device exists")
		}

		_, err := CreateVethPair("veth0", "veth1")
		if err == nil {
			t.Error("expected error when link add fails")
		}
	})

	t.Run("get first link fails", func(t *testing.T) {
		linkDelCalled := false
		netlinkLinkAdd = func(link netlink.Link) error {
			return nil
		}
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return nil, errors.New("link not found")
		}
		netlinkLinkDel = func(link netlink.Link) error {
			linkDelCalled = true
			return nil
		}

		_, err := CreateVethPair("veth0", "veth1")
		if err == nil {
			t.Error("expected error when get link fails")
		}
		if !linkDelCalled {
			t.Error("LinkDel should be called for cleanup")
		}
	})

	t.Run("set up first link fails", func(t *testing.T) {
		linkDelCalled := false
		netlinkLinkAdd = func(link netlink.Link) error {
			return nil
		}
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mockLink(name, 1), nil
		}
		netlinkLinkSetUp = func(link netlink.Link) error {
			return errors.New("permission denied")
		}
		netlinkLinkDel = func(link netlink.Link) error {
			linkDelCalled = true
			return nil
		}

		_, err := CreateVethPair("veth0", "veth1")
		if err == nil {
			t.Error("expected error when set up fails")
		}
		if !linkDelCalled {
			t.Error("LinkDel should be called for cleanup")
		}
	})

	t.Run("get peer link fails", func(t *testing.T) {
		linkDelCalled := false
		callCount := 0
		netlinkLinkAdd = func(link netlink.Link) error {
			return nil
		}
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			callCount++
			if callCount == 1 {
				return mockLink(name, 1), nil
			}
			return nil, errors.New("peer not found")
		}
		netlinkLinkSetUp = func(link netlink.Link) error {
			return nil
		}
		netlinkLinkDel = func(link netlink.Link) error {
			linkDelCalled = true
			return nil
		}

		_, err := CreateVethPair("veth0", "veth1")
		if err == nil {
			t.Error("expected error when get peer fails")
		}
		if !linkDelCalled {
			t.Error("LinkDel should be called for cleanup")
		}
	})

	t.Run("set up peer fails", func(t *testing.T) {
		linkDelCalled := false
		setUpCount := 0
		netlinkLinkAdd = func(link netlink.Link) error {
			return nil
		}
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mockLink(name, 1), nil
		}
		netlinkLinkSetUp = func(link netlink.Link) error {
			setUpCount++
			if setUpCount == 2 {
				return errors.New("permission denied")
			}
			return nil
		}
		netlinkLinkDel = func(link netlink.Link) error {
			linkDelCalled = true
			return nil
		}

		_, err := CreateVethPair("veth0", "veth1")
		if err == nil {
			t.Error("expected error when set up peer fails")
		}
		if !linkDelCalled {
			t.Error("LinkDel should be called for cleanup")
		}
	})
}

func TestSetLinkUpByName(t *testing.T) {
	defer saveDeps()()

	t.Run("success", func(t *testing.T) {
		mock := mockLink("eth0", 1)
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mock, nil
		}
		netlinkLinkSetUp = func(link netlink.Link) error {
			return nil
		}

		err := setLinkUpByName("eth0")
		if err != nil {
			t.Errorf("setLinkUpByName failed: %v", err)
		}
	})

	t.Run("link not found", func(t *testing.T) {
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return nil, errors.New("link not found")
		}

		err := setLinkUpByName("noexist")
		if err == nil {
			t.Error("expected error for non-existent link")
		}
	})

	t.Run("set up fails", func(t *testing.T) {
		mock := mockLink("eth0", 1)
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mock, nil
		}
		netlinkLinkSetUp = func(link netlink.Link) error {
			return errors.New("permission denied")
		}

		err := setLinkUpByName("eth0")
		if err == nil {
			t.Error("expected error when set up fails")
		}
	})
}

func TestCreateVethPairs(t *testing.T) {
	defer saveDeps()()

	t.Run("success with single spec", func(t *testing.T) {
		addCalled := false
		setUpCalls := 0

		netlinkLinkAdd = func(link netlink.Link) error {
			addCalled = true
			return nil
		}
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mockLink(name, 1), nil
		}
		netlinkLinkSetUp = func(link netlink.Link) error {
			setUpCalls++
			return nil
		}

		specs := []VethSpec{
			{Name: "veth0", PeerName: "veth1"},
		}
		err := CreateVethPairs(specs)
		if err != nil {
			t.Errorf("CreateVethPairs failed: %v", err)
		}
		if !addCalled {
			t.Error("LinkAdd not called")
		}
		if setUpCalls != 2 {
			t.Errorf("expected 2 LinkSetUp calls, got %d", setUpCalls)
		}
	})

	t.Run("success with MTU", func(t *testing.T) {
		var capturedLink *netlink.Veth
		netlinkLinkAdd = func(link netlink.Link) error {
			capturedLink = link.(*netlink.Veth)
			return nil
		}
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mockLink(name, 1), nil
		}
		netlinkLinkSetUp = func(link netlink.Link) error {
			return nil
		}

		specs := []VethSpec{
			{Name: "veth0", PeerName: "veth1", MTU: 9000},
		}
		err := CreateVethPairs(specs)
		if err != nil {
			t.Errorf("CreateVethPairs failed: %v", err)
		}
		if capturedLink.Attrs().MTU != 9000 {
			t.Errorf("expected MTU 9000, got %d", capturedLink.Attrs().MTU)
		}
		if capturedLink.PeerMTU != 9000 {
			t.Errorf("expected PeerMTU 9000, got %d", capturedLink.PeerMTU)
		}
	})

	t.Run("success with peer in different namespace", func(t *testing.T) {
		setUpCalls := 0
		netlinkLinkAdd = func(link netlink.Link) error {
			veth := link.(*netlink.Veth)
			if veth.PeerNamespace != netlink.NsFd(10) {
				t.Errorf("expected PeerNamespace 10, got %v", veth.PeerNamespace)
			}
			return nil
		}
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mockLink(name, 1), nil
		}
		netlinkLinkSetUp = func(link netlink.Link) error {
			setUpCalls++
			return nil
		}

		specs := []VethSpec{
			{Name: "veth0", PeerName: "veth1", PeerNsFd: 10},
		}
		err := CreateVethPairs(specs)
		if err != nil {
			t.Errorf("CreateVethPairs failed: %v", err)
		}
		// Only this end should be brought up, peer is in different ns
		if setUpCalls != 1 {
			t.Errorf("expected 1 LinkSetUp call, got %d", setUpCalls)
		}
	})

	t.Run("success with peer MAC address", func(t *testing.T) {
		mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
		netlinkLinkAdd = func(link netlink.Link) error {
			veth := link.(*netlink.Veth)
			if veth.PeerHardwareAddr.String() != mac.String() {
				t.Errorf("expected PeerHardwareAddr %s, got %s", mac, veth.PeerHardwareAddr)
			}
			return nil
		}
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mockLink(name, 1), nil
		}
		netlinkLinkSetUp = func(link netlink.Link) error {
			return nil
		}

		specs := []VethSpec{
			{Name: "veth0", PeerName: "veth1", PeerMACAddr: mac},
		}
		err := CreateVethPairs(specs)
		if err != nil {
			t.Errorf("CreateVethPairs failed: %v", err)
		}
	})

	t.Run("link add fails", func(t *testing.T) {
		netlinkLinkAdd = func(link netlink.Link) error {
			return errors.New("device exists")
		}

		specs := []VethSpec{
			{Name: "veth0", PeerName: "veth1"},
		}
		err := CreateVethPairs(specs)
		if err == nil {
			t.Error("expected error when link add fails")
		}
	})

	t.Run("set up this end fails", func(t *testing.T) {
		netlinkLinkAdd = func(link netlink.Link) error {
			return nil
		}
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mockLink(name, 1), nil
		}
		netlinkLinkSetUp = func(link netlink.Link) error {
			return errors.New("permission denied")
		}

		specs := []VethSpec{
			{Name: "veth0", PeerName: "veth1"},
		}
		err := CreateVethPairs(specs)
		if err == nil {
			t.Error("expected error when set up fails")
		}
	})

	t.Run("set up peer fails", func(t *testing.T) {
		setUpCount := 0
		netlinkLinkAdd = func(link netlink.Link) error {
			return nil
		}
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mockLink(name, 1), nil
		}
		netlinkLinkSetUp = func(link netlink.Link) error {
			setUpCount++
			if setUpCount == 2 {
				return errors.New("permission denied")
			}
			return nil
		}

		specs := []VethSpec{
			{Name: "veth0", PeerName: "veth1"},
		}
		err := CreateVethPairs(specs)
		if err == nil {
			t.Error("expected error when set up peer fails")
		}
	})

	t.Run("multiple specs success", func(t *testing.T) {
		addCount := 0
		netlinkLinkAdd = func(link netlink.Link) error {
			addCount++
			return nil
		}
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mockLink(name, 1), nil
		}
		netlinkLinkSetUp = func(link netlink.Link) error {
			return nil
		}

		specs := []VethSpec{
			{Name: "veth0", PeerName: "veth1"},
			{Name: "veth2", PeerName: "veth3"},
		}
		err := CreateVethPairs(specs)
		if err != nil {
			t.Errorf("CreateVethPairs failed: %v", err)
		}
		if addCount != 2 {
			t.Errorf("expected 2 LinkAdd calls, got %d", addCount)
		}
	})

	t.Run("second spec fails", func(t *testing.T) {
		addCount := 0
		netlinkLinkAdd = func(link netlink.Link) error {
			addCount++
			if addCount == 2 {
				return errors.New("device exists")
			}
			return nil
		}
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mockLink(name, 1), nil
		}
		netlinkLinkSetUp = func(link netlink.Link) error {
			return nil
		}

		specs := []VethSpec{
			{Name: "veth0", PeerName: "veth1"},
			{Name: "veth2", PeerName: "veth3"},
		}
		err := CreateVethPairs(specs)
		if err == nil {
			t.Error("expected error when second spec fails")
		}
	})
}

func TestSetLinkUpInNs(t *testing.T) {
	defer saveDeps()()

	t.Run("success", func(t *testing.T) {
		mock := mockLink("eth0", 1)
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mock, nil
		}
		netlinkLinkSetUp = func(link netlink.Link) error {
			return nil
		}

		ns := &mockNetNS{}
		err := SetLinkUpInNs(ns, "eth0")
		if err != nil {
			t.Errorf("SetLinkUpInNs failed: %v", err)
		}
	})

	t.Run("ns do fails", func(t *testing.T) {
		ns := &mockNetNS{
			doFunc: func(f func() error) error {
				return errors.New("namespace error")
			},
		}
		err := SetLinkUpInNs(ns, "eth0")
		if err == nil {
			t.Error("expected error when ns.Do fails")
		}
	})

	t.Run("inner function fails", func(t *testing.T) {
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return nil, errors.New("link not found")
		}

		ns := &mockNetNS{}
		err := SetLinkUpInNs(ns, "noexist")
		if err == nil {
			t.Error("expected error when inner function fails")
		}
	})
}

func TestGetLinkIndexInNs(t *testing.T) {
	defer saveDeps()()

	t.Run("success", func(t *testing.T) {
		mock := mockLink("eth0", 42)
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mock, nil
		}

		ns := &mockNetNS{}
		index, err := GetLinkIndexInNs(ns, "eth0")
		if err != nil {
			t.Errorf("GetLinkIndexInNs failed: %v", err)
		}
		if index != 42 {
			t.Errorf("expected index 42, got %d", index)
		}
	})

	t.Run("ns do fails", func(t *testing.T) {
		ns := &mockNetNS{
			doFunc: func(f func() error) error {
				return errors.New("namespace error")
			},
		}
		_, err := GetLinkIndexInNs(ns, "eth0")
		if err == nil {
			t.Error("expected error when ns.Do fails")
		}
	})

	t.Run("inner function fails", func(t *testing.T) {
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return nil, errors.New("link not found")
		}

		ns := &mockNetNS{}
		_, err := GetLinkIndexInNs(ns, "noexist")
		if err == nil {
			t.Error("expected error when inner function fails")
		}
	})
}

func TestDeleteVethPairInNs(t *testing.T) {
	defer saveDeps()()

	t.Run("success", func(t *testing.T) {
		mock := mockLink("veth0", 1)
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mock, nil
		}
		netlinkLinkDel = func(link netlink.Link) error {
			return nil
		}

		ns := &mockNetNS{}
		err := DeleteVethPairInNs(ns, "veth0")
		if err != nil {
			t.Errorf("DeleteVethPairInNs failed: %v", err)
		}
	})

	t.Run("ns do fails", func(t *testing.T) {
		ns := &mockNetNS{
			doFunc: func(f func() error) error {
				return errors.New("namespace error")
			},
		}
		err := DeleteVethPairInNs(ns, "veth0")
		if err == nil {
			t.Error("expected error when ns.Do fails")
		}
	})
}

func TestCreateVethPairInNs(t *testing.T) {
	defer saveDeps()()

	t.Run("success", func(t *testing.T) {
		linkByNameCalls := 0
		netlinkLinkAdd = func(link netlink.Link) error {
			return nil
		}
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			linkByNameCalls++
			return mockLink(name, linkByNameCalls), nil
		}
		netlinkLinkSetUp = func(link netlink.Link) error {
			return nil
		}
		netlinkLinkDel = func(link netlink.Link) error {
			return nil
		}

		ns := &mockNetNS{}
		pair, err := CreateVethPairInNs(ns, "veth0", "veth1")
		if err != nil {
			t.Errorf("CreateVethPairInNs failed: %v", err)
		}
		if pair.Name != "veth0" || pair.PeerName != "veth1" {
			t.Errorf("unexpected pair: %+v", pair)
		}
	})

	t.Run("ns do fails", func(t *testing.T) {
		ns := &mockNetNS{
			doFunc: func(f func() error) error {
				return errors.New("namespace error")
			},
		}
		_, err := CreateVethPairInNs(ns, "veth0", "veth1")
		if err == nil {
			t.Error("expected error when ns.Do fails")
		}
	})
}

func TestAddAddrInNs(t *testing.T) {
	defer saveDeps()()

	t.Run("success", func(t *testing.T) {
		mock := mockLink("eth0", 1)
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mock, nil
		}
		netlinkAddrAdd = func(link netlink.Link, addr *netlink.Addr) error {
			return nil
		}

		ns := &mockNetNS{}
		_, ipNet, _ := net.ParseCIDR("192.168.1.1/24")
		err := AddAddrInNs(ns, "eth0", ipNet)
		if err != nil {
			t.Errorf("AddAddrInNs failed: %v", err)
		}
	})

	t.Run("ns do fails", func(t *testing.T) {
		ns := &mockNetNS{
			doFunc: func(f func() error) error {
				return errors.New("namespace error")
			},
		}
		_, ipNet, _ := net.ParseCIDR("192.168.1.1/24")
		err := AddAddrInNs(ns, "eth0", ipNet)
		if err == nil {
			t.Error("expected error when ns.Do fails")
		}
	})
}

func TestSetHardwareAddrInNs(t *testing.T) {
	defer saveDeps()()

	t.Run("success", func(t *testing.T) {
		mock := mockLink("eth0", 1)
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mock, nil
		}
		netlinkLinkSetHardwareAddr = func(link netlink.Link, hwaddr net.HardwareAddr) error {
			return nil
		}

		ns := &mockNetNS{}
		mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
		err := SetHardwareAddrInNs(ns, "eth0", mac)
		if err != nil {
			t.Errorf("SetHardwareAddrInNs failed: %v", err)
		}
	})

	t.Run("ns do fails", func(t *testing.T) {
		ns := &mockNetNS{
			doFunc: func(f func() error) error {
				return errors.New("namespace error")
			},
		}
		mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
		err := SetHardwareAddrInNs(ns, "eth0", mac)
		if err == nil {
			t.Error("expected error when ns.Do fails")
		}
	})
}

func TestSetMTUInNs(t *testing.T) {
	defer saveDeps()()

	t.Run("success", func(t *testing.T) {
		mock := mockLink("eth0", 1)
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mock, nil
		}
		netlinkLinkSetMTU = func(link netlink.Link, mtu int) error {
			return nil
		}

		ns := &mockNetNS{}
		err := SetMTUInNs(ns, "eth0", 9000)
		if err != nil {
			t.Errorf("SetMTUInNs failed: %v", err)
		}
	})

	t.Run("ns do fails", func(t *testing.T) {
		ns := &mockNetNS{
			doFunc: func(f func() error) error {
				return errors.New("namespace error")
			},
		}
		err := SetMTUInNs(ns, "eth0", 9000)
		if err == nil {
			t.Error("expected error when ns.Do fails")
		}
	})
}

func TestGetMTUInNs(t *testing.T) {
	defer saveDeps()()

	t.Run("success", func(t *testing.T) {
		mock := &netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{
				Name:  "eth0",
				Index: 1,
				MTU:   9000,
			},
		}
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mock, nil
		}

		ns := &mockNetNS{}
		mtu, err := GetMTUInNs(ns, "eth0")
		if err != nil {
			t.Errorf("GetMTUInNs failed: %v", err)
		}
		if mtu != 9000 {
			t.Errorf("expected MTU 9000, got %d", mtu)
		}
	})

	t.Run("ns do fails", func(t *testing.T) {
		ns := &mockNetNS{
			doFunc: func(f func() error) error {
				return errors.New("namespace error")
			},
		}
		_, err := GetMTUInNs(ns, "eth0")
		if err == nil {
			t.Error("expected error when ns.Do fails")
		}
	})
}
