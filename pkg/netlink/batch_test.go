package netlink

import (
	"errors"
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

// saveBatchDeps saves batch-related netlink function variables for restoration
func saveBatchDeps() func() {
	origLinkByName := netlinkLinkByName
	origLinkSetHardwareAddr := netlinkLinkSetHardwareAddr
	origLinkSetUp := netlinkLinkSetUp
	origLinkSetNsFd := netlinkLinkSetNsFd

	return func() {
		netlinkLinkByName = origLinkByName
		netlinkLinkSetHardwareAddr = origLinkSetHardwareAddr
		netlinkLinkSetUp = origLinkSetUp
		netlinkLinkSetNsFd = origLinkSetNsFd
	}
}

func TestConfigureLinks(t *testing.T) {
	defer saveBatchDeps()()

	t.Run("success with MAC and up", func(t *testing.T) {
		setMACCalled := false
		setUpCalled := false

		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mockLink(name, 1), nil
		}
		netlinkLinkSetHardwareAddr = func(link netlink.Link, hwaddr net.HardwareAddr) error {
			setMACCalled = true
			return nil
		}
		netlinkLinkSetUp = func(link netlink.Link) error {
			setUpCalled = true
			return nil
		}

		mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
		configs := []LinkConfig{
			{Name: "eth0", HardwareAddr: mac, Up: true},
		}
		err := ConfigureLinks(configs)
		if err != nil {
			t.Errorf("ConfigureLinks failed: %v", err)
		}
		if !setMACCalled {
			t.Error("SetHardwareAddr not called")
		}
		if !setUpCalled {
			t.Error("SetUp not called")
		}
	})

	t.Run("success with MAC only", func(t *testing.T) {
		setMACCalled := false
		setUpCalled := false

		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mockLink(name, 1), nil
		}
		netlinkLinkSetHardwareAddr = func(link netlink.Link, hwaddr net.HardwareAddr) error {
			setMACCalled = true
			return nil
		}
		netlinkLinkSetUp = func(link netlink.Link) error {
			setUpCalled = true
			return nil
		}

		mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
		configs := []LinkConfig{
			{Name: "eth0", HardwareAddr: mac, Up: false},
		}
		err := ConfigureLinks(configs)
		if err != nil {
			t.Errorf("ConfigureLinks failed: %v", err)
		}
		if !setMACCalled {
			t.Error("SetHardwareAddr not called")
		}
		if setUpCalled {
			t.Error("SetUp should not be called when Up is false")
		}
	})

	t.Run("success with up only", func(t *testing.T) {
		setMACCalled := false
		setUpCalled := false

		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mockLink(name, 1), nil
		}
		netlinkLinkSetHardwareAddr = func(link netlink.Link, hwaddr net.HardwareAddr) error {
			setMACCalled = true
			return nil
		}
		netlinkLinkSetUp = func(link netlink.Link) error {
			setUpCalled = true
			return nil
		}

		configs := []LinkConfig{
			{Name: "eth0", Up: true},
		}
		err := ConfigureLinks(configs)
		if err != nil {
			t.Errorf("ConfigureLinks failed: %v", err)
		}
		if setMACCalled {
			t.Error("SetHardwareAddr should not be called when HardwareAddr is nil")
		}
		if !setUpCalled {
			t.Error("SetUp not called")
		}
	})

	t.Run("link not found", func(t *testing.T) {
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return nil, errors.New("link not found")
		}

		configs := []LinkConfig{
			{Name: "eth0", Up: true},
		}
		err := ConfigureLinks(configs)
		if err == nil {
			t.Error("expected error when link not found")
		}
	})

	t.Run("set MAC fails", func(t *testing.T) {
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mockLink(name, 1), nil
		}
		netlinkLinkSetHardwareAddr = func(link netlink.Link, hwaddr net.HardwareAddr) error {
			return errors.New("device busy")
		}

		mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
		configs := []LinkConfig{
			{Name: "eth0", HardwareAddr: mac},
		}
		err := ConfigureLinks(configs)
		if err == nil {
			t.Error("expected error when set MAC fails")
		}
	})

	t.Run("set up fails", func(t *testing.T) {
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mockLink(name, 1), nil
		}
		netlinkLinkSetUp = func(link netlink.Link) error {
			return errors.New("permission denied")
		}

		configs := []LinkConfig{
			{Name: "eth0", Up: true},
		}
		err := ConfigureLinks(configs)
		if err == nil {
			t.Error("expected error when set up fails")
		}
	})

	t.Run("multiple configs success", func(t *testing.T) {
		linkByNameCount := 0
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			linkByNameCount++
			return mockLink(name, linkByNameCount), nil
		}
		netlinkLinkSetUp = func(link netlink.Link) error {
			return nil
		}

		configs := []LinkConfig{
			{Name: "eth0", Up: true},
			{Name: "eth1", Up: true},
		}
		err := ConfigureLinks(configs)
		if err != nil {
			t.Errorf("ConfigureLinks failed: %v", err)
		}
		if linkByNameCount != 2 {
			t.Errorf("expected 2 LinkByName calls, got %d", linkByNameCount)
		}
	})

	t.Run("second config fails", func(t *testing.T) {
		count := 0
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			count++
			if count == 2 {
				return nil, errors.New("link not found")
			}
			return mockLink(name, count), nil
		}
		netlinkLinkSetUp = func(link netlink.Link) error {
			return nil
		}

		configs := []LinkConfig{
			{Name: "eth0", Up: true},
			{Name: "eth1", Up: true},
		}
		err := ConfigureLinks(configs)
		if err == nil {
			t.Error("expected error when second config fails")
		}
	})

	t.Run("empty configs", func(t *testing.T) {
		err := ConfigureLinks([]LinkConfig{})
		if err != nil {
			t.Errorf("ConfigureLinks failed with empty configs: %v", err)
		}
	})
}

func TestMoveLinksToNs(t *testing.T) {
	defer saveBatchDeps()()

	t.Run("success", func(t *testing.T) {
		setNsFdCalled := false
		var capturedFd int

		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mockLink(name, 1), nil
		}
		netlinkLinkSetNsFd = func(link netlink.Link, fd int) error {
			setNsFdCalled = true
			capturedFd = fd
			return nil
		}

		err := MoveLinksToNs([]string{"eth0"}, 42)
		if err != nil {
			t.Errorf("MoveLinksToNs failed: %v", err)
		}
		if !setNsFdCalled {
			t.Error("SetNsFd not called")
		}
		if capturedFd != 42 {
			t.Errorf("expected fd 42, got %d", capturedFd)
		}
	})

	t.Run("link not found", func(t *testing.T) {
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return nil, errors.New("link not found")
		}

		err := MoveLinksToNs([]string{"noexist"}, 42)
		if err == nil {
			t.Error("expected error when link not found")
		}
	})

	t.Run("set ns fd fails", func(t *testing.T) {
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mockLink(name, 1), nil
		}
		netlinkLinkSetNsFd = func(link netlink.Link, fd int) error {
			return errors.New("invalid fd")
		}

		err := MoveLinksToNs([]string{"eth0"}, 42)
		if err == nil {
			t.Error("expected error when set ns fd fails")
		}
	})

	t.Run("multiple links success", func(t *testing.T) {
		setNsFdCount := 0
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mockLink(name, 1), nil
		}
		netlinkLinkSetNsFd = func(link netlink.Link, fd int) error {
			setNsFdCount++
			return nil
		}

		err := MoveLinksToNs([]string{"eth0", "eth1", "eth2"}, 42)
		if err != nil {
			t.Errorf("MoveLinksToNs failed: %v", err)
		}
		if setNsFdCount != 3 {
			t.Errorf("expected 3 SetNsFd calls, got %d", setNsFdCount)
		}
	})

	t.Run("second link fails", func(t *testing.T) {
		count := 0
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			count++
			if count == 2 {
				return nil, errors.New("link not found")
			}
			return mockLink(name, count), nil
		}
		netlinkLinkSetNsFd = func(link netlink.Link, fd int) error {
			return nil
		}

		err := MoveLinksToNs([]string{"eth0", "noexist"}, 42)
		if err == nil {
			t.Error("expected error when second link fails")
		}
	})

	t.Run("empty names", func(t *testing.T) {
		err := MoveLinksToNs([]string{}, 42)
		if err != nil {
			t.Errorf("MoveLinksToNs failed with empty names: %v", err)
		}
	})
}
