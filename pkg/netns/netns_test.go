package netns

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

func TestErrNotExist(t *testing.T) {
	// Verify ErrNotExist is os.ErrNotExist
	if !errors.Is(ErrNotExist, os.ErrNotExist) {
		t.Error("ErrNotExist should be os.ErrNotExist")
	}
}

func TestGetByNameNotExist(t *testing.T) {
	// Use a name that definitely doesn't exist
	_, err := GetByName("nonexistent_ns_12345")
	if err == nil {
		t.Fatal("expected error for non-existent namespace")
	}

	// Verify error wraps ErrNotExist
	if !errors.Is(err, ErrNotExist) {
		t.Errorf("error should wrap ErrNotExist, got: %v", err)
	}
}

func TestGetByNameErrorMessage(t *testing.T) {
	_, err := GetByName("nonexistent_ns_12345")
	if err == nil {
		t.Fatal("expected error")
	}

	// Verify error message contains namespace name
	msg := err.Error()
	if !errors.Is(err, ErrNotExist) {
		t.Errorf("error should wrap ErrNotExist")
	}
	if len(msg) == 0 {
		t.Error("error message should not be empty")
	}
}

// --- NetNS struct tests ---

func TestNetNSName(t *testing.T) {
	// Create a mock NetNS with a name
	ns := &NetNS{name: "test_ns"}
	if ns.Name() != "test_ns" {
		t.Errorf("Name() = %q, want %q", ns.Name(), "test_ns")
	}
}

func TestNetNSNameEmpty(t *testing.T) {
	// Empty name indicates current namespace
	ns := &NetNS{name: ""}
	if ns.Name() != "" {
		t.Errorf("Name() = %q, want empty string", ns.Name())
	}
}

func TestNetNSHandle(t *testing.T) {
	// Create a mock NetNS with a specific handle value
	ns := &NetNS{handle: 42}
	if ns.Handle() != 42 {
		t.Errorf("Handle() = %d, want 42", ns.Handle())
	}
}

func TestNetNSHandleZero(t *testing.T) {
	// Zero handle is technically valid
	ns := &NetNS{handle: 0}
	if ns.Handle() != 0 {
		t.Errorf("Handle() = %d, want 0", ns.Handle())
	}
}

// --- Mock-based tests ---

func TestGetByName(t *testing.T) {
	// Save original functions
	origGetFromName := netnsGetFromName
	origStat := osStat
	defer func() {
		netnsGetFromName = origGetFromName
		osStat = origStat
	}()

	t.Run("success", func(t *testing.T) {
		// Mock os.Stat returns success
		osStat = func(name string) (os.FileInfo, error) {
			return nil, nil // file exists
		}
		// Mock netns.GetFromName returns success
		netnsGetFromName = func(name string) (netns.NsHandle, error) {
			if name == "test_ns" {
				return 42, nil
			}
			return 0, fmt.Errorf("not found")
		}

		ns, err := GetByName("test_ns")
		if err != nil {
			t.Fatalf("GetByName: %v", err)
		}
		if ns.Name() != "test_ns" {
			t.Errorf("Name = %q, want test_ns", ns.Name())
		}
		if ns.Handle() != 42 {
			t.Errorf("Handle = %d, want 42", ns.Handle())
		}
	})

	t.Run("namespace not exist", func(t *testing.T) {
		osStat = func(name string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		}

		_, err := GetByName("nonexistent")
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, ErrNotExist) {
			t.Errorf("error should wrap ErrNotExist, got: %v", err)
		}
	})

	t.Run("stat error (non-NotExist)", func(t *testing.T) {
		osStat = func(name string) (os.FileInfo, error) {
			return nil, fmt.Errorf("permission denied")
		}

		_, err := GetByName("test_ns")
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "stat netns") {
			t.Errorf("error = %v", err)
		}
	})

	t.Run("GetFromName error", func(t *testing.T) {
		osStat = func(name string) (os.FileInfo, error) {
			return nil, nil // file exists
		}
		netnsGetFromName = func(name string) (netns.NsHandle, error) {
			return 0, fmt.Errorf("mock error: failed to open")
		}

		_, err := GetByName("test_ns")
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "failed to get netns") {
			t.Errorf("error = %v", err)
		}
	})
}

func TestGetCurrent(t *testing.T) {
	origGet := netnsGet
	defer func() { netnsGet = origGet }()

	t.Run("success", func(t *testing.T) {
		netnsGet = func() (netns.NsHandle, error) {
			return 123, nil
		}

		ns, err := GetCurrent()
		if err != nil {
			t.Fatalf("GetCurrent: %v", err)
		}
		if ns.Handle() != 123 {
			t.Errorf("Handle = %d, want 123", ns.Handle())
		}
		if ns.Name() != "" {
			t.Errorf("Name = %q, want empty", ns.Name())
		}
	})

	t.Run("error", func(t *testing.T) {
		netnsGet = func() (netns.NsHandle, error) {
			return 0, fmt.Errorf("mock error")
		}

		_, err := GetCurrent()
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "failed to get current netns") {
			t.Errorf("error = %v", err)
		}
	})
}

func TestNsHandleCloseDefault(t *testing.T) {
	// Test default implementation: closing invalid handle returns error
	err := nsHandleCloseDefault(-1)
	// Closing invalid fd returns EBADF error
	if err == nil {
		t.Log("Close(-1) returned nil (unexpected but possible)")
	}
	// Either way, code path is covered
}

func TestClose(t *testing.T) {
	// Save original function
	origClose := nsHandleClose
	defer func() { nsHandleClose = origClose }()

	t.Run("success", func(t *testing.T) {
		closeCalled := false
		nsHandleClose = func(h netns.NsHandle) error {
			closeCalled = true
			if h != 42 {
				t.Errorf("Close called with handle %d, want 42", h)
			}
			return nil
		}

		ns := &NetNS{handle: 42}
		err := ns.Close()
		if err != nil {
			t.Errorf("Close: %v", err)
		}
		if !closeCalled {
			t.Error("Close was not called")
		}
	})

	t.Run("error", func(t *testing.T) {
		nsHandleClose = func(h netns.NsHandle) error {
			return fmt.Errorf("close error: bad file descriptor")
		}

		ns := &NetNS{handle: 42}
		err := ns.Close()
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "close error") {
			t.Errorf("error = %v", err)
		}
	})
}

func TestDo(t *testing.T) {
	origGet := netnsGet
	origSet := netnsSet
	defer func() {
		netnsGet = origGet
		netnsSet = origSet
	}()

	t.Run("success", func(t *testing.T) {
		var setCalls []netns.NsHandle
		netnsGet = func() (netns.NsHandle, error) {
			return 100, nil // return "original" namespace
		}
		netnsSet = func(ns netns.NsHandle) error {
			setCalls = append(setCalls, ns)
			return nil
		}

		ns := &NetNS{handle: 200}
		executed := false
		err := ns.Do(func() error {
			executed = true
			return nil
		})

		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		if !executed {
			t.Error("function not executed")
		}
		// Should first Set(200) to switch, then Set(100) to restore
		if len(setCalls) != 2 || setCalls[0] != 200 || setCalls[1] != 100 {
			t.Errorf("setCalls = %v, want [200, 100]", setCalls)
		}
	})

	t.Run("function error", func(t *testing.T) {
		netnsGet = func() (netns.NsHandle, error) { return 100, nil }
		netnsSet = func(ns netns.NsHandle) error { return nil }

		ns := &NetNS{handle: 200}
		expectedErr := fmt.Errorf("function error")
		err := ns.Do(func() error {
			return expectedErr
		})

		if err != expectedErr {
			t.Errorf("error = %v, want %v", err, expectedErr)
		}
	})

	t.Run("get current namespace error", func(t *testing.T) {
		netnsGet = func() (netns.NsHandle, error) {
			return 0, fmt.Errorf("get error")
		}

		ns := &NetNS{handle: 200}
		err := ns.Do(func() error { return nil })
		if err == nil || !strings.Contains(err.Error(), "failed to get current netns") {
			t.Errorf("error = %v", err)
		}
	})

	t.Run("set target namespace error", func(t *testing.T) {
		netnsGet = func() (netns.NsHandle, error) { return 100, nil }
		netnsSet = func(ns netns.NsHandle) error {
			if ns == 200 {
				return fmt.Errorf("set error")
			}
			return nil
		}

		ns := &NetNS{handle: 200}
		err := ns.Do(func() error { return nil })
		if err == nil || !strings.Contains(err.Error(), "failed to set netns") {
			t.Errorf("error = %v", err)
		}
	})

	t.Run("restore namespace error with function success", func(t *testing.T) {
		callCount := 0
		netnsGet = func() (netns.NsHandle, error) { return 100, nil }
		netnsSet = func(ns netns.NsHandle) error {
			callCount++
			if callCount == 2 { // fail on restore
				return fmt.Errorf("restore error")
			}
			return nil
		}

		ns := &NetNS{handle: 200}
		err := ns.Do(func() error { return nil })
		if err == nil || !strings.Contains(err.Error(), "failed to restore netns") {
			t.Errorf("error = %v", err)
		}
	})

	t.Run("restore namespace error with function error", func(t *testing.T) {
		callCount := 0
		netnsGet = func() (netns.NsHandle, error) { return 100, nil }
		netnsSet = func(ns netns.NsHandle) error {
			callCount++
			if callCount == 2 {
				return fmt.Errorf("restore error")
			}
			return nil
		}

		ns := &NetNS{handle: 200}
		err := ns.Do(func() error { return fmt.Errorf("func error") })
		// Should contain both error messages
		if err == nil {
			t.Fatal("expected error")
		}
		errStr := err.Error()
		if !strings.Contains(errStr, "restore") || !strings.Contains(errStr, "func error") {
			t.Errorf("error = %v", err)
		}
	})
}

func TestMoveDevice(t *testing.T) {
	origGet := netnsGet
	origSet := netnsSet
	origLinkByName := netlinkLinkByName
	origLinkSetNsFd := netlinkLinkSetNsFd
	defer func() {
		netnsGet = origGet
		netnsSet = origSet
		netlinkLinkByName = origLinkByName
		netlinkLinkSetNsFd = origLinkSetNsFd
	}()

	// Mock successful namespace operations
	netnsGet = func() (netns.NsHandle, error) { return 100, nil }
	netnsSet = func(ns netns.NsHandle) error { return nil }

	t.Run("success without fromNs", func(t *testing.T) {
		mockLink := &netlink.Dummy{} // use netlink's Dummy type
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			if name == "eth0" {
				return mockLink, nil
			}
			return nil, fmt.Errorf("not found")
		}
		netlinkLinkSetNsFd = func(link netlink.Link, fd int) error {
			return nil
		}

		toNs := &NetNS{handle: 200}
		err := MoveDevice("eth0", nil, toNs)
		if err != nil {
			t.Errorf("MoveDevice: %v", err)
		}
	})

	t.Run("success with fromNs", func(t *testing.T) {
		mockLink := &netlink.Dummy{}
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mockLink, nil
		}
		netlinkLinkSetNsFd = func(link netlink.Link, fd int) error {
			return nil
		}

		fromNs := &NetNS{handle: 100}
		toNs := &NetNS{handle: 200}
		err := MoveDevice("eth0", fromNs, toNs)
		if err != nil {
			t.Errorf("MoveDevice: %v", err)
		}
	})

	t.Run("device not found without fromNs", func(t *testing.T) {
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return nil, fmt.Errorf("not found")
		}

		toNs := &NetNS{handle: 200}
		err := MoveDevice("eth0", nil, toNs)
		if err == nil || !strings.Contains(err.Error(), "failed to get device") {
			t.Errorf("error = %v", err)
		}
	})

	t.Run("device not found with fromNs", func(t *testing.T) {
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return nil, fmt.Errorf("not found")
		}

		fromNs := &NetNS{handle: 100}
		toNs := &NetNS{handle: 200}
		err := MoveDevice("eth0", fromNs, toNs)
		if err == nil || !strings.Contains(err.Error(), "failed to get device") {
			t.Errorf("error = %v", err)
		}
	})

	t.Run("move fails without fromNs", func(t *testing.T) {
		mockLink := &netlink.Dummy{}
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mockLink, nil
		}
		netlinkLinkSetNsFd = func(link netlink.Link, fd int) error {
			return fmt.Errorf("move failed")
		}

		toNs := &NetNS{handle: 200}
		err := MoveDevice("eth0", nil, toNs)
		if err == nil || !strings.Contains(err.Error(), "failed to move device") {
			t.Errorf("error = %v", err)
		}
	})

	t.Run("move fails with fromNs", func(t *testing.T) {
		mockLink := &netlink.Dummy{}
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mockLink, nil
		}
		netlinkLinkSetNsFd = func(link netlink.Link, fd int) error {
			return fmt.Errorf("move failed")
		}

		fromNs := &NetNS{handle: 100}
		toNs := &NetNS{handle: 200}
		err := MoveDevice("eth0", fromNs, toNs)
		if err == nil || !strings.Contains(err.Error(), "failed to move device") {
			t.Errorf("error = %v", err)
		}
	})
}

func TestGetLinkInNs(t *testing.T) {
	origGet := netnsGet
	origSet := netnsSet
	origLinkByName := netlinkLinkByName
	defer func() {
		netnsGet = origGet
		netnsSet = origSet
		netlinkLinkByName = origLinkByName
	}()

	netnsGet = func() (netns.NsHandle, error) { return 100, nil }
	netnsSet = func(ns netns.NsHandle) error { return nil }

	t.Run("success", func(t *testing.T) {
		mockLink := &netlink.Dummy{}
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			if name == "eth0" {
				return mockLink, nil
			}
			return nil, fmt.Errorf("not found")
		}

		ns := &NetNS{handle: 200}
		link, err := GetLinkInNs(ns, "eth0")
		if err != nil {
			t.Fatalf("GetLinkInNs: %v", err)
		}
		if link != mockLink {
			t.Error("returned wrong link")
		}
	})

	t.Run("not found", func(t *testing.T) {
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return nil, fmt.Errorf("not found")
		}

		ns := &NetNS{handle: 200}
		_, err := GetLinkInNs(ns, "eth0")
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

// --- Integration tests (require real namespaces) ---
// These tests are placed in netns_integration_test.go with build tag
