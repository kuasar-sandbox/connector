// Package netns provides network namespace management utilities.
package netns

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// NetNS represents a network namespace.
type NetNS struct {
	name   string
	handle netns.NsHandle
}

// ErrNotExist indicates a namespace does not exist.
var ErrNotExist = os.ErrNotExist

// Function variables for testing (can be replaced with mocks)
var (
	netnsGet           = netns.Get
	netnsSet           = netns.Set
	netnsGetFromName   = netns.GetFromName
	netlinkLinkByName  = netlink.LinkByName
	netlinkLinkSetNsFd = netlink.LinkSetNsFd

	// netnsBasePath is the base path for network namespaces
	netnsBasePath = "/var/run/netns"

	// osStat wraps os.Stat for testing
	osStat = os.Stat
)

// nsHandleCloseFunc is the function type for closing NsHandle
type nsHandleCloseFunc func(netns.NsHandle) error

// nsHandleCloseDefault is the default implementation for closing NsHandle
func nsHandleCloseDefault(h netns.NsHandle) error {
	return h.Close()
}

// nsHandleClose is the function variable for closing NsHandle (can be replaced for testing)
var nsHandleClose nsHandleCloseFunc = nsHandleCloseDefault

// GetByName returns a NetNS handle for the given namespace name.
// The namespace must already exist. Returns an error wrapping ErrNotExist
// if the namespace does not exist.
func GetByName(name string) (*NetNS, error) {
	nsPath := filepath.Join(netnsBasePath, name)
	if _, err := osStat(nsPath); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("netns %s: %w", name, ErrNotExist)
		}
		return nil, fmt.Errorf("stat netns %s: %w", name, err)
	}

	handle, err := netnsGetFromName(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get netns %s: %w", name, err)
	}

	return &NetNS{name: name, handle: handle}, nil
}

// GetCurrent returns the current network namespace.
func GetCurrent() (*NetNS, error) {
	handle, err := netnsGet()
	if err != nil {
		return nil, fmt.Errorf("failed to get current netns: %w", err)
	}
	return &NetNS{name: "", handle: handle}, nil
}

// Name returns the namespace name (empty for current namespace).
func (ns *NetNS) Name() string {
	return ns.name
}

// Handle returns the underlying netns handle.
func (ns *NetNS) Handle() netns.NsHandle {
	return ns.handle
}

// Close releases the namespace handle.
func (ns *NetNS) Close() error {
	return nsHandleClose(ns.handle)
}

// Do executes a function within the network namespace.
// The function is executed with the current goroutine locked to its OS thread.
func (ns *NetNS) Do(f func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Save current namespace
	origNs, err := netnsGet()
	if err != nil {
		return fmt.Errorf("failed to get current netns: %w", err)
	}
	defer origNs.Close()

	// Switch to target namespace
	if err := netnsSet(ns.handle); err != nil {
		return fmt.Errorf("failed to set netns: %w", err)
	}

	// Execute function
	funcErr := f()

	// Restore original namespace
	if err := netnsSet(origNs); err != nil {
		if funcErr != nil {
			return fmt.Errorf("failed to restore netns: %w (original error: %v)", err, funcErr)
		}
		return fmt.Errorf("failed to restore netns: %w", err)
	}

	return funcErr
}

// MoveDevice moves a network device from one namespace to another.
func MoveDevice(devName string, fromNs, toNs *NetNS) error {
	var link netlink.Link
	var err error

	// Get link in source namespace
	if fromNs != nil {
		err = fromNs.Do(func() error {
			link, err = netlinkLinkByName(devName)
			return err
		})
	} else {
		link, err = netlinkLinkByName(devName)
	}
	if err != nil {
		return fmt.Errorf("failed to get device %s: %w", devName, err)
	}

	// Move to target namespace
	if fromNs != nil {
		err = fromNs.Do(func() error {
			return netlinkLinkSetNsFd(link, int(toNs.handle))
		})
	} else {
		err = netlinkLinkSetNsFd(link, int(toNs.handle))
	}
	if err != nil {
		return fmt.Errorf("failed to move device %s to netns: %w", devName, err)
	}

	return nil
}

// GetLinkInNs gets a link by name within a namespace.
func GetLinkInNs(ns *NetNS, name string) (netlink.Link, error) {
	var link netlink.Link
	var err error

	err = ns.Do(func() error {
		link, err = netlinkLinkByName(name)
		return err
	})
	if err != nil {
		return nil, err
	}
	return link, nil
}
