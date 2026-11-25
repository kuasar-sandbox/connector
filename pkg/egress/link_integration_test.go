//go:build integration

package egress

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

func testLink(t *testing.T, suffix string) LinkConfig {
	t.Helper()
	if os.Geteuid() != 0 {
		if os.Getenv("REQUIRE_CONNECTOR_EGRESS") == "1" {
			t.Fatal("Egress ownership validation requires root")
		}
		t.Skip("requires root and network namespaces")
	}
	tag := fmt.Sprintf("egt%d%s", os.Getpid(), suffix)
	dir := t.TempDir()
	c := LinkConfig{Name: tag, OwnerNS: tag + "o", GatewayNS: tag + "g", SwitchNS: tag + "s", Switch: tag, Transit: tag + "t", Gateway: tag + "e", MTU: 9000, StateDir: filepath.Join(dir, "state"), GatewayRuntimeDir: filepath.Join(dir, "runtime")}
	t.Cleanup(func() {
		for _, name := range []string{c.GatewayNS, c.OwnerNS, c.SwitchNS} {
			_ = netns.DeleteNamed(name)
		}
	})
	return c
}
func borrowedNamespaces(t *testing.T, c LinkConfig) {
	t.Helper()
	for _, name := range []string{c.OwnerNS, c.GatewayNS} {
		var record namespaceRecord
		if err := ensureNamespace(name, &record); err != nil {
			t.Fatal(err)
		}
	}
}
func dummy(t *testing.T, ns, name string, remove bool) {
	t.Helper()
	err := inNamespace(ns, func() error {
		if !remove {
			return netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}})
		}
		link, err := netlink.LinkByName(name)
		if err != nil {
			return err
		}
		return netlink.LinkDel(link)
	})
	if err != nil {
		t.Fatal(err)
	}
}
func TestLocalLinkBorrowedResourcesAndForeignNames(t *testing.T) {
	c := testLink(t, "a")
	borrowedNamespaces(t, c)
	dummy(t, c.OwnerNS, c.Transit, false)
	if _, err := PrepareLink(c); err == nil {
		t.Fatal("adopted foreign same-name endpoint")
	}
	if link, err := findLink(c.OwnerNS, c.Transit); err != nil || link == nil || link.Type() != "dummy" {
		t.Fatalf("changed foreign endpoint: %v", err)
	}
	dummy(t, c.OwnerNS, c.Transit, true)
	first, err := PrepareLink(c)
	if err != nil || !first.PairValid {
		t.Fatalf("prepare: %+v %v", first, err)
	}
	dummy(t, c.GatewayNS, "foreign-exit", false)
	if err = UninstallLink(c); err != nil {
		t.Fatal(err)
	}
	if link, err := findLink(c.GatewayNS, "foreign-exit"); err != nil || link == nil {
		t.Fatalf("deleted borrowed Pool resource: %v", err)
	}
	if handle, e := netns.GetFromName(c.OwnerNS); e != nil {
		t.Fatal("deleted borrowed owner namespace")
	} else {
		handle.Close()
	}
}
func TestLocalLinkPartialUninstallIsRetryable(t *testing.T) {
	c := testLink(t, "b")
	if _, err := PrepareLink(c); err != nil {
		t.Fatal(err)
	}
	dummy(t, c.OwnerNS, "foreign-exit", false)
	if err := UninstallLink(c); err == nil {
		t.Fatal("deleted occupied namespace")
	}
	if handle, err := netns.GetFromName(c.GatewayNS); err == nil {
		handle.Close()
		t.Fatal("empty owned gateway namespace was not reclaimed")
	}
	dummy(t, c.OwnerNS, "foreign-exit", true)
	if err := UninstallLink(c); err != nil {
		t.Fatalf("partial cleanup cannot be retried: %v", err)
	}
	if err := UninstallLink(c); err != nil {
		t.Fatal(err)
	}
}
func TestLocalLinkFailedPrepareReclaimsOnlyNewNamespace(t *testing.T) {
	c := testLink(t, "c")
	path := filepath.Join("/var/run/netns", c.GatewayNS)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	t.Cleanup(func() { os.Remove(path) })
	if _, err = PrepareLink(c); err == nil {
		t.Fatal("accepted a regular file as network namespace")
	}
	if handle, err := netns.GetFromName(c.OwnerNS); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			handle.Close()
		}
		t.Fatalf("leaked new owner namespace: %v", err)
	}
	if _, err = os.Stat(path); err != nil {
		t.Fatal("deleted foreign invalid namespace path")
	}
}
