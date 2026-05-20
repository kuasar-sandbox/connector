package netlink

import (
	"errors"
	"syscall"
	"testing"

	"github.com/vishvananda/netlink"
)

// mockQdisc implements netlink.Qdisc interface for testing
type mockQdisc struct {
	netlink.QdiscAttrs
	qdiscType string
}

func (q *mockQdisc) Attrs() *netlink.QdiscAttrs {
	return &q.QdiscAttrs
}

func (q *mockQdisc) Type() string {
	return q.qdiscType
}

// saveTCDeps saves TC-related netlink function variables for restoration
func saveTCDeps() func() {
	origLinkByName := netlinkLinkByName
	origQdiscList := netlinkQdiscList
	origQdiscAdd := netlinkQdiscAdd
	origQdiscDel := netlinkQdiscDel
	origFilterList := netlinkFilterList
	origFilterAdd := netlinkFilterAdd
	origFilterDel := netlinkFilterDel

	return func() {
		netlinkLinkByName = origLinkByName
		netlinkQdiscList = origQdiscList
		netlinkQdiscAdd = origQdiscAdd
		netlinkQdiscDel = origQdiscDel
		netlinkFilterList = origFilterList
		netlinkFilterAdd = origFilterAdd
		netlinkFilterDel = origFilterDel
	}
}

func TestEnsureClsactQdisc(t *testing.T) {
	defer saveTCDeps()()

	t.Run("clsact already exists", func(t *testing.T) {
		qdiscAddCalled := false
		netlinkQdiscList = func(link netlink.Link) ([]netlink.Qdisc, error) {
			return []netlink.Qdisc{
				&mockQdisc{qdiscType: "clsact"},
			}, nil
		}
		netlinkQdiscAdd = func(qdisc netlink.Qdisc) error {
			qdiscAddCalled = true
			return nil
		}

		mock := mockLink("eth0", 1)
		err := ensureClsactQdisc(mock)
		if err != nil {
			t.Errorf("ensureClsactQdisc failed: %v", err)
		}
		if qdiscAddCalled {
			t.Error("QdiscAdd should not be called when clsact already exists")
		}
	})

	t.Run("clsact does not exist", func(t *testing.T) {
		qdiscAddCalled := false
		netlinkQdiscList = func(link netlink.Link) ([]netlink.Qdisc, error) {
			return []netlink.Qdisc{
				&mockQdisc{qdiscType: "fq_codel"},
			}, nil
		}
		netlinkQdiscAdd = func(qdisc netlink.Qdisc) error {
			qdiscAddCalled = true
			gq := qdisc.(*netlink.GenericQdisc)
			if gq.QdiscType != "clsact" {
				t.Errorf("expected clsact qdisc type, got %s", gq.QdiscType)
			}
			return nil
		}

		mock := mockLink("eth0", 1)
		err := ensureClsactQdisc(mock)
		if err != nil {
			t.Errorf("ensureClsactQdisc failed: %v", err)
		}
		if !qdiscAddCalled {
			t.Error("QdiscAdd not called")
		}
	})

	t.Run("empty qdisc list", func(t *testing.T) {
		qdiscAddCalled := false
		netlinkQdiscList = func(link netlink.Link) ([]netlink.Qdisc, error) {
			return []netlink.Qdisc{}, nil
		}
		netlinkQdiscAdd = func(qdisc netlink.Qdisc) error {
			qdiscAddCalled = true
			return nil
		}

		mock := mockLink("eth0", 1)
		err := ensureClsactQdisc(mock)
		if err != nil {
			t.Errorf("ensureClsactQdisc failed: %v", err)
		}
		if !qdiscAddCalled {
			t.Error("QdiscAdd not called")
		}
	})

	t.Run("qdisc list fails", func(t *testing.T) {
		netlinkQdiscList = func(link netlink.Link) ([]netlink.Qdisc, error) {
			return nil, errors.New("permission denied")
		}

		mock := mockLink("eth0", 1)
		err := ensureClsactQdisc(mock)
		if err == nil {
			t.Error("expected error when qdisc list fails")
		}
	})

	t.Run("qdisc add fails", func(t *testing.T) {
		netlinkQdiscList = func(link netlink.Link) ([]netlink.Qdisc, error) {
			return []netlink.Qdisc{}, nil
		}
		netlinkQdiscAdd = func(qdisc netlink.Qdisc) error {
			return errors.New("invalid argument")
		}

		mock := mockLink("eth0", 1)
		err := ensureClsactQdisc(mock)
		if err == nil {
			t.Error("expected error when qdisc add fails")
		}
	})
}

func TestDetachTCFromLink(t *testing.T) {
	defer saveTCDeps()()

	t.Run("success with filters", func(t *testing.T) {
		filterDelCount := 0
		netlinkFilterList = func(link netlink.Link, parent uint32) ([]netlink.Filter, error) {
			return []netlink.Filter{
				&netlink.BpfFilter{},
				&netlink.BpfFilter{},
			}, nil
		}
		netlinkFilterDel = func(filter netlink.Filter) error {
			filterDelCount++
			return nil
		}

		mock := mockLink("eth0", 1)
		err := detachTCFromLink(mock)
		if err != nil {
			t.Errorf("detachTCFromLink failed: %v", err)
		}
		// 2 filters for ingress + 2 filters for egress
		if filterDelCount != 4 {
			t.Errorf("expected 4 filter deletions, got %d", filterDelCount)
		}
	})

	t.Run("success with no filters", func(t *testing.T) {
		netlinkFilterList = func(link netlink.Link, parent uint32) ([]netlink.Filter, error) {
			return []netlink.Filter{}, nil
		}

		mock := mockLink("eth0", 1)
		err := detachTCFromLink(mock)
		if err != nil {
			t.Errorf("detachTCFromLink failed: %v", err)
		}
	})

	t.Run("filter list fails gracefully", func(t *testing.T) {
		netlinkFilterList = func(link netlink.Link, parent uint32) ([]netlink.Filter, error) {
			return nil, errors.New("no such device")
		}

		mock := mockLink("eth0", 1)
		err := detachTCFromLink(mock)
		// Should not return error, just skip deletion
		if err != nil {
			t.Errorf("detachTCFromLink failed: %v", err)
		}
	})

	t.Run("filter del fails gracefully", func(t *testing.T) {
		netlinkFilterList = func(link netlink.Link, parent uint32) ([]netlink.Filter, error) {
			return []netlink.Filter{
				&netlink.BpfFilter{},
			}, nil
		}
		netlinkFilterDel = func(filter netlink.Filter) error {
			return errors.New("no such filter")
		}

		mock := mockLink("eth0", 1)
		err := detachTCFromLink(mock)
		// Should not return error, just ignore deletion errors
		if err != nil {
			t.Errorf("detachTCFromLink failed: %v", err)
		}
	})
}

func TestDetachTC(t *testing.T) {
	defer saveTCDeps()()

	t.Run("success", func(t *testing.T) {
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mockLink(name, 1), nil
		}
		netlinkFilterList = func(link netlink.Link, parent uint32) ([]netlink.Filter, error) {
			return []netlink.Filter{}, nil
		}

		err := DetachTC("eth0")
		if err != nil {
			t.Errorf("DetachTC failed: %v", err)
		}
	})

	t.Run("link not found", func(t *testing.T) {
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return nil, errors.New("link not found")
		}

		err := DetachTC("noexist")
		if err == nil {
			t.Error("expected error when link not found")
		}
	})
}

func TestRemoveClsactQdisc(t *testing.T) {
	defer saveTCDeps()()

	t.Run("success", func(t *testing.T) {
		qdiscDelCalled := false
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mockLink(name, 1), nil
		}
		netlinkQdiscDel = func(qdisc netlink.Qdisc) error {
			qdiscDelCalled = true
			gq := qdisc.(*netlink.GenericQdisc)
			if gq.QdiscType != "clsact" {
				t.Errorf("expected clsact qdisc type, got %s", gq.QdiscType)
			}
			return nil
		}

		err := RemoveClsactQdisc("eth0")
		if err != nil {
			t.Errorf("RemoveClsactQdisc failed: %v", err)
		}
		if !qdiscDelCalled {
			t.Error("QdiscDel not called")
		}
	})

	t.Run("link not found", func(t *testing.T) {
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return nil, errors.New("link not found")
		}

		err := RemoveClsactQdisc("noexist")
		if err == nil {
			t.Error("expected error when link not found")
		}
	})

	t.Run("qdisc del fails", func(t *testing.T) {
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mockLink(name, 1), nil
		}
		netlinkQdiscDel = func(qdisc netlink.Qdisc) error {
			return errors.New("no such qdisc")
		}

		err := RemoveClsactQdisc("eth0")
		if err == nil {
			t.Error("expected error when qdisc del fails")
		}
	})
}

func TestHasTCFilter(t *testing.T) {
	defer saveTCDeps()()

	t.Run("has BPF filter on ingress", func(t *testing.T) {
		netlinkFilterList = func(link netlink.Link, parent uint32) ([]netlink.Filter, error) {
			if parent == netlink.HANDLE_MIN_INGRESS {
				return []netlink.Filter{
					&netlink.BpfFilter{},
				}, nil
			}
			return []netlink.Filter{}, nil
		}

		if !HasTCFilter(mockLink("eth0", 1), Ingress) {
			t.Error("expected HasTCFilter to return true")
		}
	})

	t.Run("has BPF filter on egress", func(t *testing.T) {
		netlinkFilterList = func(link netlink.Link, parent uint32) ([]netlink.Filter, error) {
			if parent == netlink.HANDLE_MIN_EGRESS {
				return []netlink.Filter{
					&netlink.BpfFilter{},
				}, nil
			}
			return []netlink.Filter{}, nil
		}

		if !HasTCFilter(mockLink("eth0", 1), Egress) {
			t.Error("expected HasTCFilter to return true")
		}
	})

	t.Run("no BPF filter", func(t *testing.T) {
		netlinkFilterList = func(link netlink.Link, parent uint32) ([]netlink.Filter, error) {
			return []netlink.Filter{}, nil
		}

		if HasTCFilter(mockLink("eth0", 1), Ingress) {
			t.Error("expected HasTCFilter to return false")
		}
	})

	t.Run("has non-BPF filter", func(t *testing.T) {
		netlinkFilterList = func(link netlink.Link, parent uint32) ([]netlink.Filter, error) {
			return []netlink.Filter{
				&netlink.U32{}, // Not a BPF filter
			}, nil
		}

		if HasTCFilter(mockLink("eth0", 1), Ingress) {
			t.Error("expected HasTCFilter to return false for non-BPF filter")
		}
	})

	t.Run("filter list fails", func(t *testing.T) {
		netlinkFilterList = func(link netlink.Link, parent uint32) ([]netlink.Filter, error) {
			return nil, errors.New("permission denied")
		}

		if HasTCFilter(mockLink("eth0", 1), Ingress) {
			t.Error("expected HasTCFilter to return false when filter list fails")
		}
	})
}

func TestAttachTCToLink(t *testing.T) {
	defer saveTCDeps()()

	t.Run("ensure clsact fails", func(t *testing.T) {
		netlinkQdiscList = func(link netlink.Link) ([]netlink.Qdisc, error) {
			return nil, errors.New("permission denied")
		}

		mock := mockLink("eth0", 1)
		err := attachTCToLink(mock, nil, Ingress)
		if err == nil {
			t.Error("expected error when ensure clsact fails")
		}
	})
}

func TestAttachTC(t *testing.T) {
	defer saveTCDeps()()

	t.Run("link not found", func(t *testing.T) {
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return nil, errors.New("link not found")
		}

		err := AttachTC("noexist", nil, Ingress)
		if err == nil {
			t.Error("expected error when link not found")
		}
	})

	t.Run("success path to attachTCToLink", func(t *testing.T) {
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return mockLink(name, 1), nil
		}
		// This will fail in attachTCToLink, but we've covered that path
		netlinkQdiscList = func(link netlink.Link) ([]netlink.Qdisc, error) {
			return nil, errors.New("test error")
		}

		err := AttachTC("eth0", nil, Ingress)
		if err == nil {
			t.Error("expected error from attachTCToLink")
		}
	})
}

// --- Shared block tests ---

func TestNewClsactWithBlock(t *testing.T) {
	qdisc := newClsactWithBlock(42, 100)
	gq := qdisc
	if gq.QdiscType != "clsact" {
		t.Errorf("expected clsact, got %s", gq.QdiscType)
	}
	if gq.QdiscAttrs.LinkIndex != 42 {
		t.Errorf("expected LinkIndex 42, got %d", gq.QdiscAttrs.LinkIndex)
	}
	if gq.QdiscAttrs.IngressBlock == nil {
		t.Fatal("expected IngressBlock to be set")
	}
	if *gq.QdiscAttrs.IngressBlock != 100 {
		t.Errorf("expected IngressBlock 100, got %d", *gq.QdiscAttrs.IngressBlock)
	}
}

func TestAddClsactWithBlock(t *testing.T) {
	defer saveTCDeps()()

	t.Run("success", func(t *testing.T) {
		netlinkQdiscAdd = func(qdisc netlink.Qdisc) error {
			gq := qdisc.(*netlink.GenericQdisc)
			if gq.QdiscAttrs.IngressBlock == nil || *gq.QdiscAttrs.IngressBlock != 100 {
				t.Error("expected IngressBlock=100")
			}
			return nil
		}
		if err := AddClsactWithBlock(42, 100); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("already exists is ignored", func(t *testing.T) {
		netlinkQdiscAdd = func(qdisc netlink.Qdisc) error {
			return syscall.EEXIST
		}
		if err := AddClsactWithBlock(42, 100); err != nil {
			t.Errorf("expected no error for EEXIST, got: %v", err)
		}
	})

	t.Run("other error propagated", func(t *testing.T) {
		netlinkQdiscAdd = func(qdisc netlink.Qdisc) error {
			return errors.New("permission denied")
		}
		if err := AddClsactWithBlock(42, 100); err == nil {
			t.Error("expected error")
		}
	})
}

func TestAddBlockFilter(t *testing.T) {
	defer saveTCDeps()()

	t.Run("correct parameters", func(t *testing.T) {
		netlinkFilterAdd = func(filter netlink.Filter) error {
			bf, ok := filter.(*netlink.BpfFilter)
			if !ok {
				t.Fatal("expected BpfFilter")
			}
			if bf.FilterAttrs.LinkIndex != TCM_IFINDEX_MAGIC_BLOCK {
				t.Errorf("expected LinkIndex=%d, got %d", TCM_IFINDEX_MAGIC_BLOCK, bf.FilterAttrs.LinkIndex)
			}
			if bf.FilterAttrs.Parent != 100 {
				t.Errorf("expected Parent=100, got %d", bf.FilterAttrs.Parent)
			}
			if !bf.DirectAction {
				t.Error("expected DirectAction=true")
			}
			return nil
		}
		// We can't create a real ebpf.Program, so this will panic on prog.FD().
		// Just verify the mock is called correctly by testing the filter add path.
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic from nil prog")
			}
		}()
		_ = AddBlockFilter(100, nil)
	})
}

func TestHasBlockFilter(t *testing.T) {
	defer saveTCDeps()()

	t.Run("has BPF filter", func(t *testing.T) {
		netlinkFilterList = func(link netlink.Link, parent uint32) ([]netlink.Filter, error) {
			if link.Attrs().Index != TCM_IFINDEX_MAGIC_BLOCK {
				t.Errorf("expected magic block ifindex, got %d", link.Attrs().Index)
			}
			if parent != 100 {
				t.Errorf("expected parent=100, got %d", parent)
			}
			return []netlink.Filter{&netlink.BpfFilter{}}, nil
		}
		if !HasBlockFilter(100) {
			t.Error("expected true")
		}
	})

	t.Run("no filter", func(t *testing.T) {
		netlinkFilterList = func(link netlink.Link, parent uint32) ([]netlink.Filter, error) {
			return []netlink.Filter{}, nil
		}
		if HasBlockFilter(100) {
			t.Error("expected false")
		}
	})

	t.Run("error returns false", func(t *testing.T) {
		netlinkFilterList = func(link netlink.Link, parent uint32) ([]netlink.Filter, error) {
			return nil, errors.New("permission denied")
		}
		if HasBlockFilter(100) {
			t.Error("expected false on error")
		}
	})

	t.Run("non-BPF filter returns false", func(t *testing.T) {
		netlinkFilterList = func(link netlink.Link, parent uint32) ([]netlink.Filter, error) {
			return []netlink.Filter{&netlink.U32{}}, nil
		}
		if HasBlockFilter(100) {
			t.Error("expected false for non-BPF filter")
		}
	})
}

func TestCreateDummyLink(t *testing.T) {
	defer saveTCDeps()()

	origLinkAdd := netlinkLinkAdd
	defer func() { netlinkLinkAdd = origLinkAdd }()

	t.Run("dummy success", func(t *testing.T) {
		netlinkLinkAdd = func(link netlink.Link) error {
			if _, ok := link.(*netlink.Dummy); !ok {
				t.Fatal("first attempt should be Dummy type")
			}
			return nil
		}
		if err := CreateDummyLink("sw0-dummy"); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("fallback to tap on EOPNOTSUPP", func(t *testing.T) {
		callCount := 0
		netlinkLinkAdd = func(link netlink.Link) error {
			callCount++
			if callCount == 1 {
				if _, ok := link.(*netlink.Dummy); !ok {
					t.Fatal("first attempt should be Dummy type")
				}
				return syscall.EOPNOTSUPP
			}
			if _, ok := link.(*netlink.Tuntap); !ok {
				t.Fatal("fallback should be Tuntap type")
			}
			return nil
		}
		if err := CreateDummyLink("sw0-dummy"); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if callCount != 2 {
			t.Errorf("expected 2 LinkAdd calls, got %d", callCount)
		}
	})

	t.Run("no fallback on other errors", func(t *testing.T) {
		callCount := 0
		netlinkLinkAdd = func(link netlink.Link) error {
			callCount++
			return errors.New("device exists")
		}
		if err := CreateDummyLink("sw0-dummy"); err == nil {
			t.Error("expected error")
		}
		if callCount != 1 {
			t.Errorf("should not fallback on non-EOPNOTSUPP, got %d calls", callCount)
		}
	})
}

func TestDeleteLinkByName(t *testing.T) {
	defer saveTCDeps()()

	t.Run("success", func(t *testing.T) {
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}, nil
		}
		origDel := netlinkLinkDel
		defer func() { netlinkLinkDel = origDel }()
		netlinkLinkDel = func(link netlink.Link) error { return nil }

		if err := deleteLinkByName("test-dev"); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("link not found", func(t *testing.T) {
		netlinkLinkByName = func(name string) (netlink.Link, error) {
			return nil, errors.New("not found")
		}
		err := deleteLinkByName("no-such-dev")
		if err == nil {
			t.Error("expected error")
		}
	})
}

func TestDeleteLinkByNameInNs(t *testing.T) {
	defer saveTCDeps()()

	origDel := netlinkLinkDel
	defer func() { netlinkLinkDel = origDel }()

	netlinkLinkByName = func(name string) (netlink.Link, error) {
		return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}, nil
	}
	netlinkLinkDel = func(link netlink.Link) error { return nil }

	mockNs := &mockNetNS{}
	if err := DeleteLinkByNameInNs(mockNs, "test-dev"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDirection(t *testing.T) {
	// Test direction constants
	if Ingress != 0 {
		t.Errorf("expected Ingress to be 0, got %d", Ingress)
	}
	if Egress != 1 {
		t.Errorf("expected Egress to be 1, got %d", Egress)
	}
}

func TestTCFilterPriority(t *testing.T) {
	if TCFilterPriority != 1 {
		t.Errorf("expected TCFilterPriority to be 1, got %d", TCFilterPriority)
	}
}
