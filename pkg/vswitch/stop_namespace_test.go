package vswitch

import (
	"github.com/kuasar-sandbox/connector/pkg/netlink"
	"github.com/kuasar-sandbox/connector/pkg/netns"
	"testing"
)

func TestStopMissingNamedNamespaceNeverDeletesCallerLinks(t *testing.T) {
	for _, tc := range []struct {
		name                          string
		force, releaseOnly, finalOnly bool
	}{
		{name: "stop-free"}, {name: "stop-allocated", force: true},
		{name: "release-free", releaseOnly: true},
		{name: "release-allocated", force: true, releaseOnly: true},
		{name: "stop-released", finalOnly: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer resetDeps()
			mockStartControlDeps()
			slots := mockStopSwitchWithMeta(2, &SwitchMetadata{SwitchNetNS: "removed", TransitDev: "eth0"}, func(s *MmappedSlots) {
				for i := uint32(0); i < 2; i++ {
					s.UpdateSlotFields(i, func(p *SlotItem) {
						if !tc.finalOnly {
							p.Ifindex = 3 + i
						}
						p.MgmtCidrCount = 2
						p.MgmtCidrs0.Ifindex = 13
						p.MgmtCidrsExt[0].Ifindex = 14
					})
					if tc.finalOnly {
						s.TryReserve(i, InnerIPFree)
					} else if tc.force {
						s.TryAllocate(i, 0x0a000001+i)
					}
				}
			})
			netnsGetByName = func(name string) (*netns.NetNS, error) {
				if name != "removed" {
					t.Errorf("wrong namespace %q", name)
				}
				return nil, netns.ErrNotExist
			}
			netlinkDelLinkByIndex = func(index int) error { t.Errorf("deleted caller ifindex %d", index); return nil }
			netlinkDelLinkByIndexInNs = func(_ netlink.NetNS, index int) error {
				t.Errorf("deleted missing-netns ifindex %d", index)
				return nil
			}
			netnsMoveDevice = func(name string, _, _ *netns.NetNS) error { t.Errorf("moved unrelated device %s", name); return nil }
			netlinkDeleteLinkByNameInNs = func(_ netlink.NetNS, name string) error { t.Errorf("deleted unrelated dummy %s", name); return nil }
			unpinned := false
			bpfUnpinMaps = func(string) error { unpinned = true; return nil }
			var err error
			switch {
			case tc.releaseOnly:
				var out *ReleaseOutput
				out, err = ReleasePorts("sw0", ReleaseOptions{Force: tc.force})
				if err == nil && (out.Released != 2 || out.Remaining != 0) {
					t.Errorf("bad release result %+v", out)
				}
			case tc.finalOnly:
				err = StopReleased("sw0")
			default:
				err = Stop("sw0", StopOptions{Force: tc.force})
			}
			if err != nil {
				t.Fatalf("cleanup failed: %v", err)
			}
			if unpinned == tc.releaseOnly {
				t.Errorf("unpinned=%v releaseOnly=%v", unpinned, tc.releaseOnly)
			}
			for i := uint32(0); i < 2; i++ {
				p := slots.GetSlot(i)
				if p.Ifindex != 0 || slots.GetInnerIP(i) != InnerIPReserved {
					t.Errorf("slot %d not released: %+v", i, p)
				}
				if !tc.releaseOnly && (p.MgmtCidrCount != 0 || p.MgmtCidrs0.Ifindex != 0 || p.MgmtCidrsExt[0].Ifindex != 0) {
					t.Errorf("slot %d retains management bookkeeping", i)
				}
			}
		})
	}
}

func TestStopEmptyNamespaceRetainsCallerDeletion(t *testing.T) {
	defer resetDeps()
	mockStartControlDeps()
	mockStopSwitchWithMeta(1, &SwitchMetadata{}, func(s *MmappedSlots) {
		s.UpdateSlotFields(0, func(p *SlotItem) { p.Ifindex = 3; p.MgmtCidrCount = 1; p.MgmtCidrs0.Ifindex = 4 })
	})
	netnsGetByName = func(string) (*netns.NetNS, error) { t.Fatal("empty namespace must not be resolved"); return nil, nil }
	var deleted []int
	netlinkDelLinkByIndex = func(index int) error { deleted = append(deleted, index); return nil }
	netlinkDelLinkByIndexInNs = func(_ netlink.NetNS, index int) error { t.Errorf("unexpected named deletion %d", index); return nil }
	if err := Stop("sw0", StopOptions{}); err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 2 || deleted[0] != 3 || deleted[1] != 4 {
		t.Fatalf("caller deletions=%v, want [3 4]", deleted)
	}
}
