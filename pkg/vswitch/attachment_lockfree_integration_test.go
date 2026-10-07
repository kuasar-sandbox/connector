//go:build integration

package vswitch

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

// An actual directory LOCK_EX must not gate capable attachment operations.
// Open a second context so this is not merely an in-memory allocation test.
func TestAttachmentIgnoresHeldManagementLock(t *testing.T) {
	s := nativeStatsFixture(t)
	lock, err := AcquireControlLock(s.name)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	other, err := acquireSwitchLock(s.name, syscall.LOCK_EX|syscall.LOCK_NB)
	if err == nil {
		other.Release()
		t.Fatal("management lock was not actually held")
	}
	if !errors.Is(err, syscall.EWOULDBLOCK) {
		t.Fatal(err)
	}
	sw, err := Open(s.name)
	if err != nil {
		t.Fatal(err)
	}
	defer sw.Close()
	done := make(chan error, 1)
	started := time.Now()
	go func() {
		for port := 1; port <= 16; port++ {
			if _, err := sw.Attach(AttachOptions{Port: port, InnerIP: net.ParseIP("169.254.0.21"), SkipDevice: true}); err != nil {
				done <- err
				return
			}
			if err := sw.Detach(DetachOptions{Port: port, SkipDevice: true}); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		// Release and join before the fixture unmaps memory, also on regression.
		lock.Release()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("attachment did not exit after unlocking")
		}
		t.Fatal("Attach/Detach waited behind management LOCK_EX")
	}
	for slot := uint32(0); slot < 16; slot++ {
		if s.mmapSlots.GetInnerIP(slot) != InnerIPFree || s.mmapSlots.GetSlot(slot).Flags != 0 {
			t.Fatalf("slot %d not released down", slot)
		}
	}
	t.Logf("16 real-map Attach/Detach pairs completed with management LOCK_EX continuously held in %s", time.Since(started))
}

func TestReserveTakesOverInFlightAttachWithoutLifecycleWait(t *testing.T) {
	defer resetDeps()
	s := nativeStatsFixture(t)
	entered := make(chan struct{}, 1)
	proceed := make(chan struct{})
	original := writeGeneveOptsFn
	writeGeneveOptsFn = func(m BPFMap, id uint32, value *GeneveOptsValue) error {
		if err := original(m, id, value); err != nil {
			return err
		}
		entered <- struct{}{}
		<-proceed
		return nil
	}
	attachDone := make(chan error, 1)
	go func() {
		_, err := s.Attach(AttachOptions{Port: 1, InnerIP: net.ParseIP("169.254.0.21"), SkipDevice: true})
		attachDone <- err
	}()
	select {
	case <-entered:
	case err := <-attachDone:
		close(proceed)
		t.Fatalf("Attach exited before preparation barrier: %v", err)
	case <-time.After(2 * time.Second):
		close(proceed)
		t.Fatal("Attach did not enter preparation")
	}
	reserveDone := make(chan error, 1)
	go func() { _, err := s.Reserve(ReserveOptions{Port: 1, Force: true}); reserveDone <- err }()
	select {
	case err := <-reserveDone:
		if err != nil {
			close(proceed)
			<-attachDone
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		close(proceed)
		<-attachDone
		<-reserveDone
		t.Fatal("Reserve waited for in-flight Attach")
	}
	// There is intentionally NO Reserved->Free/provision/reallocation here.
	close(proceed)
	err := <-attachDone
	if err == nil || !strings.Contains(err.Error(), "taken over") {
		t.Fatalf("Attach after takeover: %v", err)
	}
	slot := s.mmapSlots.GetSlot(0)
	if s.mmapSlots.GetInnerIP(0) != InnerIPReserved || slot.Flags != 0 || slot.StatsReady != 0 {
		t.Fatalf("takeover state: %+v", slot)
	}
	t.Log("Reserve acquired the allocated port while Attach was still in preparation; the management boundary remained closed")
}

// A same-binary comparison against the legacy EX path. This measures the SDK
// with real mmap/options/stats maps, not VM startup, TAP-FD or netns movement.
func BenchmarkAttachmentCycleConcurrent(b *testing.B) {
	for _, legacy := range []bool{true, false} {
		label := "cas-no-flock"
		if legacy {
			label = "legacy-exclusive-flock"
		}
		b.Run(label, func(b *testing.B) {
			s := nativeStatsFixture(b)
			if legacy {
				s.cfg.Features = 0
			}
			if err := s.maps.Config.Update(uint32(0), s.cfg, ebpf.UpdateAny); err != nil {
				b.Fatal(err)
			}
			ports := make(chan int, 32)
			for p := 1; p <= 32; p++ {
				ports <- p
			}
			innerIP := net.ParseIP("169.254.0.21")
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					p := <-ports
					_, err := s.Attach(AttachOptions{Port: p, InnerIP: innerIP, SkipDevice: true})
					if err == nil {
						err = s.Detach(DetachOptions{Port: p, SkipDevice: true})
					}
					ports <- p
					if err != nil {
						b.Error(fmt.Errorf("port %d: %w", p, err))
						return
					}
				}
			})
		})
	}
}
