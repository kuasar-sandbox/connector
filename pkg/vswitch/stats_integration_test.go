//go:build integration

package vswitch

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/kuasar-sandbox/connector/pkg/internal/bpf"
)

// This uses pinned kernel maps, mmap slot publication and directory flocks.
// Required source CI must execute it; a skip is only for unprivileged local runs.
func nativeStatsFixture(t testing.TB) *switchContext {
	t.Helper()
	if os.Geteuid() != 0 {
		if os.Getenv("REQUIRE_CONNECTOR_STATS") == "1" {
			t.Fatal("real connector stats tests require root and a BPF-capable kernel")
		}
		t.Skip("requires root and a BPF-capable kernel")
	}
	if err := bpf.EnsureBPFFS(); err != nil {
		t.Fatal(err)
	}
	objects, err := bpf.LoadObjects()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { objects.Close() })
	name := fmt.Sprintf("test-native-stats-%d", os.Getpid())
	if err := os.Mkdir(filepath.Join(bpf.BPFPath, name), 0755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bpf.UnpinMaps(name) })
	if err := objects.PinMaps(name); err != nil {
		t.Fatal(err)
	}
	cfg := &SwitchConfig{N_ports: 64, FloatingIpBase: bpf.IPToUint32(net.ParseIP("198.18.0.1"))}
	if err := objects.Maps.Config.Update(uint32(0), cfg, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if err := SaveMetadata(objects.Maps.Metadata, &SwitchMetadata{}); err != nil {
		t.Fatal(err)
	}
	mapped, err := NewMmappedSlots(objects.Maps.Slots, cfg.N_ports)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mapped.Close() })
	return &switchContext{name: name, maps: objects.Maps, cfg: cfg, meta: &SwitchMetadata{},
		mmapSlots: mapped, statsMgr: NewStatsManager(objects.Maps.Stats, cfg.N_ports)}
}

func TestNativeStatsRealResetReuseAndReadOnlyFailure(t *testing.T) {
	s := nativeStatsFixture(t)
	attach := AttachOptions{Port: 1, InnerIP: net.ParseIP("169.254.0.21"), SkipDevice: true}
	if _, err := s.Attach(attach); err != nil {
		t.Fatal(err)
	}
	reader, err := Open(s.name)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var counters []SlotStats
	if err := s.maps.Stats.Lookup(uint32(0), &counters); err != nil {
		t.Fatal(err)
	}
	// Populate one actual per-CPU entry; the API must sum without float loss.
	counters[0] = SlotStats{MgmtRxPackets: 11, MgmtRxBytes: 9007199254740993, MgmtTxPackets: 12, MgmtTxBytes: 22,
		TransitRxPackets: 31, TransitRxBytes: 41, TransitTxPackets: 32, TransitTxBytes: 42}
	if err := s.maps.Stats.Update(uint32(0), counters, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	result, err := reader.Stats([]int{1})
	if err != nil || len(result.Ports) != 1 || result.Ports[0].MgmtRxBytes != 9007199254740993 || result.Ports[0].TransitTxBytes != 42 {
		t.Fatal("real counter observation mismatch", result, err)
	}
	if err := s.Detach(DetachOptions{Port: 1, SkipDevice: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Stats([]int{1}); !errors.Is(err, ErrPortNotAttached) {
		t.Fatal("detached port accepted", err)
	}
	readOnly, err := ebpf.LoadPinnedMap(filepath.Join(bpf.BPFPath, s.name, "stats"), &ebpf.LoadPinOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer readOnly.Close()
	// Prove a real kernel reset failure, then use that same FD during Attach.
	s.statsMgr = NewStatsManager(readOnly, s.cfg.N_ports)
	if err := s.statsMgr.ResetStats(0); !errors.Is(err, syscall.EPERM) {
		t.Fatal("read-only map did not reject reset", err)
	}
	attach.InnerIP = net.ParseIP("169.254.0.22")
	if _, err := s.Attach(attach); err != nil {
		t.Fatal("stats reset failure changed attachment success", err)
	}
	if result, err := reader.Stats([]int{1}); result != nil || !errors.Is(err, ErrStatsUnavailable) {
		t.Fatal("another map reader accepted previous owner counters", result, err)
	}
	if err := s.Detach(DetachOptions{Port: 1, SkipDevice: true}); err != nil {
		t.Fatal(err)
	}
	s.statsMgr = NewStatsManager(s.maps.Stats, s.cfg.N_ports)
	if _, err := s.Attach(attach); err != nil {
		t.Fatal(err)
	}
	result, err = reader.Stats([]int{1})
	if err != nil || result.Ports[0].InnerIP != attach.InnerIP.String() || result.Ports[0].MgmtRxBytes != 0 || result.Ports[0].TransitTxBytes != 0 {
		t.Fatal("successful reset did not publish current zero", result, err)
	}
	t.Log("real pinned per-CPU map: exact counters, detach/reuse, read-only reset failure and recovery verified")
}

func TestNativeStatsRealConcurrentOwnership(t *testing.T) {
	s := nativeStatsFixture(t)
	reader, err := Open(s.name)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var readers sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				result, err := reader.Stats([]int{1})
				if err != nil {
					if !errors.Is(err, ErrStatsUnavailable) && !errors.Is(err, ErrPortNotAttached) {
						t.Error(err)
						return
					}
					continue
				}
				if len(result.Ports) != 1 || result.Ports[0].InnerIP != "169.254.0.21" || result.Ports[0].MgmtRxBytes != 0 {
					t.Error("invalid current attachment observation", result)
					return
				}
			}
		}()
	}
	defer func() { close(stop); readers.Wait() }()
	for range 40 {
		if _, err := s.Attach(AttachOptions{Port: 1, InnerIP: net.ParseIP("169.254.0.21"), SkipDevice: true}); err != nil {
			t.Fatal(err)
		}
		if err := s.Detach(DetachOptions{Port: 1, SkipDevice: true}); err != nil {
			t.Fatal(err)
		}
	}
}

func BenchmarkNativeTrafficStats(b *testing.B) {
	for _, count := range []int{1, 16, 64} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			s := nativeStatsFixture(b)
			ports := make([]int, count)
			for i := range ports {
				ports[i] = i + 1
				if _, err := s.Attach(AttachOptions{Port: i + 1, InnerIP: net.ParseIP("169.254.0.21"), SkipDevice: true}); err != nil {
					b.Fatal(err)
				}
			}
			fdBefore, err := os.ReadDir("/proc/self/fd")
			if err != nil {
				b.Fatal(err)
			}
			goroutines := runtime.NumGoroutine()
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, err := s.Stats(ports); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			fdAfter, err := os.ReadDir("/proc/self/fd")
			if err != nil {
				b.Fatal(err)
			}
			b.ReportMetric(float64(len(fdAfter)-len(fdBefore)), "fd_delta")
			b.ReportMetric(float64(runtime.NumGoroutine()-goroutines), "goroutine_delta")
		})
	}
}
