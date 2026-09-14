//go:build integration

package vswitch

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
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
	var counters SlotStats
	if err := s.maps.Stats.LookupWithFlags(uint32(0), &counters, ebpf.LookupLock); err != nil {
		t.Fatal(err)
	}
	// Populate the actual locked counter instance without float loss.
	counters = SlotStats{Generation: counters.Generation, MgmtRxPackets: 11, MgmtRxBytes: 9007199254740993, MgmtTxPackets: 12, MgmtTxBytes: 22,
		TransitRxPackets: 31, TransitRxBytes: 41, TransitTxPackets: 32, TransitTxBytes: 42}
	if err := s.maps.Stats.Update(uint32(0), &counters, ebpf.UpdateLock); err != nil {
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
	t.Log("real pinned locked map: exact counters, detach/reuse, read-only reset failure and recovery verified")
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

// The wrapper executes real last-resort cleanup during a real map read. It
// leaves the old FD alive, exactly as a different process would observe it.
type cleanupDuringStatsRead struct {
	*ebpf.Map
	cleanup func() error
}

func (m *cleanupDuringStatsRead) LookupWithFlags(key, out any, flags ebpf.MapLookupFlags) error {
	if err := m.Map.LookupWithFlags(key, out, flags); err != nil {
		return err
	}
	return m.cleanup()
}

func TestNativeStatsRealForceCleanupDuringRead(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(fmt.Sprint(replace), func(t *testing.T) {
			s := nativeStatsFixture(t)
			if _, err := s.Attach(AttachOptions{Port: 1, InnerIP: net.ParseIP("169.254.0.21"), SkipDevice: true}); err != nil {
				t.Fatal(err)
			}
			s.statsMgr = NewStatsManager(&cleanupDuringStatsRead{Map: s.maps.Stats, cleanup: func() error {
				if err := ForceCleanup(s.name); err != nil {
					return err
				}
				if !replace {
					return nil
				}
				objects, err := bpf.LoadObjects()
				if err != nil {
					return err
				}
				t.Cleanup(func() { objects.Close() })
				if err := os.Mkdir(filepath.Join(bpf.BPFPath, s.name), 0755); err != nil {
					return err
				}
				return objects.PinMaps(s.name)
			}}, s.cfg.N_ports)
			if result, err := s.Stats([]int{1}); result != nil || !errors.Is(err, ErrStatsUnavailable) {
				t.Fatal("removed/replaced map published retained observation", result, err)
			}
		})
	}
}

func TestNativeStatsRealAttacherExitAfterClaim(t *testing.T) {
	if name := os.Getenv("CONNECTOR_STATS_CRASH_SWITCH"); name != "" {
		sw, err := Open(name)
		if err != nil {
			t.Fatal(err)
		}
		s := sw.(*switchContext)
		lock, err := acquireCurrentSwitchControlLock(s)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Release()
		if !s.mmapSlots.TryAllocate(0, bpf.IPToUint32(net.ParseIP("169.254.0.22"))) {
			t.Fatal("claim failed")
		}
		// Abrupt process death at the first instruction after the ownership CAS:
		// no Attach field update or defer can repair the published slot.
		_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
		panic("SIGKILL returned")
	}
	s := nativeStatsFixture(t)
	if _, err := s.Attach(AttachOptions{Port: 1, InnerIP: net.ParseIP("169.254.0.21"), SkipDevice: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.Detach(DetachOptions{Port: 1, SkipDevice: true}); err != nil {
		t.Fatal(err)
	}
	if s.mmapSlots.GetSlot(0).StatsReady != 1 {
		t.Fatal("fixture must retain the old readiness before the new claim")
	}
	child := exec.Command(os.Args[0], "-test.run=^TestNativeStatsRealAttacherExitAfterClaim$")
	child.Env = append(os.Environ(), "CONNECTOR_STATS_CRASH_SWITCH="+s.name)
	output, err := child.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ProcessState.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatalf("child was not killed at claimed owner: %v %s", err, output)
	}
	if s.mmapSlots.GetInnerIP(0) != bpf.IPToUint32(net.ParseIP("169.254.0.22")) {
		t.Fatal("child did not publish new owner")
	}
	if result, err := s.Stats([]int{1}); result != nil || !errors.Is(err, ErrStatsUnavailable) || errors.Is(err, syscall.EWOULDBLOCK) {
		t.Fatal("crashed owner exposed old counters or retained lock", result, err)
	}
}

func TestNativeStatsRealLateTCWriteAndLockedReset(t *testing.T) {
	_ = nativeStatsFixture(t) // Enforce the same required kernel capabilities.
	var objects statsProbeObjects
	if err := loadStatsProbeObjects(&objects, nil); err != nil {
		t.Fatal(err)
	}
	defer objects.Close()
	manager := NewStatsManager(objects.Stats, 1)
	if err := manager.ResetStats(0); err != nil {
		t.Fatal(err)
	}
	first, err := manager.GetStats(0)
	if err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 128)
	binary.LittleEndian.PutUint64(packet[16:], first.Generation)
	if _, _, err := objects.LateStatsWrite.Test(packet); err != nil {
		t.Fatal(err)
	}
	counted, err := manager.GetStats(0)
	if err != nil || counted.MgmtTxPackets != 1 || counted.MgmtTxBytes != uint64(len(packet)) {
		t.Fatal("real TC helper did not count", counted, err)
	}
	if err := manager.ResetStats(0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := objects.LateStatsWrite.Test(packet); err != nil {
		t.Fatal(err)
	}
	current, err := manager.GetStats(0)
	if err != nil || current.Generation != first.Generation+1 || current.MgmtTxPackets != 0 || current.MgmtTxBytes != 0 {
		t.Fatal("old TC generation survived reset", current, err)
	}

	// Keep actual TC executions racing userspace resets in four concurrent streams. A seeded
	// old counter must never resurrect, and every locked read must preserve
	// the exact packet/byte relation, including the final current generation.
	var senders sync.WaitGroup
	var runs atomic.Uint64
	ready := make(chan struct{}, 4)
	stop := make(chan struct{})
	for range 4 {
		senders.Add(1)
		go func() {
			defer senders.Done()
			data := make([]byte, 128)
			started := false
			defer func() {
				if !started {
					ready <- struct{}{}
				}
			}()
			for {
				select {
				case <-stop:
					return
				default:
				}
				value, err := manager.GetStats(0)
				if err != nil {
					t.Error(err)
					return
				}
				binary.LittleEndian.PutUint64(data[16:], value.Generation)
				if _, err := objects.LateStatsWrite.Run(&ebpf.RunOptions{Data: data, Repeat: 128}); err != nil {
					t.Error(err)
					return
				}
				runs.Add(1)
				if !started {
					ready <- struct{}{}
					started = true
				}
			}
		}()
	}
	defer func() { close(stop); senders.Wait() }()
	for range 4 {
		<-ready
	}
	before := runs.Load()
	for range 100 {
		prior, err := manager.GetStats(0)
		if err != nil {
			t.Fatal(err)
		}
		seed := SlotStats{Generation: prior.Generation, MgmtTxPackets: 1 << 48, MgmtTxBytes: 1 << 55}
		if err := objects.Stats.Update(uint32(0), &seed, ebpf.UpdateLock); err != nil {
			t.Fatal(err)
		}
		if err := manager.ResetStats(0); err != nil {
			t.Fatal(err)
		}
		for range 8 {
			value, err := manager.GetStats(0)
			if err != nil || value.MgmtTxPackets >= 1<<48 || value.MgmtTxBytes != value.MgmtTxPackets*128 {
				t.Fatal("concurrent TC/reset resurrected counters or tore a pair", value, err)
			}
		}
	}
	if runs.Load() <= before {
		t.Fatal("no real TC execution overlapped reset loop")
	}
	t.Logf("real TC executions during reset loop: %d", (runs.Load()-before)*128)

}

func TestNativeStatsRealLegacyCounterMapRejected(t *testing.T) {
	s := nativeStatsFixture(t)
	legacy, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: 64, MaxEntries: 64})
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Close()
	s.statsMgr = NewStatsManager(legacy, s.cfg.N_ports)
	if _, err := s.Attach(AttachOptions{Port: 1, InnerIP: net.ParseIP("169.254.0.21"), SkipDevice: true}); err != nil {
		t.Fatal("legacy map changed attachment success", err)
	}
	if result, err := s.Stats([]int{1}); result != nil || !errors.Is(err, ErrStatsUnavailable) {
		t.Fatal("legacy reset became a confirmed observation", result, err)
	}
}
