package vswitch

import (
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

func statsLockFixture(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	bpfEnsureBPFFS = func() error { return nil }
	osOpen = func(string) (*os.File, error) { return os.Open(dir) }
	syscallFlock = syscall.Flock
	acquireControlLockFn = AcquireControlLock
	verifyCurrentSwitchFn = func(*switchContext) error { return nil }
}

type resettableStatsMap struct {
	value    SlotStats
	resetErr error
}

func (m *resettableStatsMap) Lookup(_ interface{}, out interface{}) error {
	stats, ok := out.(*SlotStats)
	if !ok {
		return syscall.EINVAL // The locked array has one value per slot.
	}
	*stats = m.value
	return nil
}
func (m *resettableStatsMap) LookupWithFlags(key, out any, flags ebpf.MapLookupFlags) error {
	if flags != ebpf.LookupLock {
		return syscall.EINVAL
	}
	return m.Lookup(key, out)
}
func (m *resettableStatsMap) Update(_ interface{}, value interface{}, _ ebpf.MapUpdateFlags) error {
	if m.resetErr != nil {
		return m.resetErr
	}
	m.value = *value.(*SlotStats)
	return nil
}
func (*resettableStatsMap) Delete(interface{}) error { return nil }

func TestStatsResetValidityAcrossDetachAndReuse(t *testing.T) {
	defer resetDeps()
	s, slots := newGeneveAttachTestContext(&SwitchConfig{N_ports: 2}, true)
	statsLockFixture(t)
	writeGeneveOptsFn = func(BPFMap, uint32, *GeneveOptsValue) error { return nil }
	values := &resettableStatsMap{value: SlotStats{MgmtRxBytes: 91, TransitTxBytes: 72}}
	s.statsMgr = NewStatsManager(values, 2)
	attach := AttachOptions{Port: 1, InnerIP: net.ParseIP("169.254.0.21"), SkipDevice: true}
	if _, err := s.Attach(attach); err != nil {
		t.Fatal(err)
	}
	output, err := s.Stats([]int{1})
	if err != nil || len(output.Ports) != 1 || output.Ports[0].MgmtRxBytes != 0 || output.Ports[0].TransitTxBytes != 0 || slots.GetSlot(0).StatsReady != 1 {
		t.Fatal("confirmed reset did not publish valid zero", output, err)
	}
	values.value = SlotStats{Generation: 1, MgmtRxPackets: 11, MgmtRxBytes: 9007199254740993, MgmtTxPackets: 12, MgmtTxBytes: 22,
		TransitRxPackets: 31, TransitRxBytes: 41, TransitTxPackets: 32, TransitTxBytes: 42}
	output, err = s.Stats([]int{1})
	if err != nil || output.Ports[0].MgmtRxBytes != 9007199254740993 || output.Ports[0].TransitRxBytes != 41 {
		t.Fatal("counter value or scope changed", output, err)
	}
	if err := s.Detach(DetachOptions{Port: 1, SkipDevice: true}); err != nil {
		t.Fatal(err)
	}
	if output, err := s.Stats([]int{1}); output != nil || !errors.Is(err, ErrPortNotAttached) {
		t.Fatal("detached port returned retained counters", output, err)
	}
	values.resetErr = errors.New("reset failed")
	if _, err := s.Attach(attach); err != nil {
		t.Fatal("telemetry reset changed attachment success", err)
	}
	if slots.GetSlot(0).StatsReady != 0 {
		t.Fatal("failed reset marked ready")
	}
	if output, err := s.Stats([]int{1}); output != nil || !errors.Is(err, ErrStatsUnavailable) {
		t.Fatal("previous attachment counters returned as current", output, err)
	}
	if err := s.Detach(DetachOptions{Port: 1, SkipDevice: true}); err != nil {
		t.Fatal(err)
	}
	values.resetErr = nil
	if _, err := s.Attach(attach); err != nil {
		t.Fatal(err)
	}
	if output, err := s.Stats([]int{1}); err != nil || output.Ports[0].MgmtRxBytes != 0 {
		t.Fatal("new successful attach did not recover valid stats", output, err)
	}
}

func TestStatsControlContentionAndReplacementFailClosed(t *testing.T) {
	defer resetDeps()
	s, slots := newGeneveAttachTestContext(&SwitchConfig{N_ports: 2}, true)
	statsLockFixture(t)
	slots.TryAllocate(0, 1)
	slots.GetSlot(0).StatsReady = 1
	lock, err := AcquireControlLock(s.name)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	start := time.Now()
	if result, err := s.Stats([]int{1}); result != nil || !errors.Is(err, ErrStatsUnavailable) || !errors.Is(err, syscall.EWOULDBLOCK) {
		t.Fatal("stats did not fail on held control lock", result, err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("stats waited behind control work")
	}
	lock.Release()
	verifyCurrentSwitchFn = func(*switchContext) error { return errors.New("map replaced") }
	if result, err := s.Stats([]int{1}); result != nil || !errors.Is(err, ErrStatsUnavailable) {
		t.Fatal("replaced switch accepted", result, err)
	}
	// The failed identity check released its shared lock and FD.
	lock, err = acquireSwitchLock(s.name, syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		t.Fatal("failed read leaked observation lock", err)
	}
	lock.Release()
}

func TestStatsSkipsReservedAndRejectsUnconfirmedLegacy(t *testing.T) {
	defer resetDeps()
	s, slots := newGeneveAttachTestContext(&SwitchConfig{N_ports: 2}, false)
	statsLockFixture(t)
	InitSlotReserved(slots, 0)
	if output, err := s.Stats(nil); err != nil || len(output.Ports) != 0 {
		t.Fatal("reserved slot published as allocated stats", output, err)
	}
	slots.TryAllocate(1, 2)
	slots.GetSlot(1).StatsReady = 1
	if output, err := s.Stats([]int{2}); output != nil || !errors.Is(err, ErrStatsUnavailable) {
		t.Fatal("legacy unsynchronized ownership accepted", output, err)
	}
}

func TestStatsGenerationExhaustionDoesNotFailAttach(t *testing.T) {
	defer resetDeps()
	s, slots := newGeneveAttachTestContext(&SwitchConfig{N_ports: 1}, true)
	statsLockFixture(t)
	writeGeneveOptsFn = func(BPFMap, uint32, *GeneveOptsValue) error { return nil }
	values := &resettableStatsMap{value: SlotStats{Generation: ^uint64(0), MgmtRxBytes: 91}}
	s.statsMgr = NewStatsManager(values, 1)
	if _, err := s.Attach(AttachOptions{Port: 1, InnerIP: net.ParseIP("169.254.0.21"), SkipDevice: true}); err != nil {
		t.Fatal("counter generation changed attach success", err)
	}
	if slots.GetSlot(0).StatsReady != 0 || values.value.Generation != ^uint64(0) || values.value.MgmtRxBytes != 91 {
		t.Fatal("generation wrapped or failed reset mutated counters", values.value)
	}
	if result, err := s.Stats([]int{1}); result != nil || !errors.Is(err, ErrStatsUnavailable) {
		t.Fatal("exhausted generation published a current observation", result, err)
	}
}
