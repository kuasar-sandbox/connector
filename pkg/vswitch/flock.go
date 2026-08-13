package vswitch

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/cilium/ebpf"

	"github.com/kuasar-sandbox/connector/pkg/internal/bpf"
)

// ControlLock provides process-level mutual exclusion for control operations.
// In addition to switch lifecycle operations, ownership changes on switches
// with a geneve_opts map use it to keep the mmap slot and options map coherent.
// It uses flock on the bpffs pin directory.
type ControlLock struct {
	f *os.File
}

// Dependencies for testing.
var (
	osOpen       = os.Open
	syscallFlock = syscall.Flock
)

// AcquireControlLock acquires an exclusive lock on the switch's bpffs pin directory.
// The directory must already exist (created by StartReserved via os.Mkdir).
// It ensures bpffs is mounted and returns ErrSwitchNotExist if the directory is missing.
func AcquireControlLock(switchName string) (*ControlLock, error) {
	if err := bpfEnsureBPFFS(); err != nil {
		return nil, fmt.Errorf("failed to ensure bpffs: %w", err)
	}
	lockPath := filepath.Join(bpf.BPFPath, switchName)
	f, err := osOpen(lockPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("switch %s: %w", switchName, ErrSwitchNotExist)
		}
		return nil, fmt.Errorf("failed to open lock directory %s: %w", lockPath, err)
	}
	// LOCK_EX blocks until lock is available. This is safe because flock is
	// automatically released when the holding process exits (kernel guarantee),
	// so a crashed holder cannot leave a stale lock.
	if err := syscallFlock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("failed to acquire flock on %s: %w", lockPath, err)
	}
	return &ControlLock{f: f}, nil
}

// acquireCurrentSwitchControlLock locks the switch and then verifies that the
// context still refers to the map set currently pinned under that name. The
// verification is required after flock: while waiting for an old directory
// inode, StopReleased can remove it and a new switch can be created at the same
// path with an independent lock.
func acquireCurrentSwitchControlLock(s *switchContext) (*ControlLock, error) {
	lock, err := acquireControlLockFn(s.name)
	if err != nil {
		return nil, fmt.Errorf("failed to acquire control lock: %w", err)
	}
	if err := verifyCurrentSwitchFn(s); err != nil {
		lock.Release()
		return nil, fmt.Errorf("failed to verify current switch instance: %w", err)
	}
	return lock, nil
}

// verifyCurrentSwitch compares the opened slots map with the map currently
// pinned for the switch. A map ID is stable for the lifetime of the kernel map,
// including after its pin is removed, so an old open fd cannot be mistaken for
// a newly-created switch instance.
func verifyCurrentSwitch(s *switchContext) error {
	if s == nil || s.maps == nil || s.maps.Slots == nil {
		return fmt.Errorf("switch context has no slots map")
	}

	pinPath := filepath.Join(bpf.BPFPath, s.name, "slots")
	pinnedSlots, err := ebpf.LoadPinnedMap(pinPath, nil)
	if err != nil {
		return fmt.Errorf("load pinned slots map %s: %w", pinPath, err)
	}
	defer pinnedSlots.Close()

	openedInfo, err := s.maps.Slots.Info()
	if err != nil {
		return fmt.Errorf("inspect opened slots map: %w", err)
	}
	pinnedInfo, err := pinnedSlots.Info()
	if err != nil {
		return fmt.Errorf("inspect pinned slots map: %w", err)
	}
	openedID, ok := openedInfo.ID()
	if !ok {
		return fmt.Errorf("opened slots map has no kernel ID")
	}
	pinnedID, ok := pinnedInfo.ID()
	if !ok {
		return fmt.Errorf("pinned slots map has no kernel ID")
	}
	if openedID != pinnedID {
		return fmt.Errorf("switch %s was replaced while acquiring the control lock; reopen and retry", s.name)
	}
	return nil
}

// Release releases the flock and closes the directory fd.
func (l *ControlLock) Release() {
	if l.f != nil {
		syscallFlock(int(l.f.Fd()), syscall.LOCK_UN)
		l.f.Close()
		l.f = nil
	}
}
