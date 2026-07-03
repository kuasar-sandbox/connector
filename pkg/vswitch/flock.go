package vswitch

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/kuasar-sandbox/connector/pkg/internal/bpf"
)

// ControlLock provides process-level mutual exclusion for control operations
// (Start, Stop, ProvisionPorts). It uses flock on the bpffs pin directory.
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

// Release releases the flock and closes the directory fd.
func (l *ControlLock) Release() {
	if l.f != nil {
		syscallFlock(int(l.f.Fd()), syscall.LOCK_UN)
		l.f.Close()
		l.f = nil
	}
}
