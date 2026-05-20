package vswitch

import (
	"errors"
	"fmt"
	"os"
	"testing"
)

func TestAcquireControlLockSuccess(t *testing.T) {
	defer resetDeps()

	bpfEnsureBPFFS = func() error { return nil }
	dir := t.TempDir()
	osOpen = func(name string) (*os.File, error) { return os.Open(dir) }
	syscallFlock = func(fd int, how int) error { return nil }

	lock, err := AcquireControlLock("test-sw")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if lock == nil {
		t.Fatal("lock is nil")
	}
	lock.Release()
}

func TestAcquireControlLockOpenError(t *testing.T) {
	defer resetDeps()

	bpfEnsureBPFFS = func() error { return nil }
	osOpen = func(name string) (*os.File, error) {
		return nil, fmt.Errorf("no such directory")
	}

	_, err := AcquireControlLock("test-sw")
	if err == nil {
		t.Fatal("expected error")
	}
	if got := err.Error(); !contains(got, "failed to open lock directory") {
		t.Errorf("unexpected error: %s", got)
	}
}

func TestAcquireControlLockFlockError(t *testing.T) {
	defer resetDeps()

	bpfEnsureBPFFS = func() error { return nil }
	dir := t.TempDir()
	osOpen = func(name string) (*os.File, error) { return os.Open(dir) }
	syscallFlock = func(fd int, how int) error {
		return fmt.Errorf("flock failed")
	}

	_, err := AcquireControlLock("test-sw")
	if err == nil {
		t.Fatal("expected error")
	}
	if got := err.Error(); !contains(got, "failed to acquire flock") {
		t.Errorf("unexpected error: %s", got)
	}
}

func TestControlLockReleaseNilFile(t *testing.T) {
	defer resetDeps()
	// Release on lock with nil file should not panic
	lock := &ControlLock{f: nil}
	lock.Release() // should be no-op
}

func TestControlLockReleaseWithFile(t *testing.T) {
	defer resetDeps()

	dir := t.TempDir()
	f, err := os.Open(dir)
	if err != nil {
		t.Fatalf("failed to open dir: %v", err)
	}

	flockCalled := false
	syscallFlock = func(fd int, how int) error {
		flockCalled = true
		return nil
	}

	lock := &ControlLock{f: f}
	lock.Release()

	if !flockCalled {
		t.Error("syscallFlock not called during Release")
	}
	if lock.f != nil {
		t.Error("f should be nil after Release")
	}
}

func TestAcquireControlLockNotExist(t *testing.T) {
	defer resetDeps()

	bpfEnsureBPFFS = func() error { return nil }
	osOpen = func(name string) (*os.File, error) {
		return nil, os.ErrNotExist
	}

	_, err := AcquireControlLock("test-sw")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrSwitchNotExist) {
		t.Errorf("expected ErrSwitchNotExist, got: %v", err)
	}
}

func TestAcquireControlLockEnsureBPFFSError(t *testing.T) {
	defer resetDeps()

	bpfEnsureBPFFS = func() error { return fmt.Errorf("bpffs not mounted") }

	_, err := AcquireControlLock("test-sw")
	if err == nil {
		t.Fatal("expected error")
	}
	if got := err.Error(); !contains(got, "failed to ensure bpffs") {
		t.Errorf("unexpected error: %s", got)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
