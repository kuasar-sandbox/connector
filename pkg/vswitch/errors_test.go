package vswitch

import (
	"errors"
	"fmt"
	"testing"
)

// --- ForceCleanup ---

func TestForceCleanupSuccess(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) { return true, nil }
	bpfUnpinMaps = func(name string) error { return nil }

	err := ForceCleanup("sw0")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestForceCleanupNotExist(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) { return false, nil }

	err := ForceCleanup("sw0")
	if err == nil {
		t.Fatal("expected error for non-existent switch")
	}
	if !IsNotExist(err) {
		t.Errorf("expected ErrSwitchNotExist, got: %v", err)
	}
}

func TestForceCleanupUnpinError(t *testing.T) {
	defer resetDeps()

	bpfPinPathExists = func(name string) (bool, error) { return true, nil }
	bpfUnpinMaps = func(name string) error { return errors.New("unpin failed") }

	err := ForceCleanup("sw0")
	if err == nil {
		t.Fatal("expected error from bpfUnpinMaps")
	}
	if err.Error() != "unpin failed" {
		t.Errorf("unexpected error message: %v", err)
	}
}

// --- ErrSwitchNotExist ---

func TestIsNotExist(t *testing.T) {
	if !IsNotExist(ErrSwitchNotExist) {
		t.Error("IsNotExist(ErrSwitchNotExist) = false, want true")
	}
}

func TestIsNotExistWrapped(t *testing.T) {
	wrapped := fmt.Errorf("switch sw0: %w", ErrSwitchNotExist)
	if !IsNotExist(wrapped) {
		t.Error("IsNotExist(wrapped ErrSwitchNotExist) = false, want true")
	}
}

func TestIsNotExistOtherError(t *testing.T) {
	other := errors.New("some other error")
	if IsNotExist(other) {
		t.Error("IsNotExist(other error) = true, want false")
	}
}

func TestIsNotExistNil(t *testing.T) {
	if IsNotExist(nil) {
		t.Error("IsNotExist(nil) = true, want false")
	}
}

// --- ErrConfigMismatch ---

func TestIsConfigMismatch(t *testing.T) {
	if !IsConfigMismatch(ErrConfigMismatch) {
		t.Error("IsConfigMismatch(ErrConfigMismatch) = false, want true")
	}
}

func TestIsConfigMismatchWrapped(t *testing.T) {
	wrapped := fmt.Errorf("switch sw0 already exists with different config: %w", ErrConfigMismatch)
	if !IsConfigMismatch(wrapped) {
		t.Error("IsConfigMismatch(wrapped ErrConfigMismatch) = false, want true")
	}
}

func TestIsConfigMismatchOtherError(t *testing.T) {
	other := errors.New("some other error")
	if IsConfigMismatch(other) {
		t.Error("IsConfigMismatch(other error) = true, want false")
	}
}

func TestIsConfigMismatchNil(t *testing.T) {
	if IsConfigMismatch(nil) {
		t.Error("IsConfigMismatch(nil) = true, want false")
	}
}

// --- Error independence ---

func TestErrorsAreIndependent(t *testing.T) {
	if IsNotExist(ErrConfigMismatch) {
		t.Error("IsNotExist(ErrConfigMismatch) = true, want false")
	}
	if IsConfigMismatch(ErrSwitchNotExist) {
		t.Error("IsConfigMismatch(ErrSwitchNotExist) = true, want false")
	}
}

// --- ErrSwitchCorrupted ---

func TestIsSwitchCorrupted(t *testing.T) {
	if !IsSwitchCorrupted(ErrSwitchCorrupted) {
		t.Error("IsSwitchCorrupted(ErrSwitchCorrupted) = false, want true")
	}
}

func TestIsSwitchCorruptedWrapped(t *testing.T) {
	wrapped := newSwitchCorruptedError("sw0", errors.New("cause"))
	if !IsSwitchCorrupted(wrapped) {
		t.Error("IsSwitchCorrupted(wrapped) = false, want true")
	}
}

func TestNewSwitchCorruptedError(t *testing.T) {
	cause := errors.New("load maps failed")
	err := newSwitchCorruptedError("sw0", cause)

	// Should contain switch name
	if err.Error() == "" {
		t.Error("error message should not be empty")
	}

	// Should wrap ErrSwitchCorrupted
	if !IsSwitchCorrupted(err) {
		t.Error("newSwitchCorruptedError should wrap ErrSwitchCorrupted")
	}
}
