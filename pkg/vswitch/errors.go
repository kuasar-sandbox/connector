package vswitch

import (
	"errors"
	"fmt"
)

// Sentinel errors for switch operations.
var (
	// ErrSwitchNotExist indicates switch does not exist.
	ErrSwitchNotExist = errors.New("switch does not exist")

	// ErrConfigMismatch indicates configuration mismatch with existing switch.
	ErrConfigMismatch = errors.New("configuration mismatch")

	// ErrSwitchCorrupted indicates the switch state is corrupted and cannot be loaded.
	ErrSwitchCorrupted = errors.New("switch state corrupted")

	// ErrPortOutOfRange indicates the port number exceeds the configured maximum.
	ErrPortOutOfRange = errors.New("port out of range")

	// ErrPortAllocated indicates the port is already allocated to another sandbox.
	ErrPortAllocated = errors.New("port already allocated")

	// ErrPortNotAttached indicates the port is not attached to any sandbox.
	ErrPortNotAttached = errors.New("port not attached")

	// ErrStatsUnavailable means a complete observation cannot be associated
	// with the current switch/attachment, including an unconfirmed reset.
	ErrStatsUnavailable = errors.New("port stats unavailable")

	// ErrPortsInUse indicates some ports are still allocated and cannot be stopped.
	ErrPortsInUse = errors.New("ports in use")

	// ErrPortsNotReleased indicates ports still have devices (ifindex != 0) or are Allocated.
	ErrPortsNotReleased = errors.New("ports not released")

	// ErrPortNotProvisioned indicates the port slot has not been provisioned
	// (no underlying device). Common in tap mode: attach requires provision to
	// have already created the persistent tap device.
	ErrPortNotProvisioned = errors.New("port not provisioned")
)

// IsNotExist returns true if the error indicates the switch does not exist.
func IsNotExist(err error) bool {
	return errors.Is(err, ErrSwitchNotExist)
}

// IsConfigMismatch returns true if the error indicates config mismatch.
func IsConfigMismatch(err error) bool {
	return errors.Is(err, ErrConfigMismatch)
}

// IsSwitchCorrupted returns true if the error indicates switch state is corrupted.
func IsSwitchCorrupted(err error) bool {
	return errors.Is(err, ErrSwitchCorrupted)
}

// IsPortOutOfRange returns true if the error indicates port number is out of range.
func IsPortOutOfRange(err error) bool {
	return errors.Is(err, ErrPortOutOfRange)
}

// IsPortAllocated returns true if the error indicates port is already allocated.
func IsPortAllocated(err error) bool {
	return errors.Is(err, ErrPortAllocated)
}

// IsPortNotAttached returns true if the error indicates port is not attached.
func IsPortNotAttached(err error) bool {
	return errors.Is(err, ErrPortNotAttached)
}

// IsPortsInUse returns true if the error indicates ports are still in use.
func IsPortsInUse(err error) bool {
	return errors.Is(err, ErrPortsInUse)
}

// IsPortsNotReleased returns true if the error indicates ports are not released.
func IsPortsNotReleased(err error) bool {
	return errors.Is(err, ErrPortsNotReleased)
}

// IsPortNotProvisioned returns true if the error indicates the port has not been provisioned.
func IsPortNotProvisioned(err error) bool {
	return errors.Is(err, ErrPortNotProvisioned)
}

// newSwitchCorruptedError creates an error indicating the switch state is corrupted.
func newSwitchCorruptedError(switchName string, cause error) error {
	return fmt.Errorf("switch %s: %w: %v", switchName, ErrSwitchCorrupted, cause)
}

// ForceCleanup removes all pinned BPF maps/programs for a switch.
// This is a last-resort operation for corrupted switches that cannot be
// normally stopped (e.g. old metadata format after upgrade).
// WARNING: does not clean up veth devices or move transit device back.
func ForceCleanup(switchName string) error {
	exists, err := bpfPinPathExists(switchName)
	if err != nil {
		return fmt.Errorf("check switch %s: %w", switchName, err)
	}
	if !exists {
		return fmt.Errorf("switch %s: %w", switchName, ErrSwitchNotExist)
	}
	return bpfUnpinMaps(switchName)
}
