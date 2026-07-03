//go:build integration

package bpf_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kuasar-sandbox/connector/pkg/internal/bpf"
)

// createPinDir creates the pin directory for a switch (required before PinMaps).
func createPinDir(t *testing.T, switchName string) {
	t.Helper()
	pinPath := filepath.Join(bpf.BPFPath, switchName)
	if err := os.Mkdir(pinPath, 0755); err != nil && !os.IsExist(err) {
		t.Fatalf("failed to create pin directory: %v", err)
	}
}

// TestPinPathExists verifies PinPathExists returns correct results.
func TestPinPathExists(t *testing.T) {
	// Non-existent switch should return false
	exists, err := bpf.PinPathExists("nonexistent-switch-12345")
	if err != nil {
		t.Fatalf("PinPathExists returned error: %v", err)
	}
	if exists {
		t.Error("PinPathExists returned true for nonexistent switch")
	}
}

// TestPinPathExistsWithPinnedMaps verifies PinPathExists returns true when maps are pinned.
func TestPinPathExistsWithPinnedMaps(t *testing.T) {
	ensureBPFEnv(t)

	switchName := "test-pinpathexist"

	// Load and pin maps
	objs, err := bpf.LoadObjects()
	if err != nil {
		t.Fatalf("LoadObjects: %v", err)
	}
	defer objs.Close()

	createPinDir(t, switchName)
	if err := objs.PinMaps(switchName); err != nil {
		t.Fatalf("PinMaps: %v", err)
	}
	defer bpf.UnpinMaps(switchName)

	// Now PinPathExists should return true
	exists, err := bpf.PinPathExists(switchName)
	if err != nil {
		t.Fatalf("PinPathExists returned error: %v", err)
	}
	if !exists {
		t.Error("PinPathExists returned false for pinned maps")
	}
}

// TestUnpinMaps verifies UnpinMaps removes pinned maps.
func TestUnpinMaps(t *testing.T) {
	ensureBPFEnv(t)

	switchName := "test-unpinmaps"

	// Load and pin maps
	objs, err := bpf.LoadObjects()
	if err != nil {
		t.Fatalf("LoadObjects: %v", err)
	}
	defer objs.Close()

	createPinDir(t, switchName)
	if err := objs.PinMaps(switchName); err != nil {
		t.Fatalf("PinMaps: %v", err)
	}

	// Verify pin path exists
	exists, err := bpf.PinPathExists(switchName)
	if err != nil {
		t.Fatalf("PinPathExists returned error: %v", err)
	}
	if !exists {
		t.Fatal("PinPathExists returned false after PinMaps")
	}

	// Unpin maps
	if err := bpf.UnpinMaps(switchName); err != nil {
		t.Fatalf("UnpinMaps: %v", err)
	}

	// Verify pin path no longer exists
	exists, err = bpf.PinPathExists(switchName)
	if err != nil {
		t.Fatalf("PinPathExists returned error: %v", err)
	}
	if exists {
		t.Error("PinPathExists returned true after UnpinMaps")
	}
}

// TestUnpinMapsNonExistent verifies UnpinMaps handles non-existent switch gracefully.
func TestUnpinMapsNonExistent(t *testing.T) {
	// Unpinning a non-existent switch should not error
	err := bpf.UnpinMaps("nonexistent-switch-67890")
	if err != nil {
		t.Errorf("UnpinMaps failed for non-existent switch: %v", err)
	}
}

// TestLoadPinnedMaps verifies LoadPinnedMaps works with pinned maps.
func TestLoadPinnedMaps(t *testing.T) {
	ensureBPFEnv(t)

	switchName := "test-loadpinned"

	// Load and pin maps
	objs, err := bpf.LoadObjects()
	if err != nil {
		t.Fatalf("LoadObjects: %v", err)
	}

	createPinDir(t, switchName)
	if err := objs.PinMaps(switchName); err != nil {
		objs.Close()
		t.Fatalf("PinMaps: %v", err)
	}

	// Close original objects
	objs.Close()

	// Load pinned maps
	maps, err := bpf.LoadPinnedMaps(switchName)
	if err != nil {
		bpf.UnpinMaps(switchName)
		t.Fatalf("LoadPinnedMaps: %v", err)
	}
	defer maps.Close()
	defer bpf.UnpinMaps(switchName)

	// Verify all maps are loaded
	if maps.Slots == nil {
		t.Error("Slots map is nil")
	}
	if maps.Config == nil {
		t.Error("Config map is nil")
	}
	if maps.Stats == nil {
		t.Error("Stats map is nil")
	}
	if maps.IfindexToSlot == nil {
		t.Error("IfindexToSlot map is nil")
	}
}

// TestLoadPinnedMapsNonExistent verifies LoadPinnedMaps fails for non-existent switch.
func TestLoadPinnedMapsNonExistent(t *testing.T) {
	_, err := bpf.LoadPinnedMaps("nonexistent-switch-11111")
	if err == nil {
		t.Error("LoadPinnedMaps succeeded for non-existent switch")
	}
}

// TestObjectsClose verifies Objects.Close handles nil fields gracefully.
func TestObjectsClose(t *testing.T) {
	// Test with nil Programs and Maps
	objs := &bpf.Objects{}
	if err := objs.Close(); err != nil {
		t.Errorf("Close failed with nil fields: %v", err)
	}

	// Test with empty Programs and Maps
	objs = &bpf.Objects{
		Programs: &bpf.Programs{},
		Maps:     &bpf.Maps{},
	}
	if err := objs.Close(); err != nil {
		t.Errorf("Close failed with empty fields: %v", err)
	}
}

// TestMapsClose verifies Maps.Close handles nil fields gracefully.
func TestMapsClose(t *testing.T) {
	// Test with nil fields
	maps := &bpf.Maps{}
	if err := maps.Close(); err != nil {
		t.Errorf("Close failed with nil fields: %v", err)
	}
}

// TestBPFPath verifies the BPF filesystem path constant.
func TestBPFPath(t *testing.T) {
	expected := "/sys/fs/bpf"
	if bpf.BPFPath != expected {
		t.Errorf("BPFPath = %q, want %q", bpf.BPFPath, expected)
	}
}

// TestPinPathExistsPartialPinPath verifies PinPathExists detects directory even without slots.
func TestPinPathExistsPartialPinPath(t *testing.T) {
	// Create a directory without the slots file
	tmpSwitch := "test-partial-" + t.Name()
	pinPath := filepath.Join(bpf.BPFPath, tmpSwitch)

	// This test may fail if /sys/fs/bpf doesn't exist or isn't writable
	// In that case, skip the test
	if _, err := os.Stat(bpf.BPFPath); os.IsNotExist(err) {
		t.Skip("BPF filesystem not available")
	}

	// Try to create directory - skip if permission denied
	if err := os.MkdirAll(pinPath, 0755); err != nil {
		t.Skip("Cannot create directory in BPF filesystem:", err)
	}
	defer os.RemoveAll(pinPath)

	// PinPathExists should return true since the directory exists (even without slots)
	exists, err := bpf.PinPathExists(tmpSwitch)
	if err != nil {
		t.Fatalf("PinPathExists returned error: %v", err)
	}
	if !exists {
		t.Error("PinPathExists returned false for directory without slots file")
	}
}

// TestLoadPinnedMapsConfigFailure tests error handling when config map is missing.
func TestLoadPinnedMapsConfigFailure(t *testing.T) {
	ensureBPFEnv(t)

	switchName := "test-config-fail"

	// Load and pin maps
	objs, err := bpf.LoadObjects()
	if err != nil {
		t.Fatalf("LoadObjects: %v", err)
	}

	createPinDir(t, switchName)
	if err := objs.PinMaps(switchName); err != nil {
		objs.Close()
		t.Fatalf("PinMaps: %v", err)
	}
	objs.Close()

	// Remove config map, keeping slots
	pinPath := filepath.Join(bpf.BPFPath, switchName)
	if err := os.Remove(filepath.Join(pinPath, "config")); err != nil {
		bpf.UnpinMaps(switchName)
		t.Fatalf("Failed to remove config: %v", err)
	}

	// LoadPinnedMaps should fail
	_, err = bpf.LoadPinnedMaps(switchName)
	if err == nil {
		t.Error("expected error when config map is missing")
	}

	bpf.UnpinMaps(switchName)
}

// TestLoadPinnedMapsStatsFailure tests error handling when stats map is missing.
func TestLoadPinnedMapsStatsFailure(t *testing.T) {
	ensureBPFEnv(t)

	switchName := "test-stats-fail"

	// Load and pin maps
	objs, err := bpf.LoadObjects()
	if err != nil {
		t.Fatalf("LoadObjects: %v", err)
	}

	createPinDir(t, switchName)
	if err := objs.PinMaps(switchName); err != nil {
		objs.Close()
		t.Fatalf("PinMaps: %v", err)
	}
	objs.Close()

	// Remove stats map, keeping slots and config
	pinPath := filepath.Join(bpf.BPFPath, switchName)
	if err := os.Remove(filepath.Join(pinPath, "stats")); err != nil {
		bpf.UnpinMaps(switchName)
		t.Fatalf("Failed to remove stats: %v", err)
	}

	// LoadPinnedMaps should fail
	_, err = bpf.LoadPinnedMaps(switchName)
	if err == nil {
		t.Error("expected error when stats map is missing")
	}

	bpf.UnpinMaps(switchName)
}

// TestLoadPinnedMapsIfindexFailure tests error handling when ifindex_to_slot map is missing.
func TestLoadPinnedMapsIfindexFailure(t *testing.T) {
	ensureBPFEnv(t)

	switchName := "test-ifindex-fail"

	// Load and pin maps
	objs, err := bpf.LoadObjects()
	if err != nil {
		t.Fatalf("LoadObjects: %v", err)
	}

	createPinDir(t, switchName)
	if err := objs.PinMaps(switchName); err != nil {
		objs.Close()
		t.Fatalf("PinMaps: %v", err)
	}
	objs.Close()

	// Remove ifindex_to_slot map
	pinPath := filepath.Join(bpf.BPFPath, switchName)
	if err := os.Remove(filepath.Join(pinPath, "ifindex_to_slot")); err != nil {
		bpf.UnpinMaps(switchName)
		t.Fatalf("Failed to remove ifindex_to_slot: %v", err)
	}

	// LoadPinnedMaps should fail
	_, err = bpf.LoadPinnedMaps(switchName)
	if err == nil {
		t.Error("expected error when ifindex_to_slot map is missing")
	}

	bpf.UnpinMaps(switchName)
}
