package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestEgressStatusReportsSavedSnapshotAge(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "status.json")
	// A stale file and a nonexistent PID still constitute a readable saved
	// observation. The command must not mistake them for a liveness assertion.
	raw := `{"pid":2147483647,"configuration_generation":4,"reload_error":"bad candidate","counter":18446744073709551615}`
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	updated := now.Add(-24 * time.Hour)
	if err := os.Chtimes(path, updated, updated); err != nil {
		t.Fatal(err)
	}
	report, err := readEgressStatus(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	if report.Path != path || !report.UpdatedAt.Equal(updated) || report.AgeSeconds != 86400 {
		t.Fatalf("unexpected observation metadata: %+v", report)
	}
	encoded, err := json.Marshal(report)
	if err != nil || !bytes.Contains(encoded, []byte("18446744073709551615")) {
		t.Fatalf("lost native counter precision: %s (%v)", encoded, err)
	}
	if string(report.Snapshot) != raw {
		t.Fatalf("changed native snapshot: %s", report.Snapshot)
	}
}

func TestEgressStatusRejectsUnreadableOrMalformedSnapshots(t *testing.T) {
	for _, test := range []struct{ name, raw string }{
		{"missing", ""}, {"truncated", `{"pid":`}, {"array", `[]`},
		{"null", `null`}, {"trailing-value", `{} {}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			if test.name != "missing" {
				if err := os.WriteFile(filepath.Join(dir, "status.json"), []byte(test.raw), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := readEgressStatus(dir, time.Now()); err == nil {
				t.Fatal("accepted absent or malformed snapshot")
			}
		})
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "status.json"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := readEgressStatus(dir, time.Now()); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("accepted non-file: %v", err)
	}
}

func TestEgressStatusCommandConfigAndRecoveryPath(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "gateway.yaml")
	// This is a valid file configuration, with no corresponding namespace,
	// interface or dataplane executable. Status must only read the snapshot.
	configData := "name: test\nruntime_dir: " + dir + "\ninterfaces:\n  - {name: ingress, address: 198.18.0.1/24, mtu: 1500}\nattachments:\n  - {name: test, interface: ingress}\nareas:\n  - {vni: 7}\n"
	if err := os.WriteFile(config, []byte(configData), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "status.json"), []byte(`{"configuration_generation":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (string, error) {
		cmd := newEgressCommand()
		var output bytes.Buffer
		cmd.SetOut(&output)
		cmd.SetErr(&output)
		cmd.SetArgs(args)
		err := cmd.Execute()
		return output.String(), err
	}
	for _, args := range [][]string{{"status", "--config", config}, {"status", "--runtime-dir", dir}} {
		out, err := run(args...)
		var report egressStatusReport
		if err != nil || json.Unmarshal([]byte(out), &report) != nil || len(report.Snapshot) == 0 {
			t.Fatalf("status %q: %s (%v)", args, out, err)
		}
	}
	if err := os.WriteFile(config, []byte("invalid: ["), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := run("status", "--config", config); err == nil || !strings.Contains(err.Error(), "--runtime-dir") {
		t.Fatalf("missing invalid-config recovery hint: %v", err)
	}
	if _, err := run("status", "--runtime-dir", dir); err != nil {
		t.Fatalf("could not inspect retained snapshot with invalid candidate: %v", err)
	}
	for _, args := range [][]string{{"status"}, {"status", "--config", config, "--runtime-dir", dir}, {"status", "--runtime-dir="}, {"status", "--runtime-dir", dir, "extra"}} {
		if _, err := run(args...); err == nil {
			t.Fatalf("accepted invalid arguments %q", args)
		}
	}
}

func TestEgressStatusRejectsFIFOWithoutWaitingForAWriter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "status.json")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := readEgressStatus(dir, time.Now())
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("accepted FIFO: %v", err)
		}
	case <-time.After(5 * time.Second):
		// Unblock an accidentally blocking read-open before reporting failure.
		if writer, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			writer.Close()
		}
		t.Fatal("status waited for a FIFO writer")
	}
}
