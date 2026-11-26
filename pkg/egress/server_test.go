package egress

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDataplaneExecutableDiscovery(t *testing.T) {
	if os.Getenv("CONNECTOR_EGRESS_EXECUTABLE_HELPER") == "1" {
		path, err := dataplaneExecutable(os.Getenv("CONNECTOR_EGRESS_EXECUTABLE_OVERRIDE"))
		if err != nil {
			fmt.Print(err)
			os.Exit(1)
		}
		fmt.Print(path)
		os.Exit(0)
	}

	root := t.TempDir()
	installed := filepath.Join(root, "installed", "bin")
	unrelated := filepath.Join(root, "other-directory")
	alias := filepath.Join(root, "connector-ctl")
	for _, dir := range []string{installed, unrelated} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	control := filepath.Join(installed, "connector-ctl")
	if err = os.WriteFile(control, data, 0755); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(filepath.Join("installed", "bin", "connector-ctl"), alias); err != nil {
		t.Fatal(err)
	}
	writeExecutable := func(path string) {
		t.Helper()
		if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	sibling := filepath.Join(installed, "connector-vpp")
	explicit := filepath.Join(unrelated, "custom-dataplane")
	writeExecutable(sibling)
	writeExecutable(explicit)
	// A matching basename in both cwd and PATH must not influence discovery.
	writeExecutable(filepath.Join(unrelated, "connector-vpp"))
	run := func(name, executable, override, want, failure string) {
		t.Run(name, func(t *testing.T) {
			cmd := exec.Command(executable, "-test.run=^TestDataplaneExecutableDiscovery$")
			cmd.Dir = unrelated
			cmd.Env = append(os.Environ(), "PATH="+unrelated,
				"CONNECTOR_EGRESS_EXECUTABLE_HELPER=1",
				"CONNECTOR_EGRESS_EXECUTABLE_OVERRIDE="+override)
			output, err := cmd.CombinedOutput()
			if failure != "" {
				if err == nil || !strings.Contains(string(output), failure) || !strings.Contains(string(output), want) {
					t.Fatalf("want error containing %q and %q, got %s (%v)", failure, want, output, err)
				}
				return
			}
			if err != nil || string(output) != want {
				t.Fatalf("want %q, got %s (%v)", want, output, err)
			}
		})
	}
	run("default ignores cwd and PATH", control, "", sibling, "")
	run("default follows control symlink", alias, "", sibling, "")
	run("explicit override", control, explicit, explicit, "")
	if err = os.Remove(sibling); err != nil {
		t.Fatal(err)
	}
	run("missing default is actionable", control, "", sibling, "set vpp explicitly")
	run("explicit works without sibling", control, explicit, explicit, "")
	missing := filepath.Join(root, "missing-vpp")
	run("missing explicit path", control, missing, missing, "is unavailable")
	if err = os.Chmod(explicit, 0644); err != nil {
		t.Fatal(err)
	}
	run("nonexecutable rejected", control, explicit, explicit, "not a regular executable file")
	if err = os.Mkdir(sibling, 0755); err != nil {
		t.Fatal(err)
	}
	run("directory rejected", control, "", sibling, "not a regular executable file")
}

func TestOptionalDataplanePathPreservesReload(t *testing.T) {
	c := validConfig()
	c.VPP = ""
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if c.VPP != "" || strings.Contains(string(encoded), `"vpp"`) {
		t.Fatal("validation persisted a derived executable path")
	}
	runner := &recordingRunner{}
	engine, err := NewEngine(c, runner)
	if err != nil {
		t.Fatal(err)
	}
	c.Areas[0].Pools[0].MaxConnections++
	if err = engine.Reload(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if engine.config.VPP != "" {
		t.Fatal("reload persisted a derived executable path")
	}
	c.VPP = "./connector-vpp"
	if err = c.Validate(); err == nil {
		t.Fatal("relative explicit executable path accepted")
	}
}
