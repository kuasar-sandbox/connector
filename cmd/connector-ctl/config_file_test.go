package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/kuasar-sandbox/connector/pkg/vswitch"
)

func TestStartServeLayeredConfig(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.yaml")      // JSON input despite its extension.
	layer := filepath.Join(dir, "instance.json") // YAML input despite its extension.
	if err := os.WriteFile(base, []byte(`{"switch_name":"file-name","switch_netns":"switch_ns","port_netns":"port_ns","num_ports":4,"mac_addr":"02:00:00:00:00:01","floating_ip_base":"100.100.96.0","mtu":1500}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layer, []byte("MTU: 9000\ntransit_dev: eth1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	oldPath, oldMode, oldMTU, oldReserved := startConfigFile, startMode, startMTU, startReserved
	t.Cleanup(func() {
		startConfigFile, startMode, startMTU, startReserved = oldPath, oldMode, oldMTU, oldReserved
		resetDeps()
	})
	for _, serve := range []bool{false, true} {
		name := "start"
		if serve {
			name = "serve"
		}
		t.Run(name, func(t *testing.T) {
			startConfigFile, startMode, startMTU, startReserved = base+":"+layer, "veth", 1234, false
			vswitchLoadConfigFile = vswitch.LoadConfigFile
			captured := errors.New("configuration captured before network startup")
			var got *vswitch.Config
			capture := func(cfg *vswitch.Config) (*vswitch.StartOutput, error) {
				got = cfg
				return nil, captured
			}
			vswitchStart, vswitchStartReserved = capture, capture
			var err error
			if serve {
				err = runServe(nil, []string{"cli-name"})
			} else {
				err = runStart(nil, []string{"cli-name"})
			}
			if !errors.Is(err, captured) {
				t.Fatalf("expected startup boundary, got %v", err)
			}
			if got.Name != "cli-name" || got.MTU != 9000 || got.TransitDev != "eth1" || got.DefaultMode != vswitch.PortKindVeth {
				t.Fatalf("config/CLI precedence changed: %#v", got)
			}
		})
	}
}
