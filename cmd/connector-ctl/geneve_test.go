package main

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/kuasar-sandbox/connector/pkg/vswitch"
)

func TestBuildConfigGeneveTLVFlags(t *testing.T) {
	defer resetDeps()
	cleanup := setStartFlags("fixed")
	defer cleanup()
	startGeneveLocator = "tlv"
	startGeneveTLVLocator = "0102:81"

	cfg, err := buildConfig([]string{"sw0"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GeneveLocator != vswitch.GeneveLocatorTLV || cfg.GeneveTLVLocator == nil || cfg.GeneveTLVLocator.String() != "0102:81" {
		t.Fatalf("config = %#v", cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestShowGeneveConfigAndSlotOutput(t *testing.T) {
	cfg := &vswitch.SwitchConfig{
		N_ports:        4,
		FloatingIpBase: vswitch.IPToUint32([]byte{100, 100, 96, 0}),
		GeneveLocator:  uint8(vswitch.GeneveLocatorTLV),
		GeneveTlvClass: 0x0102,
		GeneveTlvType:  0x81,
	}
	config := ConfigJSON{
		GeneveLocator:    vswitch.GeneveLocatorFromSwitchConfig(cfg).String(),
		GenevePort:       vswitch.GeneveWirePort(vswitch.GeneveLocatorTLV, cfg.GenevePortBase, 0),
		GeneveTLVLocator: vswitch.GeneveTLVLocatorFromSwitchConfig(cfg).String(),
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	if fields["geneve_locator"] != "tlv" || fields["geneve_port"] != float64(6081) || fields["geneve_tlv_locator"] != "0102:81" {
		t.Fatalf("config JSON = %s", encoded)
	}

	slot := slotToJSON(cfg, vswitch.PortSlot{
		Port:      1,
		Allocated: true,
		SlotItem: vswitch.SlotItem{
			InnerIp:          vswitch.IPToUint32([]byte{10, 0, 0, 1}),
			TransitGeneveVni: 42,
			GeneveOptsLen:    12,
		},
	}, 0)
	if slot.TransitGeneveVNI != 42 || slot.GeneveOptsLen != 20 {
		t.Fatalf("slot JSON = %#v", slot)
	}
	freeSlot := slotToJSON(cfg, vswitch.PortSlot{Port: 2}, 1)
	if freeSlot.GeneveOptsLen != 0 {
		t.Fatalf("free slot GENEVE options length = %d, want 0", freeSlot.GeneveOptsLen)
	}
}

func TestRunAttachOpenPortFailureUsesAbortRollback(t *testing.T) {
	defer resetDeps()
	t.Setenv(tapSocketEnv, "fd=999999")
	attachInnerIP = "10.0.0.1"
	attachOpenPort = true
	vswitchAttach = func(_ string, opts vswitch.AttachOptions) (*vswitch.AttachOutput, error) {
		return &vswitch.AttachOutput{Port: 1, Mode: "tap", InnerIP: opts.InnerIP.String()}, nil
	}
	defer func() { attachOpenPort = false }()
	detached := 0
	vswitchDetach = func(name string, opts vswitch.DetachOptions) error {
		if name != "sw0" || opts.Port != 1 || !opts.SkipDevice {
			t.Fatalf("detach %s/%#v", name, opts)
		}
		detached++
		return nil
	}
	vswitchOpen = func(string) (vswitch.Interface, error) {
		return nil, errors.New("injected FD open failure")
	}

	err := runAttach(nil, []string{"sw0"})
	if err == nil || detached != 1 {
		t.Fatalf("error=%v detached=%d", err, detached)
	}
}

func TestBuildConfigRejectsUnknownGeneveLocator(t *testing.T) {
	defer resetDeps()
	cleanup := setStartFlags("fixed")
	defer cleanup()
	startGeneveLocator = "expression"
	if _, err := buildConfig([]string{"sw0"}); err == nil {
		t.Fatal("expected unknown locator error")
	}
}

func TestGeneveCLIFlagsRegistered(t *testing.T) {
	for _, flag := range []struct {
		cmd  string
		name string
	}{
		{"start", "geneve-locator"},
		{"start", "geneve-port-base"},
		{"start", "geneve-tlv-locator"},
		{"serve", "geneve-locator"},
		{"serve", "geneve-tlv-locator"},
		{"attach", "transit-geneve-opt"},
	} {
		var found bool
		switch flag.cmd {
		case "start":
			found = startCmd.Flags().Lookup(flag.name) != nil
		case "serve":
			found = serveCmd.Flags().Lookup(flag.name) != nil
		case "attach":
			found = attachCmd.Flags().Lookup(flag.name) != nil
		}
		if !found {
			t.Errorf("%s --%s is not registered", flag.cmd, flag.name)
		}
	}
}

func TestRunAttachParsesGeneveOptions(t *testing.T) {
	defer resetDeps()
	var captured []vswitch.GeneveOption
	vswitchAttach = func(_ string, opts vswitch.AttachOptions) (*vswitch.AttachOutput, error) {
		captured = opts.TransitGeneveOpts
		return &vswitch.AttachOutput{Port: 1, InnerIP: opts.InnerIP.String()}, nil
	}
	attachInnerIP = "10.0.0.1"
	attachTransitGeneveOpts = []string{"0102:02:0000002a", "0102:83:"}
	if err := runAttach(nil, []string{"sw0"}); err != nil {
		t.Fatal(err)
	}
	want := []vswitch.GeneveOption{
		{Class: 0x0102, Type: 0x02, Data: []byte{0, 0, 0, 0x2a}},
		{Class: 0x0102, Type: 0x83, Data: []byte{}},
	}
	if !reflect.DeepEqual(captured, want) {
		t.Fatalf("captured = %#v, want %#v", captured, want)
	}
}

func TestRunAttachRejectsInvalidGeneveOption(t *testing.T) {
	defer resetDeps()
	attachInnerIP = "10.0.0.1"
	attachTransitGeneveOpts = []string{"0102:02:0000"}
	if err := runAttach(nil, []string{"sw0"}); err == nil {
		t.Fatal("expected invalid option error")
	}
}
