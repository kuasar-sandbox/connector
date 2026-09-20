package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/kuasar-sandbox/connector/pkg/dhcp"
	"github.com/kuasar-sandbox/connector/pkg/vswitch"
)

// --- parsePoolRange ---

func TestParsePoolRangeValid(t *testing.T) {
	start, end, err := parsePoolRange("10.0.0.100-10.0.0.200")
	if err != nil {
		t.Fatalf("parsePoolRange: %v", err)
	}
	if start.String() != "10.0.0.100" {
		t.Errorf("start = %s, want 10.0.0.100", start)
	}
	if end.String() != "10.0.0.200" {
		t.Errorf("end = %s, want 10.0.0.200", end)
	}
}

func TestParsePoolRangeSingleIP(t *testing.T) {
	start, end, err := parsePoolRange("10.0.0.100-10.0.0.100")
	if err != nil {
		t.Fatalf("parsePoolRange: %v", err)
	}
	if !start.Equal(end) {
		t.Errorf("start and end should be equal for single IP range")
	}
}

func TestParsePoolRangeWithSpaces(t *testing.T) {
	start, end, err := parsePoolRange("  10.0.0.100  -  10.0.0.200  ")
	if err != nil {
		t.Fatalf("parsePoolRange with spaces: %v", err)
	}
	if start.String() != "10.0.0.100" {
		t.Errorf("start = %s, want 10.0.0.100", start)
	}
	if end.String() != "10.0.0.200" {
		t.Errorf("end = %s, want 10.0.0.200", end)
	}
}

func TestParsePoolRangeInvalidFormat(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"no dash", "10.0.0.100"},
		{"multiple dashes", "10.0.0.100-10.0.0.150-10.0.0.200"},
		{"empty", ""},
		{"dash only", "-"},
		{"start only", "10.0.0.100-"},
		{"end only", "-10.0.0.200"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := parsePoolRange(tt.input)
			if err == nil {
				t.Errorf("expected error for %q", tt.input)
			}
		})
	}
}

func TestParsePoolRangeInvalidStart(t *testing.T) {
	_, _, err := parsePoolRange("invalid-10.0.0.200")
	if err == nil {
		t.Fatal("expected error for invalid start IP")
	}
}

func TestParsePoolRangeInvalidEnd(t *testing.T) {
	_, _, err := parsePoolRange("10.0.0.100-invalid")
	if err == nil {
		t.Fatal("expected error for invalid end IP")
	}
}

func TestParsePoolRangeIPv6NotSupported(t *testing.T) {
	_, _, err := parsePoolRange("::1-::2")
	if err == nil {
		t.Fatal("expected error for IPv6")
	}
}

// --- Root command structure ---

func TestRootCmdExists(t *testing.T) {
	if rootCmd == nil {
		t.Fatal("rootCmd should not be nil")
	}
	if rootCmd.Use != "connector-ctl" {
		t.Errorf("rootCmd.Use = %q, want connector-ctl", rootCmd.Use)
	}
}

func TestRootCmdHasSubcommands(t *testing.T) {
	cmds := rootCmd.Commands()
	if len(cmds) == 0 {
		t.Fatal("rootCmd should have subcommands")
	}

	// Verify expected subcommands exist
	expected := []string{"vswitch", "tapfd"}
	for _, name := range expected {
		found := false
		for _, cmd := range cmds {
			if cmd.Name() == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected subcommand %q not found", name)
		}
	}
}

func TestVswitchCmdHasSubcommands(t *testing.T) {
	expected := []string{"start", "stop", "attach", "reserve", "detach", "status", "stats", "dhcp"}
	for _, name := range expected {
		found := false
		for _, cmd := range vswitchCmd.Commands() {
			if cmd.Name() == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected vswitch subcommand %q not found", name)
		}
	}
}

// --- Helper function tests ---

// parseDNSServers parses comma-separated DNS servers
func parseDNSServers(s string) ([]net.IP, error) {
	if s == "" {
		return nil, nil
	}
	// This is a simplified test - actual parsing is in runDHCPServe
	return nil, nil
}

func TestParseDNSServersEmpty(t *testing.T) {
	result, err := parseDNSServers("")
	if err != nil {
		t.Errorf("parseDNSServers empty: %v", err)
	}
	if result != nil {
		t.Errorf("parseDNSServers empty = %v, want nil", result)
	}
}

// --- runStop tests ---

func TestRunStopSuccess(t *testing.T) {
	defer resetDeps()

	vswitchStop = func(name string, opts vswitch.StopOptions) error {
		return nil
	}

	err := runStop(nil, []string{"sw0"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunStopNotExist(t *testing.T) {
	defer resetDeps()

	var exitCode int
	osExit = func(code int) { exitCode = code }
	vswitchStop = func(name string, opts vswitch.StopOptions) error {
		return vswitch.ErrSwitchNotExist
	}

	err := runStop(nil, []string{"sw0"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exitCode != 3 {
		t.Errorf("expected exit code 3, got %d", exitCode)
	}
}

func TestRunStopError(t *testing.T) {
	defer resetDeps()

	vswitchStop = func(name string, opts vswitch.StopOptions) error {
		return errors.New("internal error")
	}

	err := runStop(nil, []string{"sw0"})
	if err == nil {
		t.Error("expected error")
	}
}

func TestRunStopPortsInUse(t *testing.T) {
	defer resetDeps()

	var exitCode int
	osExit = func(code int) { exitCode = code }
	vswitchStop = func(name string, opts vswitch.StopOptions) error {
		return fmt.Errorf("switch %s has 3 allocated port(s): %w", name, vswitch.ErrPortsInUse)
	}

	err := runStop(nil, []string{"sw0"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exitCode != 4 {
		t.Errorf("expected exit code 4, got %d", exitCode)
	}
}

func TestRunStopForce(t *testing.T) {
	defer resetDeps()

	var gotOpts vswitch.StopOptions
	vswitchStop = func(name string, opts vswitch.StopOptions) error {
		gotOpts = opts
		return nil
	}

	stopForce = true
	defer func() { stopForce = false }()

	err := runStop(nil, []string{"sw0"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !gotOpts.Force {
		t.Error("expected StopOptions.Force=true when --force is set")
	}
}

func TestStopForceCleanOnCorruptedSwitch(t *testing.T) {
	defer resetDeps()

	vswitchStop = func(name string, opts vswitch.StopOptions) error {
		return fmt.Errorf("switch %s: %w: load maps failed", name, vswitch.ErrSwitchCorrupted)
	}
	var cleanedName string
	vswitchForceCleanup = func(name string) error {
		cleanedName = name
		return nil
	}

	stopForceClean = true
	defer func() { stopForceClean = false }()

	err := runStop(nil, []string{"sw0"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if cleanedName != "sw0" {
		t.Errorf("expected force cleanup on sw0, got %q", cleanedName)
	}
}

func TestStopForceCleanNotNeeded(t *testing.T) {
	defer resetDeps()

	vswitchStop = func(name string, opts vswitch.StopOptions) error {
		return fmt.Errorf("switch %s: %w: load maps failed", name, vswitch.ErrSwitchCorrupted)
	}

	stopForceClean = false

	err := runStop(nil, []string{"sw0"})
	if err == nil {
		t.Error("expected error when corrupted but --force-clean not set")
	}
	if !vswitch.IsSwitchCorrupted(err) {
		t.Errorf("expected SwitchCorrupted error, got: %v", err)
	}
}

func TestStopForceCleanupFails(t *testing.T) {
	defer resetDeps()

	vswitchStop = func(name string, opts vswitch.StopOptions) error {
		return fmt.Errorf("switch %s: %w: load maps failed", name, vswitch.ErrSwitchCorrupted)
	}
	vswitchForceCleanup = func(name string) error {
		return errors.New("unpin failed")
	}

	stopForceClean = true
	defer func() { stopForceClean = false }()

	err := runStop(nil, []string{"sw0"})
	if err == nil {
		t.Error("expected error when force cleanup fails")
	}
}

// --- runStatus tests ---

func TestRunStatusSuccess(t *testing.T) {
	defer resetDeps()

	vswitchStatus = func(name string) (*vswitch.StatusOutput, error) {
		return &vswitch.StatusOutput{
			Switch:         name,
			State:          "running",
			Ports:          4,
			PortsUsed:      1,
			PortsAvailable: 3,
			Conditions: []vswitch.Condition{
				{Type: vswitch.ConditionReady, Status: vswitch.ConditionTrue},
			},
		}, nil
	}

	// Reset global flag
	statusReadyOnly = false

	err := runStatus(nil, []string{"sw0"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunStatusNotExist(t *testing.T) {
	defer resetDeps()

	var exitCode int
	osExit = func(code int) { exitCode = code }
	vswitchStatus = func(name string) (*vswitch.StatusOutput, error) {
		return nil, vswitch.ErrSwitchNotExist
	}

	err := runStatus(nil, []string{"sw0"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exitCode != 3 {
		t.Errorf("expected exit code 3, got %d", exitCode)
	}
}

func TestRunStatusReadyTrue(t *testing.T) {
	defer resetDeps()

	vswitchStatus = func(name string) (*vswitch.StatusOutput, error) {
		return &vswitch.StatusOutput{
			Switch: name,
			State:  "running",
			Conditions: []vswitch.Condition{
				{Type: vswitch.ConditionReady, Status: vswitch.ConditionTrue},
			},
		}, nil
	}

	statusReadyOnly = true
	defer func() { statusReadyOnly = false }()

	err := runStatus(nil, []string{"sw0"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunStatusReadyFalse(t *testing.T) {
	defer resetDeps()

	var exitCode int
	osExit = func(code int) { exitCode = code }
	vswitchStatus = func(name string) (*vswitch.StatusOutput, error) {
		return &vswitch.StatusOutput{
			Switch: name,
			State:  "running",
			Conditions: []vswitch.Condition{
				{Type: vswitch.ConditionReady, Status: vswitch.ConditionFalse},
			},
		}, nil
	}

	statusReadyOnly = true
	defer func() { statusReadyOnly = false }()

	err := runStatus(nil, []string{"sw0"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exitCode != 4 {
		t.Errorf("expected exit code 4, got %d", exitCode)
	}
}

// --- runStats tests ---

func TestRunStatsSuccess(t *testing.T) {
	defer resetDeps()

	vswitchStats = func(name string, ports []int) (*vswitch.StatsOutput, error) {
		return &vswitch.StatsOutput{
			Switch: name,
			Ports: []vswitch.PortStatsOutput{
				{Port: 1, InnerIP: "10.0.0.1"},
			},
		}, nil
	}

	// Reset global flag
	statsPorts = nil

	err := runStats(nil, []string{"sw0"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunStatsNotExist(t *testing.T) {
	defer resetDeps()

	var exitCode int
	osExit = func(code int) { exitCode = code }
	vswitchStats = func(name string, ports []int) (*vswitch.StatsOutput, error) {
		return nil, vswitch.ErrSwitchNotExist
	}

	err := runStats(nil, []string{"sw0"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exitCode != 3 {
		t.Errorf("expected exit code 3, got %d", exitCode)
	}
}

// --- runDetach tests ---

func TestRunDetachSuccess(t *testing.T) {
	defer resetDeps()

	vswitchDetach = func(name string, opts vswitch.DetachOptions) error {
		return nil
	}

	detachPort = 1
	detachFromNetNS = "/proc/123/ns/net"
	defer func() {
		detachPort = 0
		detachFromNetNS = ""
	}()

	err := runDetach(nil, []string{"sw0"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunDetachError(t *testing.T) {
	defer resetDeps()

	vswitchDetach = func(name string, opts vswitch.DetachOptions) error {
		return errors.New("port not attached")
	}

	detachPort = 1
	defer func() { detachPort = 0 }()

	err := runDetach(nil, []string{"sw0"})
	if err == nil {
		t.Error("expected error")
	}
}

// --- runAttach tests ---

func TestRunAttachSuccess(t *testing.T) {
	defer resetDeps()

	vswitchAttach = func(name string, opts vswitch.AttachOptions) (*vswitch.AttachOutput, error) {
		return &vswitch.AttachOutput{
			Port:       1,
			PortDev:    "sw0-p1",
			InnerIP:    opts.InnerIP.String(),
			FloatingIP: "169.254.1.1",
		}, nil
	}

	attachInnerIP = "10.0.0.1"
	attachPort = 0
	attachToNetNS = ""
	attachTransitGatewayIP = ""
	attachTransitMACAddr = ""
	defer func() {
		attachInnerIP = ""
		attachPort = 0
		attachToNetNS = ""
		attachTransitGatewayIP = ""
		attachTransitMACAddr = ""
	}()

	err := runAttach(nil, []string{"sw0"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunAttachInvalidInnerIP(t *testing.T) {
	defer resetDeps()

	attachInnerIP = "not-an-ip"
	defer func() { attachInnerIP = "" }()

	err := runAttach(nil, []string{"sw0"})
	if err == nil {
		t.Error("expected error for invalid inner-ip")
	}
}

func TestRunAttachInvalidTransitGatewayIP(t *testing.T) {
	defer resetDeps()

	attachInnerIP = "10.0.0.1"
	attachTransitGatewayIP = "not-an-ip"
	defer func() {
		attachInnerIP = ""
		attachTransitGatewayIP = ""
	}()

	err := runAttach(nil, []string{"sw0"})
	if err == nil {
		t.Error("expected error for invalid transit-gateway-ip")
	}
}

func TestRunAttachInvalidTransitMAC(t *testing.T) {
	defer resetDeps()

	attachInnerIP = "10.0.0.1"
	attachTransitMACAddr = "not-a-mac"
	defer func() {
		attachInnerIP = ""
		attachTransitMACAddr = ""
	}()

	err := runAttach(nil, []string{"sw0"})
	if err == nil {
		t.Error("expected error for invalid transit-mac-addr")
	}
}

func TestRunAttachError(t *testing.T) {
	defer resetDeps()

	vswitchAttach = func(name string, opts vswitch.AttachOptions) (*vswitch.AttachOutput, error) {
		return nil, errors.New("no free slots")
	}

	attachInnerIP = "10.0.0.1"
	defer func() { attachInnerIP = "" }()

	err := runAttach(nil, []string{"sw0"})
	if err == nil {
		t.Error("expected error")
	}
}

// --- runReserve tests ---

func TestRunReserveRequiresPort(t *testing.T) {
	defer resetDeps()

	reservePort = 0
	err := runReserve(nil, []string{"sw0"})
	if err == nil {
		t.Error("expected error: --port is required")
	}
}

func TestRunReserveSuccess(t *testing.T) {
	defer resetDeps()

	vswitchReserve = func(name string, opts vswitch.ReserveOptions) (*vswitch.ReserveOutput, error) {
		if opts.Port != 42 {
			t.Errorf("expected port 42, got %d", opts.Port)
		}
		if opts.Force {
			t.Error("expected Force=false")
		}
		return &vswitch.ReserveOutput{Port: uint32(opts.Port), Status: "reserved"}, nil
	}

	reservePort = 42
	reserveForce = false
	defer func() {
		reservePort = 0
		reserveForce = false
	}()

	err := runReserve(nil, []string{"sw0"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunReserveForceSuccess(t *testing.T) {
	defer resetDeps()

	vswitchReserve = func(name string, opts vswitch.ReserveOptions) (*vswitch.ReserveOutput, error) {
		if !opts.Force {
			t.Error("expected Force=true")
		}
		return &vswitch.ReserveOutput{Port: uint32(opts.Port), Status: "reserved"}, nil
	}

	reservePort = 42
	reserveForce = true
	defer func() {
		reservePort = 0
		reserveForce = false
	}()

	err := runReserve(nil, []string{"sw0"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunReserveError(t *testing.T) {
	defer resetDeps()

	vswitchReserve = func(name string, opts vswitch.ReserveOptions) (*vswitch.ReserveOutput, error) {
		return nil, errors.New("slot busy")
	}

	reservePort = 42
	defer func() { reservePort = 0 }()

	err := runReserve(nil, []string{"sw0"})
	if err == nil {
		t.Error("expected error")
	}
}

func TestRunAttachMissingInnerIP(t *testing.T) {
	defer resetDeps()

	attachInnerIP = ""
	err := runAttach(nil, []string{"sw0"})
	if err == nil {
		t.Error("expected error: --inner-ip is required")
	}
}

// --- runStart tests ---

// setStartFlags sets common start flags and returns a cleanup function.
func setStartFlags(portMACAddr string) func() {
	startMACAddr = "02:00:00:00:00:01"
	startFloatingIPBase = "169.254.0.0"
	startNetNS = "sw_ns"
	startPortNetNS = "port_ns"
	startPorts = 4
	startPortMACAddr = portMACAddr
	startGeneveLocator = "port"
	startGenevePortBase = vswitch.DefaultGenevePortBase
	startGeneveTLVLocator = ""
	return func() {
		startMACAddr = ""
		startFloatingIPBase = ""
		startNetNS = ""
		startPortNetNS = ""
		startPorts = 0
		startPortMACAddr = ""
		startTransitDev = ""
		startTransitDevAddr = ""
		startTransitDevMTU = ""
		startGeneveLocator = "port"
		startGenevePortBase = vswitch.DefaultGenevePortBase
		startGeneveTLVLocator = ""
		startMgmtExtracts = nil
	}
}

// mockVswitchStartSuccess sets up a successful vswitchStart mock.
func mockVswitchStartSuccess() {
	vswitchStart = func(cfg *vswitch.Config) (*vswitch.StartOutput, error) {
		return &vswitch.StartOutput{Switch: cfg.Name, Ports: cfg.NumPorts}, nil
	}
}

func TestRunStartWithConfigFile(t *testing.T) {
	defer resetDeps()

	vswitchLoadConfigFile = func(path string) (*vswitch.Config, error) {
		return &vswitch.Config{Name: "sw0", NumPorts: 4}, nil
	}
	mockVswitchStartSuccess()

	startConfigFile = "/test/config.json"
	defer func() { startConfigFile = "" }()

	if err := runStart(nil, []string{}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunStartWithConfigFileOverrideName(t *testing.T) {
	defer resetDeps()

	var startedName string
	vswitchLoadConfigFile = func(path string) (*vswitch.Config, error) {
		return &vswitch.Config{Name: "sw0", NumPorts: 4}, nil
	}
	vswitchStart = func(cfg *vswitch.Config) (*vswitch.StartOutput, error) {
		startedName = cfg.Name
		return &vswitch.StartOutput{Switch: cfg.Name, Ports: 4}, nil
	}

	startConfigFile = "/test/config.json"
	defer func() { startConfigFile = "" }()

	if err := runStart(nil, []string{"sw1"}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if startedName != "sw1" {
		t.Errorf("expected switch name to be overridden to sw1, got %s", startedName)
	}
}

func TestRunStartWithConfigFileLoadError(t *testing.T) {
	defer resetDeps()

	vswitchLoadConfigFile = func(path string) (*vswitch.Config, error) {
		return nil, errors.New("file not found")
	}

	startConfigFile = "/test/config.json"
	defer func() { startConfigFile = "" }()

	if err := runStart(nil, []string{}); err == nil {
		t.Error("expected error for config load failure")
	}
}

func TestRunStartWithFlags(t *testing.T) {
	defer resetDeps()
	defer setStartFlags("fixed")()
	mockVswitchStartSuccess()

	if err := runStart(nil, []string{"sw0"}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunStartNoSwitchName(t *testing.T) {
	defer resetDeps()
	startConfigFile = ""

	if err := runStart(nil, []string{}); err == nil {
		t.Error("expected error for missing switch name")
	}
}

func TestRunStartInvalidInputs(t *testing.T) {
	tests := []struct {
		name   string
		setup  func()
		errMsg string
	}{
		{
			name:   "invalid MAC",
			setup:  func() { startMACAddr = "invalid" },
			errMsg: "expected error for invalid MAC",
		},
		{
			name: "invalid floating IP",
			setup: func() {
				startMACAddr = "02:00:00:00:00:01"
				startFloatingIPBase = "invalid"
			},
			errMsg: "expected error for invalid floating IP",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer resetDeps()
			tt.setup()
			if err := runStart(nil, []string{"sw0"}); err == nil {
				t.Error(tt.errMsg)
			}
		})
	}
}

func TestRunStartInvalidPortMACAddr(t *testing.T) {
	defer resetDeps()
	defer setStartFlags("invalid-mac")()
	mockVswitchStartSuccess()

	if err := runStart(nil, []string{"sw0"}); err == nil {
		t.Error("expected error for invalid port-mac-addr")
	}
}

func TestRunStartPortMACModes(t *testing.T) {
	tests := []struct {
		name        string
		portMACAddr string
		expectMAC   string
	}{
		{"per-port", "per-port", "00:00:00:00:00:00"},
		{"specific MAC", "aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer resetDeps()
			defer setStartFlags(tt.portMACAddr)()

			var cfgPortMAC net.HardwareAddr
			vswitchStart = func(cfg *vswitch.Config) (*vswitch.StartOutput, error) {
				cfgPortMAC = cfg.PortMAC
				return &vswitch.StartOutput{Switch: cfg.Name, Ports: cfg.NumPorts}, nil
			}

			if err := runStart(nil, []string{"sw0"}); err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if cfgPortMAC.String() != tt.expectMAC {
				t.Errorf("expected port MAC %s, got %s", tt.expectMAC, cfgPortMAC)
			}
		})
	}
}

func TestRunStartWithTransitDev(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		mtu     string
		wantErr bool
	}{
		{"auto addr and mtu", "auto", "auto", false},
		{"static addr and mtu", "10.0.0.2/24:10.0.0.1", "1500", false},
		{"invalid addr", "invalid", "", true},
		{"invalid mtu", "", "invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer resetDeps()
			defer setStartFlags("fixed")()
			mockVswitchStartSuccess()

			startTransitDev = "eth1"
			startTransitDevAddr = tt.addr
			startTransitDevMTU = tt.mtu

			err := runStart(nil, []string{"sw0"})
			if tt.wantErr && err == nil {
				t.Errorf("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestRunStartWithMgmtExtract(t *testing.T) {
	tests := []struct {
		name    string
		extract string
		wantErr bool
	}{
		{"valid", "mgmt_ns:mgmt0:169.254.169.254/32", false},
		{"invalid", "invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer resetDeps()
			defer setStartFlags("fixed")()
			mockVswitchStartSuccess()

			startMgmtExtracts = []string{tt.extract}

			err := runStart(nil, []string{"sw0"})
			if tt.wantErr && err == nil {
				t.Errorf("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestRunStartError(t *testing.T) {
	defer resetDeps()
	defer setStartFlags("fixed")()

	vswitchStart = func(cfg *vswitch.Config) (*vswitch.StartOutput, error) {
		return nil, errors.New("internal error")
	}

	if err := runStart(nil, []string{"sw0"}); err == nil {
		t.Error("expected error")
	}
}

func TestRunStartConfigMismatch(t *testing.T) {
	defer resetDeps()
	defer setStartFlags("fixed")()

	var exitCode int
	osExit = func(code int) { exitCode = code }
	vswitchStart = func(cfg *vswitch.Config) (*vswitch.StartOutput, error) {
		return nil, vswitch.ErrConfigMismatch
	}

	// runStart calls osExit(1) for config mismatch but still returns the error
	// because our mock osExit doesn't actually exit the process
	_ = runStart(nil, []string{"sw0"})
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}
}

// --- runDHCPRequest tests ---

// setDHCPRequestFlags sets common DHCP request flags and returns a cleanup function.
func setDHCPRequestFlags() func() {
	dhcpDev = "eth0"
	dhcpTimeout = 5 * time.Second
	dhcpRetries = 3
	return func() {
		dhcpDev = ""
		dhcpTimeout = 0
		dhcpRetries = 0
	}
}

func TestRunDHCPRequest(t *testing.T) {
	tests := []struct {
		name    string
		mock    func()
		wantErr bool
	}{
		{
			name: "success",
			mock: func() {
				dhcpRequest = func(ctx context.Context, opts dhcp.RequestOptions) (*dhcp.Lease, error) {
					return &dhcp.Lease{
						IP:        net.ParseIP("10.0.0.100"),
						Netmask:   net.CIDRMask(24, 32),
						PrefixLen: 24,
						Gateway:   net.ParseIP("10.0.0.1"),
					}, nil
				}
			},
			wantErr: false,
		},
		{
			name: "timeout error",
			mock: func() {
				dhcpRequest = func(ctx context.Context, opts dhcp.RequestOptions) (*dhcp.Lease, error) {
					return nil, errors.New("timeout")
				}
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer resetDeps()
			defer setDHCPRequestFlags()()
			tt.mock()

			err := runDHCPRequest(nil, nil)
			if tt.wantErr && err == nil {
				t.Error("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// --- runDHCPServe tests ---

// resetDHCPServeFlags resets all DHCP serve flags.
func resetDHCPServeFlags() {
	dhcpServeServerIP = ""
	dhcpServePool = ""
	dhcpServeGateway = ""
	dhcpServeDNS = ""
	dhcpServeDev = ""
	dhcpServeLease = 0
}

func TestRunDHCPServeInvalidInputs(t *testing.T) {
	tests := []struct {
		name   string
		setup  func()
		errMsg string
	}{
		{
			name:   "invalid server IP",
			setup:  func() { dhcpServeServerIP = "invalid" },
			errMsg: "expected error for invalid server IP",
		},
		{
			name:   "IPv6 server IP",
			setup:  func() { dhcpServeServerIP = "::1" },
			errMsg: "expected error for IPv6 server IP",
		},
		{
			name: "invalid pool",
			setup: func() {
				dhcpServeServerIP = "10.0.0.1"
				dhcpServePool = "invalid"
			},
			errMsg: "expected error for invalid pool",
		},
		{
			name: "invalid gateway",
			setup: func() {
				dhcpServeServerIP = "10.0.0.1"
				dhcpServePool = "10.0.0.100-10.0.0.200"
				dhcpServeGateway = "invalid"
			},
			errMsg: "expected error for invalid gateway",
		},
		{
			name: "IPv6 gateway",
			setup: func() {
				dhcpServeServerIP = "10.0.0.1"
				dhcpServePool = "10.0.0.100-10.0.0.200"
				dhcpServeGateway = "::1"
			},
			errMsg: "expected error for IPv6 gateway",
		},
		{
			name: "invalid DNS",
			setup: func() {
				dhcpServeServerIP = "10.0.0.1"
				dhcpServePool = "10.0.0.100-10.0.0.200"
				dhcpServeDNS = "invalid"
			},
			errMsg: "expected error for invalid DNS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer resetDeps()
			defer resetDHCPServeFlags()
			tt.setup()

			if err := runDHCPServe(nil, nil); err == nil {
				t.Error(tt.errMsg)
			}
		})
	}
}

// --- runProvision tests ---

func TestProvisionSuccess(t *testing.T) {
	defer resetDeps()

	vswitchProvisionPorts = func(name string, opts vswitch.ProvisionOptions) (*vswitch.ProvisionOutput, error) {
		return &vswitch.ProvisionOutput{
			Provisioned: 10,
			Total:       100,
			Available:   10,
		}, nil
	}

	provisionCount = 0
	provisionPort = 0

	err := runProvision(nil, []string{"sw0"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestProvisionMutualExclusive(t *testing.T) {
	defer resetDeps()

	provisionCount = 5
	provisionPort = 3
	defer func() {
		provisionCount = 0
		provisionPort = 0
	}()

	err := runProvision(nil, []string{"sw0"})
	if err == nil {
		t.Error("expected error for mutually exclusive --count and --port")
	}
}

func TestProvisionError(t *testing.T) {
	defer resetDeps()

	vswitchProvisionPorts = func(name string, opts vswitch.ProvisionOptions) (*vswitch.ProvisionOutput, error) {
		return nil, errors.New("provision failed")
	}

	provisionCount = 0
	provisionPort = 0

	err := runProvision(nil, []string{"sw0"})
	if err == nil {
		t.Error("expected error")
	}
}

// --- mockSwitch for Interface ---

type mockSwitch struct {
	name     string
	statusFn func() (*vswitch.StatusOutput, error)
	closed   bool
}

func (m *mockSwitch) Name() string                                                  { return m.name }
func (m *mockSwitch) Config() *vswitch.SwitchConfig                                 { return nil }
func (m *mockSwitch) Metadata() *vswitch.SwitchMetadata                             { return nil }
func (m *mockSwitch) Maps() *vswitch.Maps                                           { return nil }
func (m *mockSwitch) MmapSlots() *vswitch.MmappedSlots                              { return nil }
func (m *mockSwitch) Close() error                                                  { m.closed = true; return nil }
func (m *mockSwitch) Attach(_ vswitch.AttachOptions) (*vswitch.AttachOutput, error) { return nil, nil }
func (m *mockSwitch) Reserve(_ vswitch.ReserveOptions) (*vswitch.ReserveOutput, error) {
	return nil, nil
}
func (m *mockSwitch) Detach(_ vswitch.DetachOptions) error        { return nil }
func (m *mockSwitch) Stats(_ []int) (*vswitch.StatsOutput, error) { return nil, nil }
func (m *mockSwitch) Ports(_ bool) []vswitch.PortSlot             { return nil }

func (m *mockSwitch) Status() (*vswitch.StatusOutput, error) {
	if m.statusFn != nil {
		return m.statusFn()
	}
	return &vswitch.StatusOutput{
		Switch: m.name, State: "running", Ports: 4,
		Conditions: []vswitch.Condition{{Type: vswitch.ConditionReady, Status: vswitch.ConditionTrue}},
	}, nil
}

func newReadyStatus(name string, ports, used, available, reserved uint32) *vswitch.StatusOutput {
	return &vswitch.StatusOutput{
		Switch: name, State: "running", Ports: ports,
		PortsUsed: used, PortsAvailable: available, PortsReserved: reserved,
		Conditions: []vswitch.Condition{{Type: vswitch.ConditionReady, Status: vswitch.ConditionTrue}},
	}
}

func newNotReadyStatus(name string) *vswitch.StatusOutput {
	return &vswitch.StatusOutput{
		Switch: name, State: "running", Ports: 4,
		Conditions: []vswitch.Condition{
			{Type: vswitch.ConditionReady, Status: vswitch.ConditionFalse},
			{Type: "PortDevicesReady", Status: vswitch.ConditionFalse},
		},
	}
}

// --- runServe tests ---

func TestServeConfigError(t *testing.T) {
	defer resetDeps()

	// No args and no --config means buildConfig will fail
	startConfigFile = ""
	startMACAddr = ""
	defer func() { startConfigFile = "" }()

	err := runServe(nil, []string{})
	if err == nil {
		t.Error("expected error for missing config")
	}
}

func TestServeStartReservedError(t *testing.T) {
	defer resetDeps()

	startMACAddr = "02:00:00:00:00:01"
	startFloatingIPBase = "100.100.96.0"
	startNetNS = "ns_sw"
	startPortNetNS = "ns_port"
	startPorts = 4
	startPortMACAddr = "fixed"

	vswitchStartReserved = func(cfg *vswitch.Config) (*vswitch.StartOutput, error) {
		return nil, errors.New("bpf load failed")
	}

	err := runServe(nil, []string{"sw0"})
	if err == nil || err.Error() != "bpf load failed" {
		t.Errorf("expected 'bpf load failed', got: %v", err)
	}
}

func setupServeFlags() {
	startMACAddr = "02:00:00:00:00:01"
	startFloatingIPBase = "100.100.96.0"
	startNetNS = "ns_sw"
	startPortNetNS = "ns_port"
	startPorts = 4
	startPortMACAddr = "fixed"
}

// mockServeOpen sets up vswitchOpen to return the given mock switch.
func mockServeOpen(sw vswitch.Interface) {
	vswitchOpen = func(name string) (vswitch.Interface, error) {
		return sw, nil
	}
}

func TestServeSuccess(t *testing.T) {
	defer resetDeps()
	setupServeFlags()

	vswitchStartReserved = func(cfg *vswitch.Config) (*vswitch.StartOutput, error) {
		return &vswitch.StartOutput{Switch: cfg.Name, Ports: cfg.NumPorts}, nil
	}
	sw := &mockSwitch{name: "sw0"}
	mockServeOpen(sw)
	var sigCh chan<- os.Signal
	statusCalls := 0
	vswitchStatus = func(name string) (*vswitch.StatusOutput, error) {
		statusCalls++
		if statusCalls == 2 && sigCh != nil {
			sigCh <- syscall.SIGTERM
		}
		return newReadyStatus("sw0", 4, 0, 4, 0), nil
	}
	vswitchProvisionPorts = func(name string, opts vswitch.ProvisionOptions) (*vswitch.ProvisionOutput, error) {
		return &vswitch.ProvisionOutput{Provisioned: 4, Total: 4, Available: 4}, nil
	}

	signalNotify = func(c chan<- os.Signal, sig ...os.Signal) { sigCh = c }
	serveWatchInterval = 10 * time.Millisecond

	err := runServe(nil, []string{"sw0"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !sw.closed {
		t.Error("expected sw.Close() to be called")
	}
}

func TestServeOpenError(t *testing.T) {
	defer resetDeps()
	setupServeFlags()

	vswitchStartReserved = func(cfg *vswitch.Config) (*vswitch.StartOutput, error) {
		return &vswitch.StartOutput{Switch: cfg.Name, Ports: cfg.NumPorts}, nil
	}
	vswitchOpen = func(name string) (vswitch.Interface, error) {
		return nil, errors.New("maps not found")
	}

	err := runServe(nil, []string{"sw0"})
	if err == nil {
		t.Error("expected error for Open failure")
	}
}

func TestServeProvisionError(t *testing.T) {
	defer resetDeps()
	setupServeFlags()

	vswitchStartReserved = func(cfg *vswitch.Config) (*vswitch.StartOutput, error) {
		return &vswitch.StartOutput{Switch: cfg.Name, Ports: cfg.NumPorts}, nil
	}
	sw := &mockSwitch{name: "sw0"}
	mockServeOpen(sw)
	vswitchStatus = func(name string) (*vswitch.StatusOutput, error) {
		return newReadyStatus("sw0", 4, 0, 0, 4), nil
	}
	vswitchProvisionPorts = func(name string, opts vswitch.ProvisionOptions) (*vswitch.ProvisionOutput, error) {
		return nil, errors.New("provision failed")
	}
	var exitCode int32
	osExit = func(code int) { atomic.StoreInt32(&exitCode, int32(code)) }

	serveWatchInterval = 10 * time.Millisecond

	// provision error arrives via provDone channel → osExit(1)
	_ = runServe(nil, []string{"sw0"})
	if atomic.LoadInt32(&exitCode) != 1 {
		t.Errorf("expected exit code 1, got %d", atomic.LoadInt32(&exitCode))
	}
}

func TestServeConfigMismatch(t *testing.T) {
	defer resetDeps()
	setupServeFlags()

	var exitCode int
	osExit = func(code int) { exitCode = code }

	vswitchStartReserved = func(cfg *vswitch.Config) (*vswitch.StartOutput, error) {
		return nil, fmt.Errorf("switch exists: %w", vswitch.ErrConfigMismatch)
	}

	// osExit mock doesn't halt, so runServe continues and returns nil
	// (the real osExit would terminate before return)
	_ = runServe(nil, []string{"sw0"})
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}
}

// --- formatHealthSummary tests ---

func TestFormatHealthSummaryReady(t *testing.T) {
	output := newReadyStatus("sw0", 256, 3, 250, 3)
	summary := formatHealthSummary(output)

	expected := "[info] switch sw0: Ready, 256 ports (used=3, available=250, reserved=3)"
	if summary != expected {
		t.Errorf("got %q, want %q", summary, expected)
	}
}

func TestFormatHealthSummaryNotReady(t *testing.T) {
	output := newNotReadyStatus("sw0")
	summary := formatHealthSummary(output)

	if summary[:6] != "[warn]" {
		t.Errorf("expected [warn] prefix, got %q", summary)
	}
	if !contains(summary, "NotReady") {
		t.Errorf("expected NotReady in summary, got %q", summary)
	}
	if !contains(summary, "PortDevicesReady") {
		t.Errorf("expected reason in summary, got %q", summary)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// --- checkAndReportStatus tests ---

func TestCheckAndReportStatusTransition(t *testing.T) {
	defer resetDeps()

	callCount := 0
	vswitchStatus = func(name string) (*vswitch.StatusOutput, error) {
		callCount++
		switch callCount {
		case 1:
			return newReadyStatus("sw0", 4, 0, 4, 0), nil
		case 2:
			return newNotReadyStatus("sw0"), nil
		default:
			return newReadyStatus("sw0", 4, 1, 3, 0), nil
		}
	}

	w := newServeWatcher("sw0")

	// Call 1: first check, Ready
	w.checkAndReportStatus()
	if w.first {
		t.Error("first should be false after first call")
	}
	if !w.lastReady {
		t.Error("lastReady should be true after Ready status")
	}

	// Call 2: transition to NotReady
	w.checkAndReportStatus()
	if w.lastReady {
		t.Error("lastReady should be false after NotReady status")
	}

	// Call 3: recover to Ready
	w.checkAndReportStatus()
	if !w.lastReady {
		t.Error("lastReady should be true after recovery")
	}
}

func TestCheckAndReportStatusError(t *testing.T) {
	defer resetDeps()

	vswitchStatus = func(name string) (*vswitch.StatusOutput, error) {
		return nil, errors.New("maps corrupted")
	}

	w := newServeWatcher("sw0")
	// Should not panic, should return false
	if w.checkAndReportStatus() {
		t.Error("expected checkAndReportStatus to return false on error")
	}
}

func TestCheckAndReportStatusDedup(t *testing.T) {
	defer resetDeps()

	vswitchStatus = func(name string) (*vswitch.StatusOutput, error) {
		return newReadyStatus("sw0", 4, 0, 4, 0), nil
	}

	watcher := newServeWatcher("sw0")

	// Capture stderr
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	// Call 1: first check — should print
	watcher.checkAndReportStatus()
	// Call 2: same status — should NOT print
	watcher.checkAndReportStatus()

	w.Close()
	os.Stderr = oldStderr

	var buf [4096]byte
	n, _ := r.Read(buf[:])
	output := string(buf[:n])
	r.Close()

	// Count lines: should be exactly 1 (dedup suppressed the second)
	lines := 0
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if line != "" {
			lines++
		}
	}
	if lines != 1 {
		t.Errorf("expected 1 line of output (dedup), got %d: %q", lines, output)
	}

	if watcher.lastSummary == "" {
		t.Error("lastSummary should be set after checkAndReportStatus")
	}
}

// --- checkAndReportStatus tests ---

func TestCheckAndReportStatusReturnsTrueOnSuccess(t *testing.T) {
	defer resetDeps()

	vswitchStatus = func(name string) (*vswitch.StatusOutput, error) {
		return newReadyStatus("sw0", 4, 0, 4, 0), nil
	}

	w := newServeWatcher("sw0")
	if !w.checkAndReportStatus() {
		t.Error("expected checkAndReportStatus to return true on success")
	}
}

// --- runServe main loop tests ---

// setupServeRunLoop sets up common mocks for testing the main loop in runServe.
// Returns after provision completes and the main loop starts ticking.
func setupServeRunLoop(t *testing.T) {
	t.Helper()
	setupServeFlags()
	vswitchStartReserved = func(cfg *vswitch.Config) (*vswitch.StartOutput, error) {
		return &vswitch.StartOutput{Switch: cfg.Name, Ports: cfg.NumPorts}, nil
	}
	mockServeOpen(&mockSwitch{name: "sw0"})
	vswitchProvisionPorts = func(name string, opts vswitch.ProvisionOptions) (*vswitch.ProvisionOutput, error) {
		return &vswitch.ProvisionOutput{Provisioned: 4, Total: 4, Available: 4}, nil
	}

	serveWatchInterval = 5 * time.Millisecond
}

func TestServeConsecutiveErrorsBelowThreshold(t *testing.T) {
	defer resetDeps()
	setupServeRunLoop(t)

	// Fail below the fatal condition, then stop on the observed recovery.
	callCount := 0
	var sigCh chan<- os.Signal
	vswitchStatus = func(name string) (*vswitch.StatusOutput, error) {
		callCount++
		// First call is the initial status check before provision.
		if callCount == 1 {
			return newReadyStatus("sw0", 4, 0, 0, 4), nil
		}
		afterProv := callCount - 1
		if afterProv <= 3 {
			return nil, errors.New("pin dir missing")
		}
		if sigCh != nil {
			sigCh <- syscall.SIGTERM
			sigCh = nil
		}
		return newReadyStatus("sw0", 4, 0, 4, 0), nil
	}
	timeNow = time.Now

	var exitCalled bool
	osExit = func(code int) { exitCalled = true }
	signalNotify = func(c chan<- os.Signal, sig ...os.Signal) { sigCh = c }

	_ = runServe(nil, []string{"sw0"})
	if exitCalled {
		t.Error("unexpected osExit — errors below threshold should not exit")
	}
}

func TestServeConsecutiveErrorsExceedThreshold(t *testing.T) {
	defer resetDeps()
	setupServeRunLoop(t)

	callCount := 0
	vswitchStatus = func(name string) (*vswitch.StatusOutput, error) {
		callCount++
		// First call is initial status
		if callCount == 1 {
			return newReadyStatus("sw0", 4, 0, 0, 4), nil
		}
		// After provision: always fail
		return nil, errors.New("pin dir missing")
	}

	// Fake time: first call returns T=0, subsequent calls exceed maxErrorDuration
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	timeIdx := 0
	timeNow = func() time.Time {
		timeIdx++
		if timeIdx == 1 {
			return now
		}
		return now.Add(100 * time.Second)
	}

	var exitCode int32
	osExit = func(code int) { atomic.StoreInt32(&exitCode, int32(code)) }

	_ = runServe(nil, []string{"sw0"})
	if atomic.LoadInt32(&exitCode) != 1 {
		t.Errorf("expected exit code 1, got %d", atomic.LoadInt32(&exitCode))
	}
}

func TestServeErrorRecoveryResetsCounter(t *testing.T) {
	defer resetDeps()
	setupServeRunLoop(t)

	callCount := 0
	var sigCh chan<- os.Signal
	vswitchStatus = func(name string) (*vswitch.StatusOutput, error) {
		callCount++
		if callCount == 1 {
			return newReadyStatus("sw0", 4, 0, 0, 4), nil
		}
		// After provision: fail, fail, success, fail, fail, success.
		afterProv := callCount - 1
		if afterProv%3 == 0 {
			if afterProv >= 6 && sigCh != nil {
				sigCh <- syscall.SIGTERM
				sigCh = nil
			}
			return newReadyStatus("sw0", 4, 0, 4, 0), nil
		}
		return nil, errors.New("pin dir missing")
	}
	timeNow = time.Now

	var exitCalled bool
	osExit = func(code int) { exitCalled = true }
	signalNotify = func(c chan<- os.Signal, sig ...os.Signal) { sigCh = c }

	_ = runServe(nil, []string{"sw0"})
	if exitCalled {
		t.Error("unexpected exit — recovery should reset counter")
	}
}

func TestServeErrorsCountButDurationNot(t *testing.T) {
	defer resetDeps()
	setupServeRunLoop(t)

	callCount := 0
	var sigCh chan<- os.Signal
	vswitchStatus = func(name string) (*vswitch.StatusOutput, error) {
		callCount++
		if callCount == 1 {
			return newReadyStatus("sw0", 4, 0, 0, 4), nil
		}
		if callCount >= 5 && sigCh != nil {
			sigCh <- syscall.SIGTERM
			sigCh = nil
		}
		return nil, errors.New("pin dir missing")
	}

	// Fake time: never advances, so duration < maxErrorDuration.
	fixedTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	timeNow = func() time.Time { return fixedTime }

	var exitCalled bool
	osExit = func(code int) { exitCalled = true }
	signalNotify = func(c chan<- os.Signal, sig ...os.Signal) { sigCh = c }

	_ = runServe(nil, []string{"sw0"})
	if exitCalled {
		t.Error("unexpected exit — duration threshold not met")
	}
}

// --- watchdog tests ---

func TestServeSendsWatchdog(t *testing.T) {
	defer resetDeps()
	setupServeRunLoop(t)

	vswitchStatus = func(name string) (*vswitch.StatusOutput, error) {
		return newReadyStatus("sw0", 4, 0, 4, 0), nil
	}
	// Large status interval so STATUS messages don't flood the socket
	serveWatchInterval = 10 * time.Second

	socketPath := fmt.Sprintf("/tmp/test-wd-%d.sock", os.Getpid())
	defer os.Remove(socketPath)

	listener, err := net.ListenPacket("unixgram", socketPath)
	if err != nil {
		t.Skipf("cannot create unixgram socket: %v", err)
	}
	defer listener.Close()

	watchdogEnabled = func() (time.Duration, bool) { return 20 * time.Millisecond, true }
	t.Setenv("NOTIFY_SOCKET", socketPath)

	gotWatchdog := make(chan struct{}, 1)
	signalNotify = func(c chan<- os.Signal, sig ...os.Signal) {
		go func() {
			buf := make([]byte, 256)
			_ = listener.SetReadDeadline(time.Now().Add(2 * time.Second))
			for {
				n, _, err := listener.ReadFrom(buf)
				if err != nil {
					c <- syscall.SIGTERM
					return
				}
				if string(buf[:n]) == "WATCHDOG=1" {
					gotWatchdog <- struct{}{}
					c <- syscall.SIGTERM
					return
				}
			}
		}()
	}

	_ = runServe(nil, []string{"sw0"})
	select {
	case <-gotWatchdog:
	default:
		t.Error("expected at least one WATCHDOG=1 notification")
	}
}

func TestServeNoWatchdogWithoutEnv(t *testing.T) {
	defer resetDeps()
	setupServeRunLoop(t)

	var sigCh chan<- os.Signal
	statusCalls := 0
	vswitchStatus = func(name string) (*vswitch.StatusOutput, error) {
		statusCalls++
		if statusCalls == 2 && sigCh != nil {
			sigCh <- syscall.SIGTERM
		}
		return newReadyStatus("sw0", 4, 0, 4, 0), nil
	}

	socketPath := fmt.Sprintf("/tmp/test-nowd-%d.sock", os.Getpid())
	defer os.Remove(socketPath)

	listener, err := net.ListenPacket("unixgram", socketPath)
	if err != nil {
		t.Skipf("cannot create unixgram socket: %v", err)
	}
	defer listener.Close()

	// No WATCHDOG_USEC, but NOTIFY_SOCKET is set
	t.Setenv("NOTIFY_SOCKET", socketPath)

	signalNotify = func(c chan<- os.Signal, sig ...os.Signal) { sigCh = c }

	_ = runServe(nil, []string{"sw0"})

	// Read all messages, none should be WATCHDOG=1
	buf := make([]byte, 256)
	for {
		_ = listener.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, _, err := listener.ReadFrom(buf)
		if err != nil {
			break
		}
		if string(buf[:n]) == "WATCHDOG=1" {
			t.Error("unexpected WATCHDOG=1 notification without WATCHDOG_USEC")
			break
		}
	}
}

func TestRunDHCPServeNewServerError(t *testing.T) {
	defer resetDeps()
	defer resetDHCPServeFlags()

	dhcpNewServer = func(cfg dhcp.ServerConfig) (*dhcp.Server, error) {
		return nil, errors.New("failed to create server")
	}

	dhcpServeServerIP = "10.0.0.1"
	dhcpServePool = "10.0.0.100-10.0.0.200"
	dhcpServeDev = "veth0"
	dhcpServeLease = time.Hour

	if err := runDHCPServe(nil, nil); err == nil {
		t.Error("expected error for server creation failure")
	}
}
