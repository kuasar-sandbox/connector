package vswitch

import (
	"net"
	"strings"
	"testing"

	"github.com/kuasar-sandbox/connector/pkg/internal/bpf"
)

// --- validateConfigMatch ---

func testSwitchConfig() *SwitchConfig {
	return &SwitchConfig{
		N_ports:        256,
		FloatingIpBase: bpf.IPToUint32(net.ParseIP("100.100.96.0")),
		GenevePortBase: 50000,
	}
}

func testSwitchMetadata() *SwitchMetadata {
	return &SwitchMetadata{
		SwitchNetNS: "sandbox_switch",
		PortNetNS:   "sandbox_port",
		TransitDev:  "eth1",
	}
}

func testRequestedConfig() *Config {
	return &Config{
		Name:           "sw0",
		SwitchNetNS:    "sandbox_switch",
		PortNetNS:      "sandbox_port",
		NumPorts:       256,
		MACAddr:        net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		FloatingIPBase: net.ParseIP("100.100.96.0"),
		TransitDev:     "eth1",
		GenevePortBase: 50000,
	}
}

func TestValidateConfigMatchSuccess(t *testing.T) {
	requested := testRequestedConfig()
	existing := testSwitchConfig()
	existingMeta := testSwitchMetadata()

	err := validateConfigMatch(requested, existing, existingMeta)
	if err != nil {
		t.Fatalf("validateConfigMatch: %v", err)
	}
}

func TestValidateConfigMatchPortsMismatch(t *testing.T) {
	requested := testRequestedConfig()
	existing := testSwitchConfig()
	existingMeta := testSwitchMetadata()
	existing.N_ports = 128

	err := validateConfigMatch(requested, existing, existingMeta)
	if err == nil {
		t.Fatal("expected error for ports mismatch")
	}
	if !IsConfigMismatch(err) {
		t.Errorf("expected ErrConfigMismatch, got: %v", err)
	}
}

func TestValidateConfigMatchFloatingIPMismatch(t *testing.T) {
	requested := testRequestedConfig()
	existing := testSwitchConfig()
	existingMeta := testSwitchMetadata()
	existing.FloatingIpBase = bpf.IPToUint32(net.ParseIP("10.0.0.0"))

	err := validateConfigMatch(requested, existing, existingMeta)
	if err == nil {
		t.Fatal("expected error for floating_ip_base mismatch")
	}
	if !IsConfigMismatch(err) {
		t.Errorf("expected ErrConfigMismatch, got: %v", err)
	}
}

func TestValidateConfigMatchSwitchNetNSMismatch(t *testing.T) {
	requested := testRequestedConfig()
	existing := testSwitchConfig()
	existingMeta := testSwitchMetadata()
	existingMeta.SwitchNetNS = "other_switch"

	err := validateConfigMatch(requested, existing, existingMeta)
	if err == nil {
		t.Fatal("expected error for switch_netns mismatch")
	}
	if !IsConfigMismatch(err) {
		t.Errorf("expected ErrConfigMismatch, got: %v", err)
	}
}

func TestValidateConfigMatchPortNetNSMismatch(t *testing.T) {
	requested := testRequestedConfig()
	existing := testSwitchConfig()
	existingMeta := testSwitchMetadata()
	existingMeta.PortNetNS = "other_port"

	err := validateConfigMatch(requested, existing, existingMeta)
	if err == nil {
		t.Fatal("expected error for port_netns mismatch")
	}
	if !IsConfigMismatch(err) {
		t.Errorf("expected ErrConfigMismatch, got: %v", err)
	}
}

func TestValidateConfigMatchTransitDevMismatch(t *testing.T) {
	requested := testRequestedConfig()
	existing := testSwitchConfig()
	existingMeta := testSwitchMetadata()
	existingMeta.TransitDev = "eth2"

	err := validateConfigMatch(requested, existing, existingMeta)
	if err == nil {
		t.Fatal("expected error for transit_dev mismatch")
	}
	if !IsConfigMismatch(err) {
		t.Errorf("expected ErrConfigMismatch, got: %v", err)
	}
}

func TestValidateConfigMatchGenevePortBaseMismatch(t *testing.T) {
	requested := testRequestedConfig()
	existing := testSwitchConfig()
	existingMeta := testSwitchMetadata()
	existing.GenevePortBase = 60000

	err := validateConfigMatch(requested, existing, existingMeta)
	if err == nil {
		t.Fatal("expected error for geneve_port_base mismatch")
	}
	if !IsConfigMismatch(err) {
		t.Errorf("expected ErrConfigMismatch, got: %v", err)
	}
}

func TestValidateConfigMatchMultipleMismatches(t *testing.T) {
	requested := testRequestedConfig()
	existing := testSwitchConfig()
	existingMeta := testSwitchMetadata()
	existing.N_ports = 128
	existing.GenevePortBase = 60000

	err := validateConfigMatch(requested, existing, existingMeta)
	if err == nil {
		t.Fatal("expected error for multiple mismatches")
	}
	if !IsConfigMismatch(err) {
		t.Errorf("expected ErrConfigMismatch, got: %v", err)
	}
	// Error message should mention both mismatches
	errStr := err.Error()
	if !strings.Contains(errStr, "ports") {
		t.Errorf("error should mention ports mismatch: %s", errStr)
	}
	if !strings.Contains(errStr, "geneve_port_base") {
		t.Errorf("error should mention geneve_port_base mismatch: %s", errStr)
	}
}

func TestValidateConfigMatchNoTransitDev(t *testing.T) {
	requested := testRequestedConfig()
	requested.TransitDev = ""
	existing := testSwitchConfig()
	existingMeta := testSwitchMetadata()
	existingMeta.TransitDev = ""

	err := validateConfigMatch(requested, existing, existingMeta)
	if err != nil {
		t.Fatalf("validateConfigMatch: %v", err)
	}
}
