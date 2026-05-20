package vswitch

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// --- ParseMgmtExtract ---

func TestParseMgmtExtractSingleIP(t *testing.T) {
	me, err := ParseMgmtExtract("myns:eth0:169.254.169.254")
	if err != nil {
		t.Fatalf("ParseMgmtExtract: %v", err)
	}
	if me.NetNS != "myns" {
		t.Errorf("NetNS = %q", me.NetNS)
	}
	if me.Dev != "eth0" {
		t.Errorf("Dev = %q", me.Dev)
	}
	if len(me.ServiceRoutes) != 1 {
		t.Fatalf("ServiceRoutes len = %d, want 1", len(me.ServiceRoutes))
	}
	if me.ServiceRoutes[0].IP.String() != "169.254.169.254" {
		t.Errorf("IP = %s", me.ServiceRoutes[0].IP)
	}
	ones, _ := me.ServiceRoutes[0].Mask.Size()
	if ones != 32 {
		t.Errorf("mask = /%d, want /32", ones)
	}
}

func TestParseMgmtExtractCIDR(t *testing.T) {
	me, err := ParseMgmtExtract("ns:dev:10.0.0.0/24")
	if err != nil {
		t.Fatalf("ParseMgmtExtract: %v", err)
	}
	if len(me.ServiceRoutes) != 1 {
		t.Fatalf("ServiceRoutes len = %d", len(me.ServiceRoutes))
	}
	ones, _ := me.ServiceRoutes[0].Mask.Size()
	if ones != 24 {
		t.Errorf("mask = /%d, want /24", ones)
	}
}

func TestParseMgmtExtractMultipleRoutes(t *testing.T) {
	me, err := ParseMgmtExtract("ns:dev:169.254.169.254,169.254.1.0/24,10.0.0.1")
	if err != nil {
		t.Fatalf("ParseMgmtExtract: %v", err)
	}
	if len(me.ServiceRoutes) != 3 {
		t.Errorf("ServiceRoutes len = %d, want 3", len(me.ServiceRoutes))
	}
}

func TestParseMgmtExtractInvalidFormat(t *testing.T) {
	cases := []string{
		"",
		"onlyonepart",
		"two:parts",
		"ns::route", // empty dev
		"ns:dev:",   // empty routes
		"::route",   // both netns and dev empty
		":dev:",     // empty netns ok but empty routes not
	}
	for _, s := range cases {
		_, err := ParseMgmtExtract(s)
		if err == nil {
			t.Errorf("expected error for %q", s)
		}
	}
}

// TestParseMgmtExtractEmptyNetNS verifies that an empty <netns> field is
// accepted and signals "use the caller netns" (host-netns mode).
func TestParseMgmtExtractEmptyNetNS(t *testing.T) {
	me, err := ParseMgmtExtract(":eth0:169.254.169.254")
	if err != nil {
		t.Fatalf("ParseMgmtExtract: %v", err)
	}
	if me.NetNS != "" {
		t.Errorf("NetNS = %q, want \"\"", me.NetNS)
	}
	if !me.IsCallerNetNS() {
		t.Error("IsCallerNetNS() = false, want true")
	}
	if me.Dev != "eth0" {
		t.Errorf("Dev = %q, want eth0", me.Dev)
	}
	if len(me.ServiceRoutes) != 1 {
		t.Fatalf("ServiceRoutes len = %d, want 1", len(me.ServiceRoutes))
	}
}

// TestParseMgmtExtractNamedNetNSIsCaller verifies that a named netns
// (non-empty) does NOT report as caller netns.
func TestParseMgmtExtractNamedNetNSIsCaller(t *testing.T) {
	me, err := ParseMgmtExtract("mgmt_ns:eth0:1.2.3.4")
	if err != nil {
		t.Fatalf("ParseMgmtExtract: %v", err)
	}
	if me.IsCallerNetNS() {
		t.Error("IsCallerNetNS() = true for named netns, want false")
	}
}

func TestParseMgmtExtractInvalidRoute(t *testing.T) {
	_, err := ParseMgmtExtract("ns:dev:not-an-ip")
	if err == nil {
		t.Fatal("expected error for invalid IP")
	}
}

func TestParseMgmtExtractInvalidCIDR(t *testing.T) {
	_, err := ParseMgmtExtract("ns:dev:10.0.0.0/99")
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestParseMgmtExtractWithEmptyRoutes(t *testing.T) {
	// Routes with extra commas/spaces should be handled gracefully
	me, err := ParseMgmtExtract("ns:dev:10.0.0.1, ,10.0.0.2")
	if err != nil {
		t.Fatalf("ParseMgmtExtract: %v", err)
	}
	if len(me.ServiceRoutes) != 2 {
		t.Errorf("ServiceRoutes len = %d, want 2", len(me.ServiceRoutes))
	}
}

// --- ParseTransitDevAddr ---

func TestParseTransitDevAddr(t *testing.T) {
	addr, gw, err := ParseTransitDevAddr("192.168.1.10/24:192.168.1.1")
	if err != nil {
		t.Fatalf("ParseTransitDevAddr: %v", err)
	}
	if addr.IP.String() != "192.168.1.10" {
		t.Errorf("IP = %s, want 192.168.1.10", addr.IP)
	}
	ones, _ := addr.Mask.Size()
	if ones != 24 {
		t.Errorf("mask = /%d, want /24", ones)
	}
	if gw.String() != "192.168.1.1" {
		t.Errorf("nexthop = %s", gw)
	}
}

func TestParseTransitDevAddrInvalidFormat(t *testing.T) {
	_, _, err := ParseTransitDevAddr("no-colon")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestParseTransitDevAddrInvalidAddr(t *testing.T) {
	_, _, err := ParseTransitDevAddr("not-cidr:10.0.0.1")
	if err == nil {
		t.Fatal("expected error for invalid address")
	}
}

func TestParseTransitDevAddrInvalidNexthop(t *testing.T) {
	_, _, err := ParseTransitDevAddr("10.0.0.1/24:bad-gw")
	if err == nil {
		t.Fatal("expected error for invalid nexthop")
	}
}

// --- Config.Validate ---

func validConfig() *Config {
	return &Config{
		Name:           "sw0",
		SwitchNetNS:    "switch_ns",
		PortNetNS:      "port_ns",
		NumPorts:       256,
		MACAddr:        net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		FloatingIPBase: net.ParseIP("100.100.96.0"),
	}
}

func TestValidateSuccess(t *testing.T) {
	if err := validConfig().Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidateEmptyName(t *testing.T) {
	c := validConfig()
	c.Name = ""
	if err := c.Validate(); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateEmptySwitchNetNS(t *testing.T) {
	c := validConfig()
	c.SwitchNetNS = ""
	if err := c.Validate(); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateEmptyPortNetNS(t *testing.T) {
	c := validConfig()
	c.PortNetNS = ""
	if err := c.Validate(); err == nil {
		t.Fatal("expected error")
	}
}

// TestValidateReservedAllowsEmptyPortNetNS verifies that the reserved-only
// validation path does NOT require port-netns. (StartReserved doesn't auto-
// provision, so the port-netns won't be touched until a later `provision`.)
func TestValidateReservedAllowsEmptyPortNetNS(t *testing.T) {
	c := validConfig()
	c.PortNetNS = ""
	if err := c.ValidateReserved(); err != nil {
		t.Fatalf("ValidateReserved with empty PortNetNS should pass, got: %v", err)
	}
}

// TestValidateReservedStillEnforcesBase verifies that ValidateReserved still
// catches the non-port-netns errors (name, switch-netns, ports, mac, etc.).
func TestValidateReservedStillEnforcesBase(t *testing.T) {
	c := validConfig()
	c.PortNetNS = "" // would have failed Validate(); allowed by ValidateReserved
	c.Name = ""      // but Name still required
	if err := c.ValidateReserved(); err == nil {
		t.Fatal("expected error for empty Name even in reserved path")
	}
}

func TestValidateZeroPorts(t *testing.T) {
	c := validConfig()
	c.NumPorts = 0
	if err := c.Validate(); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateExceedMaxPorts(t *testing.T) {
	c := validConfig()
	c.NumPorts = MaxPorts + 1
	if err := c.Validate(); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateMaxPorts(t *testing.T) {
	c := validConfig()
	c.NumPorts = MaxPorts
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidateInvalidMAC(t *testing.T) {
	c := validConfig()
	c.MACAddr = net.HardwareAddr{0x01, 0x02} // too short
	if err := c.Validate(); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateNilFloatingIP(t *testing.T) {
	c := validConfig()
	c.FloatingIPBase = nil
	if err := c.Validate(); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateTooManyMgmtExtracts(t *testing.T) {
	c := validConfig()
	for i := 0; i <= int(MaxMgmtCIDRPerSlot); i++ {
		c.MgmtExtracts = append(c.MgmtExtracts, &MgmtExtract{})
	}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateMTUZero(t *testing.T) {
	c := validConfig()
	c.MTU = 0
	if err := c.Validate(); err != nil {
		t.Fatalf("MTU=0 should be valid: %v", err)
	}
}

func TestValidateMTUPositive(t *testing.T) {
	c := validConfig()
	c.MTU = 1500
	if err := c.Validate(); err != nil {
		t.Fatalf("MTU=1500 should be valid: %v", err)
	}
}

func TestValidateMTUNegative(t *testing.T) {
	c := validConfig()
	c.MTU = -1
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for negative MTU")
	}
}

func TestValidateMTUTooLarge(t *testing.T) {
	c := validConfig()
	c.MTU = 65536
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for MTU > 65535")
	}
}

func TestValidateMTUMaxValid(t *testing.T) {
	c := validConfig()
	c.MTU = 65535
	if err := c.Validate(); err != nil {
		t.Fatalf("MTU=65535 should be valid: %v", err)
	}
}

// --- Encap overhead constants ---

func TestGeneveOverheadConstants(t *testing.T) {
	if GeneveIPOverhead != 50 {
		t.Errorf("GeneveIPOverhead = %d, want 50", GeneveIPOverhead)
	}
	if GeneveEthOverhead != 64 {
		t.Errorf("GeneveEthOverhead = %d, want 64", GeneveEthOverhead)
	}
	if GeneveEthOverhead != GeneveIPOverhead+14 {
		t.Errorf("GeneveEthOverhead should be GeneveIPOverhead + 14 (inner ETH)")
	}
}

// --- Device name helpers ---

func TestPortDeviceName(t *testing.T) {
	c := &Config{Name: "sw0"}
	if got := c.PortDeviceName(0); got != "sw0-p1" {
		t.Errorf("PortDeviceName(0) = %q", got)
	}
	if got := c.PortDeviceName(9); got != "sw0-p10" {
		t.Errorf("PortDeviceName(9) = %q", got)
	}
}

func TestPeerDeviceName(t *testing.T) {
	c := &Config{Name: "sw0"}
	if got := c.PeerDeviceName(0); got != "sw0-n1" {
		t.Errorf("PeerDeviceName(0) = %q", got)
	}
}

func TestMgmtDeviceName(t *testing.T) {
	c := &Config{Name: "sw0"}
	if got := c.MgmtDeviceName(0); got != "sw0-m0" {
		t.Errorf("MgmtDeviceName(0) = %q", got)
	}
	if got := c.MgmtDeviceName(2); got != "sw0-m2" {
		t.Errorf("MgmtDeviceName(2) = %q", got)
	}
}

// --- FileConfig / LoadConfigFile ---

func TestLoadConfigFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	content := `{
		"switch_name": "sw0",
		"switch_netns": "sandbox_switch",
		"port_netns": "sandbox_port",
		"num_ports": 128,
		"mac_addr": "02:00:00:00:00:01",
		"floating_ip_base": "100.100.96.0",
		"mgmt_extracts": ["sandbox_mgmt:eth0:169.254.169.254"],
		"transit_dev": "eth1",
		"transit_dev_addr": "auto",
		"transit_dev_mtu": "9000"
	}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfigFile(path)
	if err != nil {
		t.Fatalf("LoadConfigFile: %v", err)
	}

	if cfg.Name != "sw0" {
		t.Errorf("Name = %q, want sw0", cfg.Name)
	}
	if cfg.SwitchNetNS != "sandbox_switch" {
		t.Errorf("SwitchNetNS = %q", cfg.SwitchNetNS)
	}
	if cfg.NumPorts != 128 {
		t.Errorf("NumPorts = %d, want 128", cfg.NumPorts)
	}
	if len(cfg.MgmtExtracts) != 1 {
		t.Errorf("MgmtExtracts len = %d, want 1", len(cfg.MgmtExtracts))
	}
	if cfg.TransitDev != "eth1" {
		t.Errorf("TransitDev = %q", cfg.TransitDev)
	}
	if !cfg.TransitAddrAuto {
		t.Error("TransitAddrAuto should be true")
	}
	if cfg.TransitDevMTU != 9000 {
		t.Errorf("TransitDevMTU = %d, want 9000", cfg.TransitDevMTU)
	}
}

func TestLoadConfigFileNotFound(t *testing.T) {
	_, err := LoadConfigFile("/nonexistent/config.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadConfigFileInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	os.WriteFile(path, []byte("{invalid"), 0644)

	_, err := LoadConfigFile(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestLoadConfigFileInvalidMAC(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	content := `{
		"switch_name": "sw0",
		"switch_netns": "ns1",
		"port_netns": "ns2",
		"num_ports": 1,
		"mac_addr": "invalid",
		"floating_ip_base": "10.0.0.0"
	}`
	os.WriteFile(path, []byte(content), 0644)

	_, err := LoadConfigFile(path)
	if err == nil {
		t.Fatal("expected error for invalid MAC")
	}
}

func TestLoadConfigFileInvalidIP(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	content := `{
		"switch_name": "sw0",
		"switch_netns": "ns1",
		"port_netns": "ns2",
		"num_ports": 1,
		"mac_addr": "02:00:00:00:00:01",
		"floating_ip_base": "not-an-ip"
	}`
	os.WriteFile(path, []byte(content), 0644)

	_, err := LoadConfigFile(path)
	if err == nil {
		t.Fatal("expected error for invalid IP")
	}
}

func TestFileConfigToConfigWithTransitDevAddr(t *testing.T) {
	fc := &FileConfig{
		SwitchName:     "sw0",
		SwitchNetNS:    "ns1",
		PortNetNS:      "ns2",
		NumPorts:       1,
		MACAddr:        "02:00:00:00:00:01",
		FloatingIPBase: "10.0.0.0",
		TransitDev:     "eth1",
		TransitDevAddr: "192.168.1.1/24:192.168.1.254",
	}
	cfg, err := fc.ToConfig()
	if err != nil {
		t.Fatalf("ToConfig: %v", err)
	}
	if cfg.TransitAddr == nil {
		t.Fatal("TransitAddr should not be nil")
	}
	if cfg.TransitNexthop.String() != "192.168.1.254" {
		t.Errorf("TransitNexthop = %s", cfg.TransitNexthop)
	}
}

func TestFileConfigToConfigInvalidTransitDevAddr(t *testing.T) {
	fc := &FileConfig{
		SwitchName:     "sw0",
		SwitchNetNS:    "ns1",
		PortNetNS:      "ns2",
		NumPorts:       1,
		MACAddr:        "02:00:00:00:00:01",
		FloatingIPBase: "10.0.0.0",
		TransitDevAddr: "bad",
	}
	_, err := fc.ToConfig()
	if err == nil {
		t.Fatal("expected error for invalid transit_dev_addr")
	}
}

func TestFileConfigToConfigInvalidTransitDevMTU(t *testing.T) {
	fc := &FileConfig{
		SwitchName:     "sw0",
		SwitchNetNS:    "ns1",
		PortNetNS:      "ns2",
		NumPorts:       1,
		MACAddr:        "02:00:00:00:00:01",
		FloatingIPBase: "10.0.0.0",
		TransitDevMTU:  "invalid",
	}
	_, err := fc.ToConfig()
	if err == nil {
		t.Fatal("expected error for invalid transit_dev_mtu")
	}
}

func TestFileConfigToConfigZeroTransitDevMTU(t *testing.T) {
	fc := &FileConfig{
		SwitchName:     "sw0",
		SwitchNetNS:    "ns1",
		PortNetNS:      "ns2",
		NumPorts:       1,
		MACAddr:        "02:00:00:00:00:01",
		FloatingIPBase: "10.0.0.0",
		TransitDevMTU:  "0", // Zero MTU should be rejected
	}
	_, err := fc.ToConfig()
	if err == nil {
		t.Fatal("expected error for zero transit_dev_mtu")
	}
}

func TestFileConfigToConfigTransitDevMTUAuto(t *testing.T) {
	fc := &FileConfig{
		SwitchName:     "sw0",
		SwitchNetNS:    "ns1",
		PortNetNS:      "ns2",
		NumPorts:       1,
		MACAddr:        "02:00:00:00:00:01",
		FloatingIPBase: "10.0.0.0",
		TransitDevMTU:  "auto",
	}
	cfg, err := fc.ToConfig()
	if err != nil {
		t.Fatalf("ToConfig: %v", err)
	}
	if !cfg.TransitDevMTUAuto {
		t.Error("TransitDevMTUAuto should be true")
	}
}

func TestFileConfigToConfigTransitDevMTUNumeric(t *testing.T) {
	fc := &FileConfig{
		SwitchName:     "sw0",
		SwitchNetNS:    "ns1",
		PortNetNS:      "ns2",
		NumPorts:       1,
		MACAddr:        "02:00:00:00:00:01",
		FloatingIPBase: "10.0.0.0",
		TransitDevMTU:  "9000",
	}
	cfg, err := fc.ToConfig()
	if err != nil {
		t.Fatalf("ToConfig: %v", err)
	}
	if cfg.TransitDevMTU != 9000 {
		t.Errorf("TransitDevMTU = %d, want 9000", cfg.TransitDevMTU)
	}
}

func TestFileConfigToConfigTransitAddrAuto(t *testing.T) {
	fc := &FileConfig{
		SwitchName:     "sw0",
		SwitchNetNS:    "ns1",
		PortNetNS:      "ns2",
		NumPorts:       1,
		MACAddr:        "02:00:00:00:00:01",
		FloatingIPBase: "10.0.0.0",
		TransitDevAddr: "auto",
	}
	cfg, err := fc.ToConfig()
	if err != nil {
		t.Fatalf("ToConfig: %v", err)
	}
	if !cfg.TransitAddrAuto {
		t.Error("TransitAddrAuto should be true")
	}
}

func TestFileConfigToConfigPortMACPerPort(t *testing.T) {
	fc := &FileConfig{
		SwitchName:     "sw0",
		SwitchNetNS:    "ns1",
		PortNetNS:      "ns2",
		NumPorts:       1,
		MACAddr:        "02:00:00:00:00:01",
		FloatingIPBase: "10.0.0.0",
		PortMACAddr:    "per-port",
	}
	cfg, err := fc.ToConfig()
	if err != nil {
		t.Fatalf("ToConfig: %v", err)
	}
	// per-port mode uses all zeros MAC
	if !IsZeroMAC(cfg.PortMAC) {
		t.Error("PortMAC should be zero for per-port mode")
	}
}

func TestFileConfigToConfigPortMACCustom(t *testing.T) {
	fc := &FileConfig{
		SwitchName:     "sw0",
		SwitchNetNS:    "ns1",
		PortNetNS:      "ns2",
		NumPorts:       1,
		MACAddr:        "02:00:00:00:00:01",
		FloatingIPBase: "10.0.0.0",
		PortMACAddr:    "02:00:00:11:22:33",
	}
	cfg, err := fc.ToConfig()
	if err != nil {
		t.Fatalf("ToConfig: %v", err)
	}
	if cfg.PortMAC.String() != "02:00:00:11:22:33" {
		t.Errorf("PortMAC = %s, want 02:00:00:11:22:33", cfg.PortMAC)
	}
}

func TestFileConfigToConfigPortMACInvalid(t *testing.T) {
	fc := &FileConfig{
		SwitchName:     "sw0",
		SwitchNetNS:    "ns1",
		PortNetNS:      "ns2",
		NumPorts:       1,
		MACAddr:        "02:00:00:00:00:01",
		FloatingIPBase: "10.0.0.0",
		PortMACAddr:    "invalid-mac",
	}
	_, err := fc.ToConfig()
	if err == nil {
		t.Fatal("expected error for invalid port_mac_addr")
	}
}
