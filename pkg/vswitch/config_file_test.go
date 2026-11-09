package vswitch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const configFileBase = `{"switch_name":"sw0","switch_netns":"switch_ns","port_netns":"port_ns","num_ports":4,"mac_addr":"02:00:00:00:00:01","floating_ip_base":"100.100.96.0"}`

func configFilePaths(t *testing.T, bodies ...string) string {
	t.Helper()
	dir := t.TempDir()
	paths := make([]string, len(bodies))
	for i, body := range bodies {
		paths[i] = filepath.Join(dir, fmt.Sprintf("%d.conf", i))
		if err := os.WriteFile(paths[i], []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return strings.Join(paths, ":")
}

func TestLoadConfigFileLayers(t *testing.T) {
	path := configFilePaths(t,
		`{"switch_name":"sw0","switch_netns":"switch_ns","port_netns":"port_ns","mtu":1500,"geneve_encap_eth":true,"geneve_locator":"tlv","geneve_tlv_locator":"0102:81"}`,
		"num_ports: 4\nmac_addr: 02:00:00:00:00:01\nfloating_ip_base: 100.100.96.0\nMTU: 9000\ngeneve_locator: vni\ngeneve_tlv_locator: null\ngeneve_encap_eth: false\n",
	)
	cfg, err := LoadConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MTU != 9000 || cfg.GeneveEncapEth || cfg.GeneveLocator != GeneveLocatorVNI || cfg.GeneveTLVLocator != nil {
		t.Fatalf("unexpected layered config: %#v", cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(path, ":")
	if _, err := LoadConfigFile(parts[0]); err == nil {
		t.Fatal("the incomplete first fragment should not work on its own")
	}
}

func TestLoadConfigFileZeroEmptyAndDelete(t *testing.T) {
	path := configFilePaths(t, configFileBase,
		`{"MTU":9000,"geneve_encap_eth":true,"mgmt_extracts":[":mgmt0:169.254.169.254"],"transit_dev":"eth1"}`,
		`{"mtu":0,"geneve_encap_eth":false,"mgmt_extracts":[],"transit_dev":""}`,
	)
	cfg, err := LoadConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MTU != 0 || cfg.GeneveEncapEth || len(cfg.MgmtExtracts) != 0 || cfg.TransitDev != "" {
		t.Fatalf("explicit zero/empty values were lost: %#v", cfg)
	}
	deleted, err := LoadConfigFile(configFilePaths(t, configFileBase, `{"mtu":9000}`, `{"MTU":null}`))
	if err != nil || deleted.MTU != 0 {
		t.Fatalf("case-insensitive deletion: cfg=%#v err=%v", deleted, err)
	}
}

func TestLoadConfigFileJSONCompatibility(t *testing.T) {
	for _, fragment := range []string{
		`"mtu":1500,"MTU":9000`,
		`"mtu":9000,"mtu":null`,
		`"geneve_encap_eth":true,"geneve_encap_eth":null`,
		`"geneve_locator":"tlv","geneve_tlv_locator":"0102:81","geneve_tlv_locator":null`,
		`"mtu":"bad","mtu":9000`,
		`"geneve_locator":"invalid","geneve_locator":"port"`,
		`"mtu":9000.0`,
		`"mtu":9e3`,
		`"unused":18446744073709551617`,
	} {
		t.Run(fragment, func(t *testing.T) {
			body := strings.TrimSuffix(configFileBase, "}") + "," + fragment + "}"
			var fc FileConfig
			decodeErr := json.Unmarshal([]byte(body), &fc)
			var want *Config
			if decodeErr == nil {
				want, decodeErr = fc.ToConfig()
			}
			for _, bodies := range [][]string{{body}, {body, `{}`}, {configFileBase, "{" + fragment + "}"}} {
				got, err := LoadConfigFile(configFilePaths(t, bodies...))
				if (err != nil) != (decodeErr != nil) {
					t.Fatalf("bodies=%v: err=%v, native err=%v", bodies, err, decodeErr)
				}
				if err == nil && !reflect.DeepEqual(got, want) {
					t.Fatalf("bodies=%v: got=%#v, native=%#v", bodies, got, want)
				}
			}
		})
	}
}

func TestLoadConfigFileOrderedRepeatedFiles(t *testing.T) {
	paths := strings.Split(configFilePaths(t, configFileBase, `{"mtu":1500}`, `{"mtu":9000}`), ":")
	cfg, err := LoadConfigFile(strings.Join([]string{paths[0], paths[1], paths[2], paths[1]}, ":"))
	if err != nil || cfg.MTU != 1500 {
		t.Fatalf("repeated input was reordered/deduplicated: cfg=%#v err=%v", cfg, err)
	}
}

func TestLoadConfigFileFormatIgnoresFilename(t *testing.T) {
	yamlBody := "switch_name: sw0\nswitch_netns: switch_ns\nport_netns: port_ns\nnum_ports: 4\nmac_addr: 02:00:00:00:00:01\nfloating_ip_base: 100.100.96.0\ngeneve_locator: tlv\ngeneve_tlv_locator: '0102:81'\n"
	jsonBody := strings.TrimSuffix(configFileBase, "}") + `,"geneve_locator":"tlv","geneve_tlv_locator":"0102:81"}`
	var expected *Config
	for _, suffix := range []string{".conf", ".json", ".yaml", ".yml", ""} {
		for _, body := range []string{jsonBody, yamlBody} {
			path := filepath.Join(t.TempDir(), "config"+suffix)
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := LoadConfigFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if expected == nil {
				expected = cfg
			} else if !reflect.DeepEqual(cfg, expected) {
				t.Fatalf("format or suffix changed config: %#v != %#v", cfg, expected)
			}
		}
	}
}

func TestLoadConfigFileYAMLFallbackBoundary(t *testing.T) {
	// A trailing comma is invalid JSON but valid YAML and is intentionally new
	// accepted input. An invalid JSON field value must not get a second decoder.
	trailingComma := strings.TrimSuffix(configFileBase, "}") + ",}"
	if _, err := LoadConfigFile(configFilePaths(t, trailingComma)); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`{"mtu":"bad"}`, `{"geneve_locator":42}`, `[]`, `null`, `"mtu: 9000"`} {
		_, err := LoadConfigFile(configFilePaths(t, configFileBase, body))
		if err == nil || strings.Contains(err.Error(), "YAML:") {
			t.Fatalf("valid JSON must not fall back: body=%s err=%v", body, err)
		}
	}
}

func TestLoadConfigFileYAMLRules(t *testing.T) {
	for _, body := range []string{
		"mtu: 1500\nmtu: 9000\n",
		"unused:\n  x: 1\n  x: 2\n",
		"mtu: 1500\n---\nmtu: 9000\n",
		"- 1500\n",
		"1: value\n",
		"unused: &cycle {child: *cycle}\n",
		"mtu: *missing\n",
		"mtu: .inf\n",
		"mtu: 9000.0\n",
	} {
		t.Run(body, func(t *testing.T) {
			path := configFilePaths(t, configFileBase, body, `{"mtu":1500}`)
			_, err := LoadConfigFile(path)
			// A type error may be overwritten by a later valid layer; YAML
			// structural errors must be caught within their source file.
			if body == "mtu: 9000.0\n" {
				if err != nil {
					t.Fatal(err)
				}
				_, err = LoadConfigFile(configFilePaths(t, configFileBase, body))
			}
			if err == nil {
				t.Fatal("expected YAML/config error")
			}
		})
	}
}

func TestLoadConfigFileYAMLAnchorsAndMergeKeys(t *testing.T) {
	body := "first: &first {mtu: 1500, geneve_encap_eth: true}\nsecond: &second {mtu: 9000, transit_dev: eth1}\n<<: [*first, *second]\ngeneve_encap_eth: false\n"
	cfg, err := LoadConfigFile(configFilePaths(t, configFileBase, body))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MTU != 1500 || cfg.GeneveEncapEth || cfg.TransitDev != "eth1" {
		t.Fatalf("incorrect YAML merge precedence: %#v", cfg)
	}
}

func TestConfigFileRawObjectMerge(t *testing.T) {
	base, err := parseConfigFile([]byte(`{"x":{"keep":1,"remove":2,"items":[1,2]},"replace":1}`))
	if err != nil {
		t.Fatal(err)
	}
	layer, err := parseConfigFile([]byte(`{"x":{"remove":null,"items":[],"new":9007199254740993},"replace":{"a":null,"b":false}}`))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	mergeConfigObjects(base, layer, true).writeJSON(&out)
	want := `{"x":{"keep":1,"items":[],"new":9007199254740993},"replace":{"b":false}}`
	if out.String() != want {
		t.Fatalf("merge=%s, want=%s", out.String(), want)
	}
}

func TestConfigFileYAMLNumberPrecision(t *testing.T) {
	value, err := parseConfigFile([]byte("large: 9007199254740993\nhex: 0x2328\nfloat: 9_000.0\nnegative: -.5e+2\n"))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	value.writeJSON(&out)
	want := `{"large":9007199254740993,"hex":9000,"float":9000.0,"negative":-0.5e+2}`
	if out.String() != want {
		t.Fatalf("numeric conversion=%s, want=%s", out.String(), want)
	}
}

func TestLoadConfigFilePathErrors(t *testing.T) {
	base := configFilePaths(t, configFileBase)
	for _, path := range []string{"", base + ":", ":" + base, base + "::" + base, base + ":" + t.TempDir(), base + ":" + filepath.Join(t.TempDir(), "missing")} {
		if _, err := LoadConfigFile(path); err == nil {
			t.Fatalf("expected error for %q", path)
		}
	}
	path := configFilePaths(t, configFileBase, "{broken: [")
	_, err := LoadConfigFile(path)
	if err == nil || !strings.Contains(err.Error(), "1.conf") || !strings.Contains(err.Error(), "JSON:") || !strings.Contains(err.Error(), "YAML:") {
		t.Fatalf("missing syntax/path diagnostics: %v", err)
	}
	if _, err := LoadConfigFile(base + ":" + configFilePaths(t, `{"mac_addr":"bad"}`)); err == nil || !strings.Contains(err.Error(), base) || !strings.Contains(err.Error(), "invalid mac_addr") {
		t.Fatalf("missing final config diagnostics: %v", err)
	}
}
