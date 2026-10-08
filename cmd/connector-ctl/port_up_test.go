package main

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/kuasar-sandbox/connector/pkg/tapfd"
	"github.com/kuasar-sandbox/connector/pkg/vswitch"
)

func tapFDExchange(t *testing.T, sw vswitch.Interface, line string) string {
	t.Helper()
	server, client := unixSocketPair(t)
	defer client.Close()
	done := make(chan struct{})
	go func() { defer close(done); handleTapFDConn(server, "sw0", sw, nil) }()
	if _, err := client.Write([]byte(line + "\n")); err != nil {
		t.Fatal(err)
	}
	response := readAllString(t, client)
	<-done
	return response
}

func TestTapFDDeferredPrepareAndSetPortUp(t *testing.T) {
	fake := &fakeVSwitch{attachOut: &vswitch.AttachOutput{Port: 1, InnerIP: "10.0.0.1", Mode: "tap", AdminDown: true}}
	response := tapFDExchange(t, fake, "TAPFD/1 PREPARE VSWITCH=sw0 INNER_IP=10.0.0.1 ADMIN_DOWN=true")
	if !fake.attachOpts.AdminDown || !strings.Contains(response, "admin_down=1") {
		t.Fatal("down not passed/returned", response)
	}
	request, err := tapfd.BuildRequest(tapfd.RequestOpSetPortUp, "VSWITCH=sw0 PORT=1 INNER_IP=10.0.0.2 TRANSIT_GATEWAY_IP=192.0.2.1 TRANSIT_GENEVE_VNI=42 TRANSIT_GENEVE_OPTS=0102:02:0000002a TRANSIT_MAC=02:00:00:00:00:09", false)
	if err != nil {
		t.Fatal(err)
	}
	response = tapFDExchange(t, fake, strings.TrimSpace(string(request)))
	o := fake.upOpts
	if !strings.Contains(response, "OK port=1 admin_down=0") || fake.upCalls != 1 || o.Port != 1 || o.InnerIP.String() != "10.0.0.2" || o.TransitGatewayIP.String() != "192.0.2.1" || o.TransitGeneveVNI != 42 || len(o.TransitGeneveOpts) != 1 || o.TransitMAC.String() != "02:00:00:00:00:09" {
		t.Fatal(response, o)
	}
	if fake.detachOpts.Port != 0 {
		t.Fatal("SetPortUp triggered release")
	}
}

func TestTapFDAdminDownStrictParsing(t *testing.T) {
	for _, key := range []string{"admin_down", "ADMIN_DOWN"} {
		for _, value := range []string{"1", "true", "0", "false", "", "tru", "2"} {
			t.Run(key+"="+value, func(t *testing.T) {
				opts, err := prepareAttachOptions(&tapfd.Request{Fields: map[string]string{"INNER_IP": "10.0.0.1", key: value}})
				valid := value == "1" || value == "true" || value == "0" || value == "false"
				if !valid {
					if err == nil {
						t.Fatal("malformed down flag accepted")
					}
					return
				}
				if err != nil || opts.AdminDown != (value == "1" || value == "true") {
					t.Fatal(opts, err)
				}
			})
		}
	}
	fake := &fakeVSwitch{}
	response := tapFDExchange(t, fake, "TAPFD/1 PREPARE VSWITCH=sw0 INNER_IP=10.0.0.1 ADMIN_DOWN=tru")
	if !strings.Contains(response, "BAD_REQUEST") || fake.attachOpts.InnerIP != nil {
		t.Fatal("malformed flag reached Attach", response)
	}
}

func TestTapFDSetPortUpRejectsInvalidRequests(t *testing.T) {
	for _, extra := range []string{"INNER_IP=10.0.0.2", "PORT=0 INNER_IP=10.0.0.2", "PORT=1", "PORT=1 INNER_IP=no", "PORT=1 INNER_IP=10.0.0.2 GENERATION=2", "PORT=1 INNER_IP=10.0.0.2 ADMIN_DOWN=1"} {
		t.Run(extra, func(t *testing.T) {
			fake := &fakeVSwitch{}
			response := tapFDExchange(t, fake, "TAPFD/1 SET_PORT_UP VSWITCH=sw0 "+extra)
			if !strings.Contains(response, " ERR ") || fake.upCalls != 0 {
				t.Fatal("invalid request reached mutation", response)
			}
		})
	}
	fake := &fakeVSwitch{upErr: errors.New("port already up")}
	if response := tapFDExchange(t, fake, "TAPFD/1 SET_PORT_UP VSWITCH=sw0 PORT=1 INNER_IP=10.0.0.2"); !strings.Contains(response, " ERR ") || fake.detachOpts.Port != 0 {
		t.Fatal(response)
	}
}

func TestRunSetPortUpPassesCompleteConfiguration(t *testing.T) {
	defer resetDeps()
	upPort = 7
	upInnerIP = "10.0.0.2"
	upGateway = "192.0.2.1"
	upVNI = 42
	upMAC = "02:00:00:00:00:09"
	upOpts = []string{"0102:02:0000002a"}
	called := false
	vswitchSetPortUp = func(name string, o vswitch.PortUpOptions) error {
		called = true
		if name != "sw0" || o.Port != 7 || o.InnerIP.String() != "10.0.0.2" || o.TransitGatewayIP.String() != "192.0.2.1" || o.TransitGeneveVNI != 42 || len(o.TransitGeneveOpts) != 1 || len(o.TransitMAC) != 6 {
			t.Fatal(name, o)
		}
		return nil
	}
	if err := runSetPortUp(setPortUpCmd, []string{"sw0"}); err != nil || !called {
		t.Fatal(err)
	}
}

func TestRunAttachPassesAdminDown(t *testing.T) {
	defer resetDeps()
	attachInnerIP = "10.0.0.1"
	attachAdminDown = true
	attachOpenPort = false
	attachTransitGeneveOpts = nil
	called := false
	vswitchAttach = func(_ string, o vswitch.AttachOptions) (*vswitch.AttachOutput, error) {
		called = true
		if !o.AdminDown {
			t.Fatal("flag lost")
		}
		return &vswitch.AttachOutput{AdminDown: true}, nil
	}
	if err := runAttach(attachCmd, []string{"sw0"}); err != nil || !called {
		t.Fatal(err)
	}
}

func TestShowAllocatedDownState(t *testing.T) {
	cfg := &vswitch.SwitchConfig{Features: vswitch.SwitchFPortUp}
	p := vswitch.PortSlot{Port: 1, Allocated: true, SlotItem: vswitch.SlotItem{InnerIp: vswitch.IPToUint32(net.ParseIP("10.0.0.1"))}}
	if s := slotToJSON(cfg, p, 0); !s.Allocated || !s.AdminDown || s.State != "allocated" {
		t.Fatal(s)
	}
	p.Flags = vswitch.PortFUp
	if slotToJSON(cfg, p, 0).AdminDown {
		t.Fatal("up shown down")
	}
}
