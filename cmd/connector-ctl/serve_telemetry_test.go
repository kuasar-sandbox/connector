package main

import (
	"testing"
	"time"

	"github.com/kuasar-sandbox/connector/pkg/vswitch"
)

func TestConnectorProjectionKeepsPortGenerationAndNoSandboxID(t *testing.T) {
	now := time.Now()
	got := switchMetricPoints(&vswitch.StatusOutput{Ports: 20, PortsUsed: 1, PortsAvailable: 19}, now)
	got = appendPortMetricPoints(got, vswitch.PortStatsOutput{Port: 7, Generation: 4, TransitRxBytes: 12}, now)
	if len(got) != 12 {
		t.Fatalf("metrics=%d", len(got))
	}
	if got[0].Name != "connector.switch.ports.total" || got[0].Value != 20 {
		t.Fatalf("status metrics %+v", got)
	}
	portMetric := got[4]
	if portMetric.Attributes["port"] != "7" || portMetric.Attributes["attachment.generation"] != "4" {
		t.Fatalf("port identity %+v", portMetric)
	}
	for _, p := range got {
		if _, found := p.Attributes["sandbox.id"]; found {
			t.Fatalf("incorrect SandboxID %+v", p)
		}
	}
}
