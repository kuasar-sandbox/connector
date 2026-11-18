package main

import (
	"context"
	"strconv"
	"time"

	"github.com/kuasar-sandbox/connector/internal/hostmetrics"
	"github.com/kuasar-sandbox/connector/pkg/vswitch"
)

func switchMetricPoints(status *vswitch.StatusOutput, observed time.Time) []hostmetrics.Point {
	return []hostmetrics.Point{
		{Name: "connector.switch.ports.total", Unit: "{port}", Time: observed, Value: float64(status.Ports)},
		{Name: "connector.switch.ports.used", Unit: "{port}", Time: observed, Value: float64(status.PortsUsed)},
		{Name: "connector.switch.ports.available", Unit: "{port}", Time: observed, Value: float64(status.PortsAvailable)},
		{Name: "connector.switch.ports.reserved", Unit: "{port}", Time: observed, Value: float64(status.PortsReserved)},
	}
}

func appendPortMetricPoints(values []hostmetrics.Point, row vswitch.PortStatsOutput, observed time.Time) []hostmetrics.Point {
	labels := map[string]string{"port": strconv.FormatUint(uint64(row.Port), 10), "attachment.generation": strconv.FormatUint(uint64(row.Generation), 10)}
	for _, counter := range []struct {
		name, unit string
		value      uint64
	}{
		{"connector.port.mgmt.rx.packets", "{packet}", row.MgmtRxPackets},
		{"connector.port.mgmt.rx.bytes", "By", row.MgmtRxBytes},
		{"connector.port.mgmt.tx.packets", "{packet}", row.MgmtTxPackets},
		{"connector.port.mgmt.tx.bytes", "By", row.MgmtTxBytes},
		{"connector.port.transit.rx.packets", "{packet}", row.TransitRxPackets},
		{"connector.port.transit.rx.bytes", "By", row.TransitRxBytes},
		{"connector.port.transit.tx.packets", "{packet}", row.TransitTxPackets},
		{"connector.port.transit.tx.bytes", "By", row.TransitTxBytes},
	} {
		v := counter.value
		values = append(values, hostmetrics.Point{Name: counter.name, Unit: counter.unit, Time: observed, Uint: &v, Attributes: labels})
	}
	return values
}

// Called only by the existing serve watcher tick; failures are independent of
// attachment and systemd health. Bounded chunks protect large 4096-port nodes.
func emitConnectorHostMetrics(ctx context.Context, p *hostmetrics.Publisher, sw vswitch.Interface, status *vswitch.StatusOutput, statusTime time.Time) {
	if ctx.Err() != nil || !p.Available() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	points := switchMetricPoints(status, statusTime)
	stats, err := vswitch.ObservePortStats(sw)
	if err == nil {
		at := time.Now()
		for _, row := range stats.Ports {
			// Each port contributes eight points. Flush before adding a whole port.
			if len(points)+8 > 512 {
				if p.Send(ctx, points) != nil {
					return
				}
				points = points[:0]
			}
			points = appendPortMetricPoints(points, row, at)
		}
	}
	_ = p.Send(ctx, points)
}
