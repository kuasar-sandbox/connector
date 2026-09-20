package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/kuasar-sandbox/connector/pkg/daemon"
	"github.com/kuasar-sandbox/connector/pkg/dhcp"
	"github.com/kuasar-sandbox/connector/pkg/vswitch"
)

// Function variables for external dependencies.
// These can be replaced with mocks in tests.
var (
	osExit              = os.Exit
	vswitchStop         = vswitch.Stop
	vswitchForceCleanup = vswitch.ForceCleanup
	vswitchStatus       = vswitch.Status
	vswitchStats        = vswitch.Stats
	vswitchAttach       = vswitch.Attach
	vswitchReserve      = vswitch.Reserve
	vswitchDetach       = vswitch.Detach

	// runStop/runServe dependencies
	vswitchReleasePorts = vswitch.ReleasePorts
	vswitchStopReleased = vswitch.StopReleased

	// runStart/runServe dependencies
	vswitchStart          = vswitch.Start
	vswitchStartReserved  = vswitch.StartReserved
	vswitchOpen           = vswitch.Open
	vswitchProvisionPorts = vswitch.ProvisionPorts
	vswitchLoadConfigFile = vswitch.LoadConfigFile

	// serve dependencies
	signalNotify    = signal.Notify
	timeNow         = time.Now
	watchdogEnabled = daemon.WatchdogEnabled

	// DHCP dependencies
	dhcpRequest   = dhcp.Request
	dhcpNewServer = dhcp.NewServer
)

// DHCPServer interface for DHCP server mock.
type DHCPServer interface {
	Serve(ctx context.Context) error
}

// printJSON outputs the value as formatted JSON to stdout.
func printJSON(v interface{}) error {
	data, err := json.MarshalIndent(v, "", "    ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}
