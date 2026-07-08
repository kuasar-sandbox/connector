package main

import (
	"os"
	"os/signal"
	"time"

	"github.com/kuasar-sandbox/connector/pkg/dhcp"
	"github.com/kuasar-sandbox/connector/pkg/vswitch"
)

func resetDeps() {
	osExit = os.Exit
	vswitchStop = vswitch.Stop
	vswitchForceCleanup = vswitch.ForceCleanup
	vswitchStatus = vswitch.Status
	vswitchStats = vswitch.Stats
	vswitchAttach = vswitch.Attach
	vswitchReserve = vswitch.Reserve
	vswitchDetach = vswitch.Detach
	vswitchReleasePorts = vswitch.ReleasePorts
	vswitchStopReleased = vswitch.StopReleased
	vswitchStart = vswitch.Start
	vswitchStartReserved = vswitch.StartReserved
	vswitchOpen = vswitch.Open
	vswitchProvisionPorts = vswitch.ProvisionPorts
	vswitchLoadConfigFile = vswitch.LoadConfigFile
	dhcpRequest = dhcp.Request
	dhcpNewServer = dhcp.NewServer
	signalNotify = signal.Notify
	timeNow = time.Now
	serveTapFDListen = ""
	startMgmtExtracts = nil
	startMgmtServices = nil
	stopForce = false
	stopForceClean = false
	reservePort = 0
	reserveForce = false
}
