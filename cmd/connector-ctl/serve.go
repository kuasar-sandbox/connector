package main

import (
	"context"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/kuasar-sandbox/connector/pkg/daemon"
	"github.com/kuasar-sandbox/connector/pkg/vswitch"
)

const (
	maxConsecutiveErrors = 3
	maxErrorDuration     = 90 * time.Second
)

var serveWatchInterval time.Duration
var serveTapFDListen string

var serveCmd = &cobra.Command{
	Use:   "serve [switch_name]",
	Short: "Start switch and continuously provision ports",
	Long: `Start a virtual switch with async port provisioning and sd_notify integration.

The serve command performs:
1. StartReserved: initialize BPF, maps, fixed devices, and Reserved slots
2. Open the optional --tapfd-listen server before notifying readiness
3. sd_notify READY=1: notify systemd that the control service is available
4. ProvisionPorts: asynchronously create tap or veth devices for Reserved slots
5. Health check loop: periodic status monitoring until SIGTERM/SIGINT

READY=1 and the Ready condition do not guarantee allocatable ports. Inspect
ports_available/ports_reserved or the selected slot and retry while provisioning.

This is the recommended way to run connector-ctl vswitch as a systemd service
(Type=notify) for fast startup with background port provisioning.

Example:
  connector-ctl vswitch serve sw0 \
    --netns=sandbox_switch \
    --port-netns=sandbox_ports \
    --ports=4096 \
    --mac-addr=02:00:00:00:00:01 \
    --floating-ip-base=100.100.96.0 \
    --transit-dev=eth1 \
    --transit-dev-addr=auto \
    --mgmt-extract=sandbox_mgmt:mgmt0:169.254.169.254/32`,
	Args: cobra.MaximumNArgs(1),
	RunE: runServe,
}

func init() {
	// Reuse the same flags as start
	serveCmd.Flags().StringVar(&startConfigFile, "config", "", "JSON config file (alternative to CLI flags)")
	serveCmd.Flags().StringVar(&startNetNS, "netns", "", "Switch network namespace (required)")
	serveCmd.Flags().StringVar(&startPortNetNS, "port-netns", "", "Ports network namespace (required for veth mode; optional for tap)")
	serveCmd.Flags().Uint32Var(&startPorts, "ports", 0, "Number of ports (1-4096, required)")
	serveCmd.Flags().StringVar(&startMACAddr, "mac-addr", "", "Virtual MAC address (required)")
	serveCmd.Flags().StringVar(&startFloatingIPBase, "floating-ip-base", "", "Floating IP base address (required)")
	serveCmd.Flags().StringArrayVar(&startMgmtExtracts, "mgmt-extract", nil, "Management plane extraction CIDRs (format: <netns>:<dev>:<cidr1>,<cidr2>,...; CIDRs are traffic matches, not interface addresses; leave <netns> empty, e.g. ':mgmt0:1.2.3.4', to keep the peer in the caller/host netns)")
	serveCmd.Flags().StringArrayVar(&startMgmtServices, "mgmt-service", nil, "Management service VIP<->target translation (format: <VIP>:<vport>:<targetIP>:<targetPort>; repeatable). VIP must fall within a --mgmt-extract route. Translates both TCP and UDP. Each (targetIP,targetPort) must be unique. Loopback targets require route_localnet=1 on the mgmt dev.")
	serveCmd.Flags().StringVar(&startTransitDev, "transit-dev", "", "Transit device name")
	serveCmd.Flags().StringVar(&startTransitDevAddr, "transit-dev-addr", "", "Transit device address (format: <ip>/<prefix>:<nexthop> or 'auto' for DHCP)")
	serveCmd.Flags().StringVar(&startTransitDevMTU, "transit-dev-mtu", "", "Transit device MTU ('auto' or specific value, default: no change)")
	serveCmd.Flags().StringVar(&startGeneveLocator, "geneve-locator", "port", "GENEVE slot locator (port, vni, or tlv)")
	serveCmd.Flags().Uint16Var(&startGenevePortBase, "geneve-port-base", 50000, "GENEVE UDP port base")
	serveCmd.Flags().StringVar(&startGeneveTLVLocator, "geneve-tlv-locator", "", "GENEVE TLV slot locator CLASS:TYPE (required with --geneve-locator=tlv)")
	serveCmd.Flags().BoolVar(&startGeneveEncapEth, "geneve-encap-eth", false, "Use Ether-over-GENEVE (default: IP-over-GENEVE)")
	serveCmd.Flags().IntVar(&startMTU, "mtu", 0, "Requested MTU for management setup and transit budgeting; not applied to TAP/veth ports by two-phase provisioning")
	serveCmd.Flags().StringVar(&startPortMACAddr, "port-mac-addr", "fixed", "Port MAC address mode: 'fixed' (default), 'per-port', or specific MAC address")
	serveCmd.Flags().StringVar(&startMode, "mode", "tap", `Port kind for auto-provision: "tap" (default) or "veth". With veth, --port-netns is required.`)
	serveCmd.Flags().DurationVar(&serveWatchInterval, "watch-interval", 30*time.Second, "Health check interval")
	serveCmd.Flags().StringVar(&serveTapFDListen, "tapfd-listen", "", "Unix socket path for persistent TAPFD/1 PREPARE/OPEN/RELEASE requests")
}

func runServe(cmd *cobra.Command, args []string) error {
	cfg, err := buildConfig(args)
	if err != nil {
		return err
	}

	// Parse --mode and route to cfg.DefaultMode (used by ProvisionPorts step).
	mode, err := vswitch.ParsePortKind(startMode)
	if err != nil {
		return fmt.Errorf("invalid --mode: %w", err)
	}
	cfg.DefaultMode = mode

	// Step 1: Fast initialization with all slots Reserved (may be idempotent)
	if _, err := vswitchStartReserved(cfg); err != nil {
		if vswitch.IsConfigMismatch(err) {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			osExit(1)
			// unreachable in production; return kept for test mock
		}
		return err
	}

	// Step 2: Open once for defer Close (keeps BPF refs alive)
	sw, err := vswitchOpen(cfg.Name)
	if err != nil {
		return fmt.Errorf("open switch: %w", err)
	}
	defer sw.Close()

	serveCtx, stopServe := context.WithCancel(context.Background())
	defer stopServe()

	var tapFDErrC <-chan error
	if serveTapFDListen != "" {
		tapFDSrv, err := startTapFDServer(serveCtx, serveTapFDListen, cfg.Name, sw)
		if err != nil {
			return err
		}
		defer tapFDSrv.Close()
		tapFDErrC = tapFDSrv.Err()
		fmt.Fprintf(os.Stderr, "[info] switch %s: tapfd listening on %s\n", cfg.Name, serveTapFDListen)
	}

	// Step 3: Notify systemd (before status check so READY=1 is first datagram)
	daemon.NotifyReady()
	fmt.Fprintf(os.Stderr, "[info] switch %s: ready\n", cfg.Name)

	// Step 4: Print initial status
	w := newServeWatcher(cfg.Name)
	w.checkAndReportStatus()

	// Step 5: Provision asynchronously
	provDone := make(chan error, 1)
	go func() {
		output, err := vswitchProvisionPorts(cfg.Name, vswitch.ProvisionOptions{Mode: cfg.DefaultMode})
		if err == nil && output.Provisioned > 0 {
			fmt.Fprintf(os.Stderr, "[info] switch %s: provisioned %d/%d ports\n",
				cfg.Name, output.Provisioned, output.Total)
		}
		provDone <- err
	}()

	// Step 6: Main loop — signal, watchdog, provision completion, health check
	sigCh := make(chan os.Signal, 1)
	signalNotify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	statusTicker := time.NewTicker(serveWatchInterval)
	defer statusTicker.Stop()

	var wdC <-chan time.Time
	if wdInterval, ok := watchdogEnabled(); ok {
		wdTicker := time.NewTicker(wdInterval)
		defer wdTicker.Stop()
		wdC = wdTicker.C
	}

	var consecutiveStatusErrs int
	var firstStatusErrTime time.Time
	provisioned := false

	for {
		select {
		case sig := <-sigCh:
			fmt.Fprintf(os.Stderr, "[info] received %s, shutting down\n", sig)
			stopServe()
			return nil
		case err := <-tapFDErrC:
			if err != nil {
				fmt.Fprintf(os.Stderr, "[fatal] switch %s: tapfd listener failed: %v\n", cfg.Name, err)
				osExit(1)
				return err
			}
		case err := <-provDone:
			provDone = nil // nil channel blocks forever in select
			if err != nil {
				fmt.Fprintf(os.Stderr, "[error] switch %s: provision failed: %v\n",
					cfg.Name, err)
				osExit(1)
				return err // unreachable in production; return kept for test mock
			}
			provisioned = true
			w.checkAndReportStatus()
		case <-wdC:
			daemon.NotifyWatchdog()
		case <-statusTicker.C:
			if !provisioned {
				continue
			}
			if w.checkAndReportStatus() {
				consecutiveStatusErrs = 0
			} else {
				consecutiveStatusErrs++
				if consecutiveStatusErrs == 1 {
					firstStatusErrTime = timeNow()
				}
				if consecutiveStatusErrs >= maxConsecutiveErrors &&
					timeNow().Sub(firstStatusErrTime) >= maxErrorDuration {
					fmt.Fprintf(os.Stderr,
						"[fatal] switch %s: %d consecutive health check errors over %s, exiting\n",
						cfg.Name, consecutiveStatusErrs,
						timeNow().Sub(firstStatusErrTime).Round(time.Second))
					osExit(1)
					return nil
				}
			}
		}
	}
}

// serveWatcher manages health-check state for checkAndReportStatus.
type serveWatcher struct {
	mu          sync.Mutex
	name        string
	lastReady   bool
	lastSummary string
	first       bool
}

func newServeWatcher(name string) *serveWatcher {
	return &serveWatcher{name: name, first: true}
}

// checkAndReportStatus checks switch status, prints summary, and sends sd_notify STATUS.
// It detects state transitions and reports them.
// Returns true if the health check succeeded, false otherwise.
func (w *serveWatcher) checkAndReportStatus() bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	output, err := vswitchStatus(w.name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[warn] switch %s: health check failed: %v\n", w.name, err)
		daemon.NotifyStatus("health check error")
		return false
	}

	ready := output.IsReady()

	// State transition alerts
	if !w.first && ready != w.lastReady {
		if ready {
			fmt.Fprintf(os.Stderr, "[info] switch %s: recovered → Ready\n", w.name)
		} else {
			fmt.Fprintf(os.Stderr, "[warn] switch %s: degraded → NotReady — %s\n", w.name, output.GetNotReadyReasons())
		}
	}
	w.first = false
	w.lastReady = ready

	summary := formatHealthSummary(output)

	// Only print to stderr when summary changes (dedup repeated status lines)
	if summary != w.lastSummary {
		fmt.Fprintln(os.Stderr, summary)
		w.lastSummary = summary
	}

	// Always send STATUS so systemd can display current state
	daemon.NotifyStatus(summary)
	return true
}

// formatHealthSummary formats a one-line health summary from StatusOutput.
func formatHealthSummary(output *vswitch.StatusOutput) string {
	level := "[info]"
	state := "Ready"
	if !output.IsReady() {
		level = "[warn]"
		state = "NotReady"
	}
	summary := fmt.Sprintf("%s switch %s: %s, %d ports (used=%d, available=%d, reserved=%d)",
		level, output.Switch, state, output.Ports, output.PortsUsed, output.PortsAvailable, output.PortsReserved)
	if !output.IsReady() {
		summary += " — " + output.GetNotReadyReasons()
	}
	return summary
}
