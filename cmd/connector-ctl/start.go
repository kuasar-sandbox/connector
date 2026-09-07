package main

import (
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/kuasar-sandbox/connector/pkg/vswitch"
)

var startCmd = &cobra.Command{
	Use:   "start [switch_name]",
	Short: "Create and start a virtual switch",
	Long: `Create and start a new virtual switch with the specified configuration.

The switch will create veth pairs for each port and attach eBPF TC programs
for packet processing. The BPF maps are pinned to /sys/fs/bpf/<switch_name>/
so the forwarding continues after this process exits.

Configuration can come from CLI flags or a JSON config file (--config).
When using --config, the switch_name argument is optional and overrides
the switch_name in the config file if provided.

Use --reserved to only initialize the switch with Reserved slots (no veth creation).
Ports can then be provisioned later with the 'provision' command.

Example (CLI flags):
  connector-ctl vswitch start sw0 \
    --netns=sandbox_switch \
    --port-netns=sandbox_ports \
    --ports=4096 \
    --mac-addr=02:00:00:00:00:01 \
    --floating-ip-base=100.100.96.0 \
    --transit-dev=eth1 \
    --transit-dev-addr=auto \
    --mgmt-extract=sandbox_mgmt:mgmt0:169.254.169.254/32

Example (config file):
  connector-ctl vswitch start --config /etc/connector/switch.json`,
	Args: cobra.MaximumNArgs(1),
	RunE: runStart,
}

var (
	startConfigFile       string
	startNetNS            string
	startPortNetNS        string
	startPorts            uint32
	startMACAddr          string
	startFloatingIPBase   string
	startMgmtExtracts     []string
	startMgmtServices     []string
	startTransitDev       string
	startTransitDevAddr   string
	startTransitDevMTU    string
	startGeneveLocator    string
	startGenevePortBase   uint16
	startGeneveTLVLocator string
	startGeneveEncapEth   bool
	startMTU              int
	startPortMACAddr      string
	startReserved         bool
	startMode             string
)

func init() {
	startCmd.Flags().StringVar(&startConfigFile, "config", "", "JSON config file (alternative to CLI flags)")
	startCmd.Flags().StringVar(&startNetNS, "netns", "", "Switch network namespace (required)")
	startCmd.Flags().StringVar(&startPortNetNS, "port-netns", "", "Ports network namespace (required for veth mode; optional for tap)")
	startCmd.Flags().Uint32Var(&startPorts, "ports", 0, "Number of ports (1-4096, required)")
	startCmd.Flags().StringVar(&startMACAddr, "mac-addr", "", "Virtual MAC address (required)")
	startCmd.Flags().StringVar(&startFloatingIPBase, "floating-ip-base", "", "Floating IP base address (required)")
	startCmd.Flags().StringArrayVar(&startMgmtExtracts, "mgmt-extract", nil, "Management plane extraction CIDRs (format: <netns>:<dev>:<cidr1>,<cidr2>,...; CIDRs are traffic matches, not interface addresses; leave <netns> empty, e.g. ':mgmt0:1.2.3.4', to keep the peer in the caller/host netns)")
	startCmd.Flags().StringArrayVar(&startMgmtServices, "mgmt-service", nil, "Management service VIP<->target translation (format: <VIP>:<vport>:<targetIP>:<targetPort>; repeatable). VIP must fall within a --mgmt-extract route. Translates both TCP and UDP. Each (targetIP,targetPort) must be unique. Loopback targets require route_localnet=1 on the mgmt dev.")
	startCmd.Flags().StringVar(&startTransitDev, "transit-dev", "", "Transit device name")
	startCmd.Flags().StringVar(&startTransitDevAddr, "transit-dev-addr", "", "Transit device address (format: <ip>/<prefix>:<nexthop> or 'auto' for DHCP)")
	startCmd.Flags().StringVar(&startTransitDevMTU, "transit-dev-mtu", "", "Transit device MTU ('auto' or specific value, default: no change)")
	startCmd.Flags().StringVar(&startGeneveLocator, "geneve-locator", "port", "GENEVE slot locator (port, vni, or tlv)")
	startCmd.Flags().Uint16Var(&startGenevePortBase, "geneve-port-base", 50000, "GENEVE UDP port base")
	startCmd.Flags().StringVar(&startGeneveTLVLocator, "geneve-tlv-locator", "", "GENEVE TLV slot locator CLASS:TYPE (required with --geneve-locator=tlv)")
	startCmd.Flags().BoolVar(&startGeneveEncapEth, "geneve-encap-eth", false, "Use Ether-over-GENEVE (default: IP-over-GENEVE)")
	startCmd.Flags().IntVar(&startMTU, "mtu", 0, "Requested MTU for management setup and transit budgeting; not applied to TAP/veth ports by two-phase provisioning")
	startCmd.Flags().StringVar(&startPortMACAddr, "port-mac-addr", "fixed", "Port MAC address mode: 'fixed' (default), 'per-port', or specific MAC address")
	startCmd.Flags().BoolVar(&startReserved, "reserved", false, "Only initialize Reserved slots; set --port-netns now if later provisioning veth peers because provision reads the pinned start-time configuration")
	startCmd.Flags().StringVar(&startMode, "mode", "tap", `Port kind for the auto-provision step: "tap" (default) or "veth". With tap (default), ports stay in switch-netns and the sandbox receives a fd via 'open-port' (--port-netns optional); veth moves a peer into the sandbox netns and requires --port-netns.`)
}

// buildConfig builds a vswitch.Config from CLI flags or config file.
func buildConfig(args []string) (*vswitch.Config, error) {
	var cfg *vswitch.Config

	if startConfigFile != "" {
		// Load from config file
		var err error
		cfg, err = vswitchLoadConfigFile(startConfigFile)
		if err != nil {
			return nil, fmt.Errorf("load config: %w", err)
		}
		// CLI arg overrides config file switch_name
		if len(args) > 0 && args[0] != "" {
			cfg.Name = args[0]
		}
	} else {
		if len(args) == 0 {
			return nil, fmt.Errorf("switch_name argument is required (or use --config)")
		}
		switchName := args[0]

		// Parse MAC address
		mac, err := net.ParseMAC(startMACAddr)
		if err != nil {
			return nil, fmt.Errorf("invalid MAC address: %w", err)
		}

		// Parse floating IP base
		floatingIP := net.ParseIP(startFloatingIPBase)
		if floatingIP == nil {
			return nil, fmt.Errorf("invalid floating-ip-base: %s", startFloatingIPBase)
		}
		geneveLocator, err := vswitch.ParseGeneveLocator(startGeneveLocator)
		if err != nil {
			return nil, err
		}
		var geneveTLVLocator *vswitch.GeneveTLVLocator
		if startGeneveTLVLocator != "" {
			parsed, err := vswitch.ParseGeneveTLVLocator(startGeneveTLVLocator)
			if err != nil {
				return nil, err
			}
			geneveTLVLocator = &parsed
		}

		cfg = &vswitch.Config{
			Name:             switchName,
			SwitchNetNS:      startNetNS,
			PortNetNS:        startPortNetNS,
			NumPorts:         startPorts,
			MACAddr:          mac,
			FloatingIPBase:   floatingIP,
			GeneveLocator:    geneveLocator,
			GenevePortBase:   startGenevePortBase,
			GeneveTLVLocator: geneveTLVLocator,
			GeneveEncapEth:   startGeneveEncapEth,
			MTU:              startMTU,
		}

		// Parse management extractions
		for _, me := range startMgmtExtracts {
			extract, err := vswitch.ParseMgmtExtract(me)
			if err != nil {
				return nil, fmt.Errorf("invalid mgmt-extract: %w", err)
			}
			cfg.MgmtExtracts = append(cfg.MgmtExtracts, extract)
		}

		// Parse management service translations
		for _, ms := range startMgmtServices {
			svc, err := vswitch.ParseMgmtService(ms)
			if err != nil {
				return nil, fmt.Errorf("invalid mgmt-service: %w", err)
			}
			cfg.MgmtServices = append(cfg.MgmtServices, svc)
		}

		// Parse transit device config
		if startTransitDev != "" {
			cfg.TransitDev = startTransitDev

			if startTransitDevAddr != "" {
				if startTransitDevAddr == "auto" {
					cfg.TransitAddrAuto = true
				} else {
					addr, gw, err := vswitch.ParseTransitDevAddr(startTransitDevAddr)
					if err != nil {
						return nil, fmt.Errorf("invalid transit-dev-addr: %w", err)
					}
					cfg.TransitAddr = addr
					cfg.TransitNexthop = gw
				}
			}

			if startTransitDevMTU != "" {
				if startTransitDevMTU == "auto" {
					cfg.TransitDevMTUAuto = true
				} else {
					mtu, err := strconv.Atoi(startTransitDevMTU)
					if err != nil || mtu <= 0 {
						return nil, fmt.Errorf("invalid transit-dev-mtu: %s", startTransitDevMTU)
					}
					cfg.TransitDevMTU = mtu
				}
			}
		}

		// Parse port-mac-addr
		switch startPortMACAddr {
		case "fixed":
			cfg.PortMAC = vswitch.PortMACFixed(mac)
		case "per-port":
			cfg.PortMAC = make(net.HardwareAddr, 6) // all zeros
		default:
			portMAC, err := net.ParseMAC(startPortMACAddr)
			if err != nil {
				return nil, fmt.Errorf("invalid port-mac-addr: expected 'fixed', 'per-port', or MAC address")
			}
			cfg.PortMAC = portMAC
		}
	}

	return cfg, nil
}

func runStart(cmd *cobra.Command, args []string) error {
	cfg, err := buildConfig(args)
	if err != nil {
		return err
	}

	// Parse --mode. With --reserved no auto-provision happens, so DefaultMode
	// is purely a validation hint here (it controls whether port-netns is
	// required — see Config.ValidateReserved). The actual per-slot mode is
	// chosen later via `provision --mode=...`.
	mode, err := vswitch.ParsePortKind(startMode)
	if err != nil {
		return fmt.Errorf("invalid --mode: %w", err)
	}
	cfg.DefaultMode = mode

	var output *vswitch.StartOutput

	if startReserved {
		output, err = vswitchStartReserved(cfg)
	} else {
		output, err = vswitchStart(cfg)
	}

	if err != nil {
		if vswitch.IsConfigMismatch(err) {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			osExit(1)
		}
		return err
	}

	return printJSON(output)
}
