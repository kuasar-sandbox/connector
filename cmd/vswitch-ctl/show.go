package main

import (
	"fmt"
	"net"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/fullof-work/sandbox-vswitch/pkg/vswitch"
)

// showCmd groups read-only inspection subcommands.
var showCmd = &cobra.Command{
	Use:   "show",
	Short: "Inspect switch internals (slots, config)",
	Long: `Inspect the runtime state of a virtual switch.

Subcommands:
  slots <switch_name> [slot_id]   Dump the port slot table as JSON (filterable)
  config <switch_name>            Dump the in-kernel switch config as JSON`,
}

var showSlotsCmd = &cobra.Command{
	Use:   "slots <switch_name> [slot_id]",
	Short: "Dump the port slot table as JSON",
	Long: `Print the port slot table as a JSON array. Each entry contains the
slot's inner_ip ("0.0.0.0" = free, "255.255.255.255" = reserved, otherwise
the allocated sandbox IP), floating_ip, port_mac, allocation state, and
transit info.

If [slot_id] (0-indexed) is given, the array contains only that slot.`,
	Args: cobra.RangeArgs(1, 2),
	RunE: runShowSlots,
}

var showConfigCmd = &cobra.Command{
	Use:   "config <switch_name>",
	Short: "Dump the in-kernel switch config as JSON",
	Args:  cobra.ExactArgs(1),
	RunE:  runShowConfig,
}

func init() {
	showCmd.AddCommand(showSlotsCmd)
	showCmd.AddCommand(showConfigCmd)
}

// SlotJSON is the JSON-friendly view of a single port slot.
type SlotJSON struct {
	SlotID           uint32 `json:"slot_id"`
	Port             int    `json:"port"`
	State            string `json:"state"` // "free", "reserved", "allocated"
	Mode             string `json:"mode"`  // "veth" or "tap"
	Allocated        bool   `json:"allocated"`
	InnerIP          string `json:"inner_ip"`
	FloatingIP       string `json:"floating_ip"`
	PortMAC          string `json:"port_mac"`
	TransitIP        string `json:"transit_ip,omitempty"`
	TransitGatewayIP string `json:"transit_gateway_ip,omitempty"`
	TransitGeneveVNI uint32 `json:"transit_geneve_vni,omitempty"`
	TransitMAC       string `json:"transit_mac,omitempty"`
	Ifindex          uint32 `json:"ifindex"`
}

// ConfigJSON is the JSON-friendly view of the in-kernel SwitchConfig.
type ConfigJSON struct {
	SwitchMAC      string `json:"switch_mac"`
	PortMAC        string `json:"port_mac"`
	NPorts         uint32 `json:"n_ports"`
	FloatingIPBase string `json:"floating_ip_base"`
	GenevePortBase uint32 `json:"geneve_port_base"`
	GeneveEncapEth bool   `json:"geneve_encap_eth"`
	TransitNexthop string `json:"transit_nexthop,omitempty"`
}

func runShowSlots(cmd *cobra.Command, args []string) error {
	switchName := args[0]

	sw, err := vswitchOpen(switchName)
	if err != nil {
		if vswitch.IsNotExist(err) {
			fmt.Printf("Switch %s is not running\n", switchName)
			osExit(3)
			return nil
		}
		return err
	}
	defer sw.Close()

	cfg := sw.Config()
	slots := sw.Ports(false)

	// Optional slot_id filter (0-indexed).
	var filter *uint32
	if len(args) == 2 {
		v, err := strconv.ParseUint(args[1], 10, 32)
		if err != nil {
			return fmt.Errorf("invalid slot_id %q: %w", args[1], err)
		}
		if uint32(v) >= cfg.N_ports {
			return fmt.Errorf("slot_id %d out of range (max %d)", v, cfg.N_ports-1)
		}
		sid := uint32(v)
		filter = &sid
	}

	out := []SlotJSON{}
	for _, ps := range slots {
		sid := uint32(ps.Port - 1)
		if filter != nil && sid != *filter {
			continue
		}
		out = append(out, slotToJSON(cfg, ps, sid))
	}
	return printJSON(out)
}

func slotToJSON(cfg *vswitch.SwitchConfig, ps vswitch.PortSlot, sid uint32) SlotJSON {
	state := "allocated"
	switch ps.InnerIp {
	case vswitch.InnerIPFree:
		state = "free"
	case vswitch.InnerIPReserved:
		state = "reserved"
	}
	portMAC := vswitch.GetPortMAC(cfg.SwitchMac[:], cfg.PortMac[:], sid)
	sj := SlotJSON{
		SlotID:           sid,
		Port:             ps.Port,
		State:            state,
		Mode:             vswitch.SlotPortKind(&ps.SlotItem).String(),
		Allocated:        ps.Allocated,
		InnerIP:          vswitch.Uint32ToIP(ps.InnerIp).String(),
		FloatingIP:       vswitch.Uint32ToIP(cfg.FloatingIpBase + sid).String(),
		PortMAC:          portMAC.String(),
		Ifindex:          ps.Ifindex,
		TransitGeneveVNI: ps.TransitGeneveVni,
	}
	if ps.TransitIp != 0 {
		sj.TransitIP = vswitch.Uint32ToIP(ps.TransitIp).String()
	}
	if ps.TransitGatewayIp != 0 {
		sj.TransitGatewayIP = vswitch.Uint32ToIP(ps.TransitGatewayIp).String()
	}
	if mac := (net.HardwareAddr)(ps.TransitMac[:]); !isZeroMAC(mac) {
		sj.TransitMAC = mac.String()
	}
	return sj
}

func isZeroMAC(mac net.HardwareAddr) bool {
	for _, b := range mac {
		if b != 0 {
			return false
		}
	}
	return true
}

func runShowConfig(cmd *cobra.Command, args []string) error {
	switchName := args[0]

	sw, err := vswitchOpen(switchName)
	if err != nil {
		if vswitch.IsNotExist(err) {
			fmt.Printf("Switch %s is not running\n", switchName)
			osExit(3)
			return nil
		}
		return err
	}
	defer sw.Close()

	cfg := sw.Config()
	switchMAC := net.HardwareAddr(cfg.SwitchMac[:]).String()
	portMAC := net.HardwareAddr(cfg.PortMac[:]).String()

	out := ConfigJSON{
		SwitchMAC:      switchMAC,
		PortMAC:        portMAC,
		NPorts:         cfg.N_ports,
		FloatingIPBase: vswitch.Uint32ToIP(cfg.FloatingIpBase).String(),
		GenevePortBase: cfg.GenevePortBase,
		GeneveEncapEth: cfg.GeneveEncapEth != 0,
	}
	if cfg.TransitNexthop != 0 {
		out.TransitNexthop = vswitch.Uint32ToIP(cfg.TransitNexthop).String()
	}
	return printJSON(out)
}
