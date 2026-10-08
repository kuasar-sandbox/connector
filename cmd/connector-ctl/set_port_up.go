package main

import (
	"fmt"
	"github.com/kuasar-sandbox/connector/pkg/vswitch"
	"github.com/spf13/cobra"
	"net"
)

var setPortUpCmd = &cobra.Command{Use: "set-port-up <switch_name>", Short: "Commit final configuration and bring an attached down port up", Args: cobra.ExactArgs(1), RunE: runSetPortUp}
var upPort int
var upInnerIP, upGateway, upMAC string
var upVNI uint32
var upOpts []string

func init() {
	f := setPortUpCmd.Flags()
	f.IntVar(&upPort, "port", 0, "Attached port (required)")
	f.StringVar(&upInnerIP, "inner-ip", "", "Final inner IPv4 (required)")
	f.StringVar(&upGateway, "transit-gateway-ip", "", "Final transit gateway")
	f.Uint32Var(&upVNI, "transit-geneve-vni", 0, "Final transit VNI")
	f.StringArrayVar(&upOpts, "transit-geneve-opt", nil, "Opaque GENEVE option CLASS:TYPE:DATA")
	f.StringVar(&upMAC, "transit-mac-addr", "", "Final transit MAC")
	_ = setPortUpCmd.MarkFlagRequired("port")
	_ = setPortUpCmd.MarkFlagRequired("inner-ip")
}
func runSetPortUp(_ *cobra.Command, args []string) error {
	ip := net.ParseIP(upInnerIP)
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("invalid final inner IPv4 %q", upInnerIP)
	}
	o := vswitch.PortUpOptions{Port: upPort, InnerIP: ip, TransitGeneveVNI: upVNI}
	if upGateway != "" {
		o.TransitGatewayIP = net.ParseIP(upGateway)
		if o.TransitGatewayIP == nil || o.TransitGatewayIP.To4() == nil {
			return fmt.Errorf("invalid transit gateway %q", upGateway)
		}
	}
	if upMAC != "" {
		mac, e := net.ParseMAC(upMAC)
		if e != nil {
			return e
		}
		o.TransitMAC = mac
	}
	for _, v := range upOpts {
		x, e := vswitch.ParseGeneveOption(v)
		if e != nil {
			return e
		}
		o.TransitGeneveOpts = append(o.TransitGeneveOpts, x)
	}
	return vswitch.SetPortUp(args[0], o)
}
