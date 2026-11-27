package main

import (
	"encoding/json"
	"fmt"
	"os/signal"
	"syscall"

	"github.com/kuasar-sandbox/connector/pkg/egress"
	"github.com/kuasar-sandbox/connector/pkg/vswitch"
	"github.com/spf13/cobra"
)

func newEgressCommand() *cobra.Command {
	root := &cobra.Command{Use: "egress", Short: "Manage the unified Geneve Egress gateway"}
	for _, mode := range []string{"validate", "serve"} {
		var path string
		cmd := &cobra.Command{Use: mode, Short: map[string]string{"validate": "Validate gateway configuration", "serve": "Run Egress in the gateway interface network namespace"}[mode], Args: cobra.NoArgs}
		cmd.Flags().StringVar(&path, "config", "", "Gateway JSON/YAML configuration")
		_ = cmd.MarkFlagRequired("config")
		cmd.RunE = func(cmd *cobra.Command, _ []string) error {
			_, err := egress.LoadConfig(path)
			if err != nil {
				return err
			}
			if mode == "validate" {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]bool{"valid": true})
			}
			ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer cancel()
			return egress.Serve(ctx, path, cmd.ErrOrStderr())
		}
		root.AddCommand(cmd)
	}
	root.AddCommand(newEgressStatusCommand())
	links := &cobra.Command{Use: "link", Short: "Own local veth wiring and stable vSwitch namespace handoff"}
	for _, operation := range []string{"prepare", "check", "start", "stop", "repair", "uninstall"} {
		var config, switchConfig, mode string
		cmd := &cobra.Command{Use: operation, Args: cobra.NoArgs, Short: fmt.Sprintf("%s a managed local transit attachment", operation)}
		cmd.Flags().StringVar(&config, "config", "", "Local link JSON configuration")
		_ = cmd.MarkFlagRequired("config")
		if operation == "start" || operation == "repair" {
			cmd.Flags().StringVar(&switchConfig, "switch-config", "", "Existing vSwitch JSON/YAML configuration")
			_ = cmd.MarkFlagRequired("switch-config")
			cmd.Flags().StringVar(&mode, "mode", "tap", "Port kind: tap or veth, matching vswitch start")
		}
		cmd.RunE = func(cmd *cobra.Command, _ []string) error {
			c, err := egress.LoadLink(config)
			if err != nil {
				return err
			}
			var result any
			switch operation {
			case "prepare":
				result, err = egress.PrepareLink(c)
			case "check":
				result, err = egress.CheckLink(c)
			case "stop":
				err = egress.StopLocalSwitch(c)
			case "uninstall":
				err = egress.UninstallLink(c)
			default:
				var sw *vswitch.Config
				sw, err = vswitch.LoadConfigFile(switchConfig)
				if err != nil {
					return err
				}
				sw.DefaultMode, err = vswitch.ParsePortKind(mode)
				if err != nil {
					return err
				}
				if operation == "start" {
					result, err = egress.StartLocalSwitch(c, sw)
				} else {
					result, err = egress.RepairLink(c, sw)
				}
			}
			if err != nil {
				return err
			}
			if result == nil {
				result = map[string]bool{"complete": true}
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
		}
		links.AddCommand(cmd)
	}
	root.AddCommand(links)
	return root
}
func init() { rootCmd.AddCommand(newEgressCommand()) }
