package netlink

import (
	"fmt"
	"net"
)

// LinkConfig describes configuration to apply to a link.
type LinkConfig struct {
	Name         string           // Device name
	HardwareAddr net.HardwareAddr // MAC address (nil = don't change)
	Up           bool             // true = bring up the link
}

// ConfigureLinks applies configurations to multiple links.
// This batches multiple operations within a single netns context.
func ConfigureLinks(configs []LinkConfig) error {
	for _, cfg := range configs {
		link, err := netlinkLinkByName(cfg.Name)
		if err != nil {
			return fmt.Errorf("get link %s: %w", cfg.Name, err)
		}

		if cfg.HardwareAddr != nil {
			if err := netlinkLinkSetHardwareAddr(link, cfg.HardwareAddr); err != nil {
				return fmt.Errorf("set MAC on %s: %w", cfg.Name, err)
			}
		}

		if cfg.Up {
			if err := netlinkLinkSetUp(link); err != nil {
				return fmt.Errorf("bring up %s: %w", cfg.Name, err)
			}
		}
	}
	return nil
}

// MoveLinksToNs moves multiple links to a target namespace.
// Must be called from the source namespace.
func MoveLinksToNs(names []string, targetNsFd int) error {
	for _, name := range names {
		link, err := netlinkLinkByName(name)
		if err != nil {
			return fmt.Errorf("get link %s: %w", name, err)
		}
		if err := netlinkLinkSetNsFd(link, targetNsFd); err != nil {
			return fmt.Errorf("move %s to ns: %w", name, err)
		}
	}
	return nil
}
