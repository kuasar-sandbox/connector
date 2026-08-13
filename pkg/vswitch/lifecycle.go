package vswitch

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kuasar-sandbox/connector/pkg/dhcp"
	"github.com/kuasar-sandbox/connector/pkg/internal/bpf"
	"github.com/kuasar-sandbox/connector/pkg/netlink"
	"github.com/kuasar-sandbox/connector/pkg/netns"
)

const defaultPortMTU = 1500

// getTransitDeviceMTU gets the MTU of transit device in caller's namespace.
func getTransitDeviceMTU(transitDev string) (int, error) {
	callerNs, err := netnsGetCurrent()
	if err != nil {
		return 0, fmt.Errorf("failed to get current netns: %w", err)
	}
	defer callerNs.Close()

	mtu, err := netlinkGetMTUInNs(callerNs, transitDev)
	if err != nil {
		return 0, fmt.Errorf("failed to get MTU for transit device %s: %w", transitDev, err)
	}
	return mtu, nil
}

// resolveTransitMTU resolves transit device MTU based on the three-branch logic:
//   - TransitDevMTUAuto: compute and store requiredMTU
//   - TransitDevMTU > 0 (explicit): validate it's sufficient
//   - neither: validate existing device MTU is sufficient
//
// portMTU is the discovered/configured port MTU (cfg.MTU or read from veths).
func resolveTransitMTU(cfg *Config, portMTU int) error {
	baseOverhead := GeneveIPOverhead
	overheadName := "IP-over-GENEVE"
	if cfg.GeneveEncapEth {
		baseOverhead = GeneveEthOverhead
		overheadName = "Ether-over-GENEVE"
	}
	optionsOverhead := 0
	if cfg.GeneveLocator == GeneveLocatorTLV {
		optionsOverhead = geneveTLVLocatorWireLen
	}
	// Auto mode reserves the full protocol maximum so every later valid Attach
	// fits without resizing an active transit device.
	if cfg.TransitDevMTUAuto {
		optionsOverhead = int(MaxGeneveOptsLen)
	}
	requiredMTU := portMTU + baseOverhead + optionsOverhead

	if cfg.TransitDevMTUAuto {
		cfg.TransitDevMTU = requiredMTU
		return nil
	}
	if cfg.TransitDevMTU > 0 {
		if cfg.TransitDevMTU < requiredMTU {
			return fmt.Errorf("transit-dev-mtu %d is too small: requires at least %d (port MTU %d + %s overhead %d + fixed options overhead %d)",
				cfg.TransitDevMTU, requiredMTU, portMTU, overheadName, baseOverhead, optionsOverhead)
		}
		return nil
	}
	// Not setting transit MTU - validate existing device MTU
	transitMTU, err := getTransitDeviceMTU(cfg.TransitDev)
	if err != nil {
		return err
	}
	if transitMTU < requiredMTU {
		return fmt.Errorf("transit device %s MTU %d is too small: requires at least %d (port MTU %d + %s overhead %d + fixed options overhead %d)",
			cfg.TransitDev, transitMTU, requiredMTU, portMTU, overheadName, baseOverhead, optionsOverhead)
	}
	return nil
}

// validateTransitDeviceEarly validates transit device state and MTU before resource creation.
// This is the "fast path" validation when --mtu is specified.
func validateTransitDeviceEarly(cfg *Config) error {
	if cfg.TransitDev == "" {
		return nil
	}

	// Safety check: ensure transit device is DOWN
	isDown, err := netlinkIsLinkDown(cfg.TransitDev)
	if err != nil {
		return fmt.Errorf("failed to check transit device state: %w", err)
	}
	if !isDown {
		return fmt.Errorf("transit device %s must be DOWN before use (safety check)", cfg.TransitDev)
	}

	// Fast path MTU validation (only when --mtu is specified)
	if cfg.MTU > 0 {
		return resolveTransitMTU(cfg, cfg.MTU)
	}

	return nil
}

// buildVethSpecs builds veth pair specifications for all ports.
// Extracted for testability.
func buildVethSpecs(cfg *Config, portNsFd int) []netlink.VethSpec {
	specs := make([]netlink.VethSpec, cfg.NumPorts)
	for i := uint32(0); i < cfg.NumPorts; i++ {
		peerMAC := GetPortMAC(cfg.MACAddr, cfg.PortMAC, i)
		specs[i] = netlink.VethSpec{
			Name:        cfg.PeerDeviceName(int(i)),
			PeerName:    cfg.PortDeviceName(int(i)),
			MTU:         cfg.MTU,
			PeerNsFd:    portNsFd,
			PeerMACAddr: peerMAC,
			Group:       PortLinkGroup,
		}
	}
	return specs
}

// attachTCToPorts adds clsact with shared block to all port peer devices.
// Returns peer ifindexes. The block filter is shared via the dummy device.
func attachTCToPorts(cfg *Config) ([]int, error) {
	peerIfindexes := make([]int, cfg.NumPorts)
	startTime := time.Now()
	lastProgressTime := startTime
	const progressInterval = 5 * time.Second

	for i := uint32(0); i < cfg.NumPorts; i++ {
		peerName := cfg.PeerDeviceName(int(i))

		link, err := netlinkLinkByName(peerName)
		if err != nil {
			return nil, fmt.Errorf("get link %s: %w", peerName, err)
		}
		ifindex := link.Attrs().Index

		if err := netlinkAddClsactWithBlock(ifindex, PortIngressBlockID); err != nil {
			return nil, fmt.Errorf("configure %s: %w", peerName, err)
		}
		peerIfindexes[i] = ifindex

		// Report progress every 5 seconds
		if now := time.Now(); now.Sub(lastProgressTime) >= progressInterval {
			elapsed := now.Sub(startTime).Seconds()
			fmt.Fprintf(os.Stderr, "[info] TC attach progress: %d/%d ports (%.1fs elapsed)\n", i+1, cfg.NumPorts, elapsed)
			lastProgressTime = now
		}
	}
	return peerIfindexes, nil
}

// createPortVethPairs creates all port veth pairs and adds clsact with shared block.
// Returns the peer ifindexes for slot initialization.
func createPortVethPairs(cfg *Config, switchNs, portNs *netns.NetNS) ([]int, error) {
	// Phase 1: Batch create all veth pairs in switch namespace
	portNsFd := int(portNs.Handle())
	if err := netnsDoFn(switchNs, func() error {
		specs := buildVethSpecs(cfg, portNsFd)
		return netlinkCreateVethPairs(specs)
	}); err != nil {
		return nil, fmt.Errorf("failed to create veth pairs: %w", err)
	}

	// Phase 2: Add clsact with shared block to all port peers
	var peerIfindexes []int
	if err := netnsDoFn(switchNs, func() error {
		var err error
		peerIfindexes, err = attachTCToPorts(cfg)
		return err
	}); err != nil {
		return nil, fmt.Errorf("failed to configure ports in switch namespace: %w", err)
	}

	return peerIfindexes, nil
}

// initBPFSlotsReserved initializes all BPF slots to Reserved state via mmap CAS.
// Must be called after mmap is created.
func initBPFSlotsReserved(mmapSlots *MmappedSlots, numPorts uint32) error {
	for i := uint32(0); i < numPorts; i++ {
		if !InitSlotReserved(mmapSlots, i) {
			return fmt.Errorf("failed to reserve slot %d during init (unexpected non-Free state)", i)
		}
	}
	return nil
}

// floatingReturnPrefix is the prefix length of the return route(s) installed in
// each management namespace. The floating-IP space is slot_id-indexed over at
// most MaxPorts (=4096 = 2^12) addresses, so a fixed /20 exactly covers one
// aligned block.
const floatingReturnPrefix = 20

// floatingReturnNets returns the /20 network(s) that must be routed back toward
// the switch so management-service replies addressed to a floating IP reach the
// sw-mX TC ingress. The covered window is [base, base+MaxPorts-1]; since the
// window width equals the /20 block size it touches exactly one block when base
// is /20-aligned and two adjacent blocks otherwise (we install both rather than
// require alignment). Returns nil for a nil/non-IPv4 base (floating IPs are
// IPv4 — the BPF floating_ip_base is a __u32); the caller then installs no
// return route.
func floatingReturnNets(base net.IP) []*net.IPNet {
	if base.To4() == nil {
		return nil
	}
	mask := net.CIDRMask(floatingReturnPrefix, 32)
	maskU := bpf.MaskToUint32(mask)

	u := bpf.IPToUint32(base)
	startNet := u & maskU

	nets := []*net.IPNet{{IP: bpf.Uint32ToIP(startNet), Mask: mask}}

	endU := u + (MaxPorts - 1)
	if endU < u { // uint32 overflow near the top of the address space
		return nets
	}
	if endNet := endU & maskU; endNet != startNet {
		nets = append(nets, &net.IPNet{IP: bpf.Uint32ToIP(endNet), Mask: mask})
	}
	return nets
}

// createMgmtPlanes creates management veth pairs and configures the extraction
// data path. Extraction CIDRs are not assigned as management-side addresses.
// Returns the mgmt plane info list. Does NOT write to slots (deferred to ProvisionPorts).
func createMgmtPlanes(cfg *Config, switchNs *netns.NetNS, objects *bpf.Objects, cs *cleanupState) ([]MgmtPlaneInfo, error) {
	mgmtPlanes := []MgmtPlaneInfo{}

	for i, me := range cfg.MgmtExtracts {
		mgmtName := cfg.MgmtDeviceName(i)
		metric := 100 + i // per-plane metric to avoid route conflicts

		// Get management namespace. Empty me.NetNS means "caller netns" — used when
		// the mgmt service runs directly on the host (no dedicated netns).
		var mgmtNs *netns.NetNS
		var err error
		if me.IsCallerNetNS() {
			mgmtNs, err = netnsGetCurrent()
			if err != nil {
				return nil, fmt.Errorf("failed to get caller netns for mgmt plane %d: %w", i, err)
			}
		} else {
			mgmtNs, err = netnsGetByName(me.NetNS)
			if err != nil {
				return nil, fmt.Errorf("failed to get mgmt netns %s: %w", me.NetNS, err)
			}
		}

		// Compute MAC before CreateVethPairs so it can be set at creation time
		mgmtDevMAC := MgmtMAC(cfg.MACAddr, i)

		// Create veth pair via CreateVethPairs:
		// - MTU is set during creation (saves 2 SetMTU calls)
		// - Peer is placed directly in mgmt ns (saves 1 MoveDevice call)
		// - Peer MAC is set during creation (saves 1 SetHardwareAddr call)
		// - Group is set for batch deletion
		mgmtNsFd := int(mgmtNs.Handle())
		spec := netlink.VethSpec{
			Name:        mgmtName,
			PeerName:    me.Dev,
			MTU:         cfg.MTU,
			PeerNsFd:    mgmtNsFd,
			PeerMACAddr: mgmtDevMAC,
			Group:       MgmtLinkGroup,
		}
		if err := netnsDoFn(switchNs, func() error {
			return netlinkCreateVethPairs([]netlink.VethSpec{spec})
		}); err != nil {
			mgmtNs.Close()
			return nil, fmt.Errorf("failed to create mgmt veth pair %d: %w", i, err)
		}
		// Get mgmt ifindex for cleanup tracking
		mgmtIfindex, err := netlinkGetLinkIndexInNs(switchNs, mgmtName)
		if err != nil {
			mgmtNs.Close()
			return nil, fmt.Errorf("failed to get ifindex for mgmt device %s: %w", mgmtName, err)
		}
		cs.mgmtIfindexes = append(cs.mgmtIfindexes, mgmtIfindex)

		// Attach TC ingress to mgmt port (ARP proxy + DNAT for responses)
		if err := netnsDoFn(switchNs, func() error {
			return netlinkAttachTC(mgmtName, objects.Programs.IngressMX, netlink.Ingress)
		}); err != nil {
			mgmtNs.Close()
			return nil, fmt.Errorf("failed to attach TC to %s: %w", mgmtName, err)
		}

		// Configure device in mgmt namespace:
		// MAC is already set by CreateVethPairs, only need:
		// 1. Bring up
		// 2. Add return route(s) for floating_ip traffic
		if err := netnsDoFn(mgmtNs, func() error {
			if err := netlinkSetLinkUp(me.Dev); err != nil {
				return fmt.Errorf("bring up: %w", err)
			}

			// Add return route(s) (direct, no gateway) scoped to the floating-IP
			// /20 block(s) so management-service responses to a floating_ip route
			// back through sw-mX, without hijacking the mgmt netns default route.
			for _, fn := range floatingReturnNets(cfg.FloatingIPBase) {
				if err := netlinkAddDeviceRoute(me.Dev, fn, metric); err != nil {
					return fmt.Errorf("add return route: %w", err)
				}
			}

			return nil
		}); err != nil {
			mgmtNs.Close()
			return nil, fmt.Errorf("failed to configure %s in %s: %w", me.Dev, me.NetNS, err)
		}

		routes := []string{}
		for _, r := range me.ServiceRoutes {
			routes = append(routes, r.String())
		}
		mgmtPlanes = append(mgmtPlanes, MgmtPlaneInfo{
			Index:             i,
			MgmtNetNS:         me.NetNS,
			MgmtDev:           me.Dev,
			ServiceRoutes:     routes,
			ReturnRouteMetric: metric,
		})

		mgmtNs.Close()
	}

	return mgmtPlanes, nil
}

// validateMTUSlowPath validates MTU when --mtu was not specified.
// Reads actual MTU from created veths and validates/calculates transit dev MTU.
// Port veths that don't exist yet (e.g., in StartReserved) use the kernel
// default MTU that ProvisionPorts will assign.
func validateMTUSlowPath(cfg *Config, switchNs *netns.NetNS) error {
	if cfg.MTU != 0 || cfg.TransitDev == "" {
		return nil
	}

	var portMTU int
	// Find max MTU among port veths (sw-nX) and mgmt veths (sw-mX).
	// Port veths may not exist yet (StartReserved creates them later via ProvisionPorts),
	// so missing devices are skipped gracefully.
	for i := uint32(0); i < cfg.NumPorts; i++ {
		peerName := cfg.PeerDeviceName(int(i))
		mtu, err := netlinkGetMTUInNs(switchNs, peerName)
		if err != nil {
			continue // device not yet created (StartReserved context)
		}
		if mtu > portMTU {
			portMTU = mtu
		}
	}
	for i := range cfg.MgmtExtracts {
		mgmtName := cfg.MgmtDeviceName(i)
		mtu, err := netlinkGetMTUInNs(switchNs, mgmtName)
		if err != nil {
			return fmt.Errorf("failed to get MTU for %s: %w", mgmtName, err)
		}
		if mtu > portMTU {
			portMTU = mtu
		}
	}

	if portMTU == 0 {
		portMTU = defaultPortMTU
	}
	return resolveTransitMTU(cfg, portMTU)
}

// configureTransitDevice moves and configures the transit device.
// Returns the transit device IP string.
func configureTransitDevice(cfg *Config, switchNs *netns.NetNS, objects *bpf.Objects, cs *cleanupState) (string, error) {
	if cfg.TransitDev == "" {
		return "", nil
	}

	var transitDevIP string

	// Save caller namespace for potential rollback before moving transit device
	callerNs, err := netnsGetCurrent()
	if err != nil {
		return "", fmt.Errorf("failed to get current netns: %w", err)
	}
	cs.callerNs = callerNs
	cs.transitDevName = cfg.TransitDev

	// Move transit device from caller's namespace to switch namespace
	if err := netnsMoveDevice(cfg.TransitDev, callerNs, switchNs); err != nil {
		cs.callerNs.Close()
		cs.callerNs = nil
		return "", fmt.Errorf("failed to move transit device %s to switch netns: %w", cfg.TransitDev, err)
	}
	cs.transitMoved = true

	// Configure transit device in switch namespace
	if err := netnsDoFn(switchNs, func() error {
		// Set transit device MTU if configured (before bringing up)
		if cfg.TransitDevMTU > 0 {
			if err := netlinkSetMTU(cfg.TransitDev, cfg.TransitDevMTU); err != nil {
				return fmt.Errorf("set transit MTU: %w", err)
			}
		}

		// Bring up transit device
		if err := netlinkSetLinkUp(cfg.TransitDev); err != nil {
			return err
		}

		// DHCP if auto mode - must be done after device is moved and brought up
		if cfg.TransitAddrAuto {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			lease, err := dhcpRequest(ctx, dhcp.RequestOptions{
				Interface: cfg.TransitDev,
				Timeout:   5 * time.Second,
				Retries:   3,
			})
			if err != nil {
				return fmt.Errorf("DHCP failed: %w", err)
			}

			var gatewayInferred bool
			cfg.TransitAddr, cfg.TransitNexthop, gatewayInferred = lease.ToTransitConfig()
			if gatewayInferred {
				fmt.Fprintf(os.Stderr, "[info] DHCP lease has no gateway, using subnet first IP %s as gateway\n", cfg.TransitNexthop)
			}

			// Bug fix: Update transit_nexthop in BPF config map after DHCP.
			// UpdateSwitchConfig was called before DHCP, so transit_nexthop was not set.
			if cfg.TransitNexthop != nil {
				if err := updateSwitchConfigFieldsFn(objects.Maps.Config, func(c *SwitchConfig) {
					c.TransitNexthop = bpf.IPToUint32(cfg.TransitNexthop)
				}); err != nil {
					return fmt.Errorf("failed to update transit_nexthop in config: %w", err)
				}
			}

			// Update transit address info in metadata after DHCP
			if cfg.TransitAddr != nil {
				if err := updateSwitchMetadataFieldsFn(objects.Maps.Metadata, func(m *SwitchMetadata) {
					m.TransitDevAddr = cfg.TransitAddr.String()
					if cfg.TransitNexthop != nil {
						m.TransitDevNexthop = cfg.TransitNexthop.String()
					}
				}); err != nil {
					return fmt.Errorf("failed to update transit info in metadata: %w", err)
				}
			}
		}

		// Add address if configured (either manual or from DHCP)
		if cfg.TransitAddr != nil {
			if err := netlinkAddAddr(cfg.TransitDev, cfg.TransitAddr); err != nil {
				// Ignore if already exists
			}
			transitDevIP = cfg.TransitAddr.IP.String()
		}
		return netlinkAttachTC(cfg.TransitDev, objects.Programs.IngressTransit, netlink.Ingress)
	}); err != nil {
		return "", fmt.Errorf("failed to configure transit device %s: %w", cfg.TransitDev, err)
	}

	// Success: close callerNs as we no longer need it for rollback
	cs.callerNs.Close()
	cs.callerNs = nil

	return transitDevIP, nil
}

// switchMapPaths returns the bpffs pin path of every map a switch pins, keyed
// by map name. Kept in one place so command output stays in sync with
// Objects.PinMaps / LoadPinnedMaps.
func switchMapPaths(name string, includeGeneveOpts bool) map[string]string {
	maps := []string{"slots", "config", "stats", "ifindex_to_slot", "metadata", "mgmt_svc_fwd", "mgmt_svc_rev"}
	if includeGeneveOpts {
		maps = append(maps, "geneve_opts")
	}
	out := make(map[string]string, len(maps))
	for _, m := range maps {
		out[m] = fmt.Sprintf("%s/%s/%s", bpf.BPFPath, name, m)
	}
	return out
}

// buildStartOutput builds the StartOutput from configuration and created resources.
func buildStartOutput(cfg *Config, mgmtPlanes []MgmtPlaneInfo, transitDevIP string, reserved bool) *StartOutput {
	var portsAvailable, portsReserved uint32
	if reserved {
		portsReserved = cfg.NumPorts
	} else {
		portsAvailable = cfg.NumPorts
	}
	output := &StartOutput{
		Switch:         cfg.Name,
		SwitchNetNS:    cfg.SwitchNetNS,
		SwitchMaps:     switchMapPaths(cfg.Name, true),
		PortNetNS:      cfg.PortNetNS,
		Ports:          cfg.NumPorts,
		PortsUsed:      0,
		PortsAvailable: portsAvailable,
		PortsReserved:  portsReserved,
		FloatingIPBase: cfg.FloatingIPBase.String(),
		MgmtPlanes:     mgmtPlanes,
		MgmtServices:   MgmtServiceInfos(cfg.MgmtServices),
	}

	if cfg.TransitDev != "" {
		output.TransitType = "overlay-geneve"
		output.TransitDev = cfg.TransitDev
		output.TransitDevIP = transitDevIP
		output.GeneveLocator = cfg.GeneveLocator.String()
		output.GenevePort = geneveWirePort(cfg.GeneveLocator, uint32(cfg.GenevePortBase), 0)
		if cfg.GeneveLocator == GeneveLocatorPort {
			output.GenevePortBase = cfg.GenevePortBase
		}
		if cfg.GeneveLocator == GeneveLocatorTLV && cfg.GeneveTLVLocator != nil {
			output.GeneveTLVLocator = cfg.GeneveTLVLocator.String()
		}
	} else {
		output.TransitType = "none"
	}

	return output
}

// Start creates and starts a new virtual switch (full synchronous startup).
// Combines StartReserved + ProvisionPorts for backward compatibility.
// If the switch already exists with matching config, returns its current status (idempotent).
//
// cfg.DefaultMode controls the port kind for the bulk auto-provision step:
// PortKindVeth (default) creates veth pairs and requires --port-netns; PortKindTap
// creates persistent tap devices in switch-netns and does not need --port-netns.
func Start(cfg *Config) (*StartOutput, error) {
	output, err := StartReserved(cfg)
	if err != nil {
		return nil, err
	}
	_, err = ProvisionPorts(cfg.Name, ProvisionOptions{Mode: cfg.DefaultMode})
	if err != nil {
		return nil, err
	}
	return output, nil
}

// StartReserved initializes a switch with all slots in Reserved state.
// Steps 1-7 + mmap + initSlotsReserved + mgmt/transit, but skips veth creation.
// The switch is functional after this call, but ports need ProvisionPorts to become available.
func StartReserved(cfg *Config) (*StartOutput, error) {
	// 1. Config validation (relaxed: port-netns not required since no port
	// devices are provisioned here — see Config.ValidateReserved).
	if err := cfg.ValidateReserved(); err != nil {
		return nil, err
	}

	// Ensure bpffs is mounted before acquiring flock
	if err := bpfEnsureBPFFS(); err != nil {
		return nil, fmt.Errorf("failed to ensure bpffs: %w", err)
	}

	// 2. Atomic mkdir — determines if this is a new or existing switch
	pinPath := filepath.Join(bpf.BPFPath, cfg.Name)
	if err := osMkdir(pinPath, 0755); err != nil {
		if !os.IsExist(err) {
			return nil, fmt.Errorf("create pin directory %s: %w", pinPath, err)
		}
		// EEXIST: switch already exists — acquire flock, return existing
		lock, err := acquireControlLockFn(cfg.Name)
		if err != nil {
			return nil, fmt.Errorf("failed to acquire control lock: %w", err)
		}
		defer lock.Release()
		return getExistingSwitch(cfg.Name, cfg)
	}

	// New switch — acquire flock, proceed with creation
	lock, err := acquireControlLockFn(cfg.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to acquire control lock: %w", err)
	}
	defer lock.Release()

	// Initialize cleanup state early — pinDir is already created
	cs := &cleanupState{pinDirCreated: true}

	// 3. Get namespaces
	switchNs, err := netnsGetByName(cfg.SwitchNetNS)
	if err != nil {
		cs.cleanup(cfg, nil, nil)
		return nil, fmt.Errorf("failed to get switch netns %s: %w", cfg.SwitchNetNS, err)
	}
	defer switchNs.Close()

	// 4. Early transit device validation (fast path)
	if err := validateTransitDeviceEarly(cfg); err != nil {
		cs.cleanup(cfg, switchNs, nil)
		return nil, err
	}

	// 5. Load BPF objects
	objects, err := bpfLoadObjects()
	if err != nil {
		cs.cleanup(cfg, switchNs, nil)
		return nil, fmt.Errorf("failed to load BPF objects: %w", err)
	}
	cs.bpfLoaded = true

	// 6. Pin maps
	if err := bpfObjectsPinMaps(objects, cfg.Name); err != nil {
		cs.cleanup(cfg, switchNs, objects)
		return nil, fmt.Errorf("failed to pin maps: %w", err)
	}
	cs.mapsPinned = true

	// 6b. Create dummy device and attach shared block filter
	dummyDevName := cfg.DummyDeviceName()
	if err := netnsDoFn(switchNs, func() error {
		if err := netlinkCreateDummyLink(dummyDevName); err != nil {
			return fmt.Errorf("create block anchor device: %w", err)
		}
		link, err := netlinkLinkByName(dummyDevName)
		if err != nil {
			return fmt.Errorf("get block anchor device: %w", err)
		}
		if err := netlinkAddClsactWithBlock(link.Attrs().Index, PortIngressBlockID); err != nil {
			return fmt.Errorf("add clsact with block: %w", err)
		}
		if err := netlinkAddBlockFilter(PortIngressBlockID, objects.Programs.IngressNX); err != nil {
			return fmt.Errorf("add block filter: %w", err)
		}
		return nil
	}); err != nil {
		cs.cleanup(cfg, switchNs, objects)
		return nil, err
	}
	cs.dummyDevCreated = true

	// 7. Initialize switch config in BPF map (kernel-side only)
	if err := updateSwitchConfigFn(objects.Maps.Config, cfg); err != nil {
		cs.cleanup(cfg, switchNs, objects)
		return nil, err
	}

	// 7b. Initialize switch metadata in BPF map (JSON format)
	if err := updateSwitchMetadataFn(objects.Maps.Metadata, cfg); err != nil {
		cs.cleanup(cfg, switchNs, objects)
		return nil, err
	}

	// 8. Create mmap'd slots (before slot init, since InitSlotReserved uses mmap)
	mmapSlots, err := newMmappedSlotsFn(objects.Maps.Slots, cfg.NumPorts)
	if err != nil {
		cs.cleanup(cfg, switchNs, objects)
		return nil, fmt.Errorf("failed to mmap slots: %w", err)
	}
	defer mmapSlots.Close()

	// 9. Initialize all BPF slots to Reserved state via mmap CAS
	if err := initBPFSlotsReserved(mmapSlots, cfg.NumPorts); err != nil {
		cs.cleanup(cfg, switchNs, objects)
		return nil, err
	}

	// 10. Create management planes
	mgmtPlanes, err := createMgmtPlanes(cfg, switchNs, objects, cs)
	if err != nil {
		cs.cleanup(cfg, switchNs, objects)
		return nil, err
	}

	// 10a. Populate management service NAT maps (VIP<->target translation).
	if err := writeMgmtServicesFn(objects.Maps.MgmtSvcFwd, objects.Maps.MgmtSvcRev, cfg.MgmtServices); err != nil {
		cs.cleanup(cfg, switchNs, objects)
		return nil, err
	}

	// 10b. Slow-path MTU validation (when --mtu not specified, reads veth MTU)
	if err := validateMTUSlowPath(cfg, switchNs); err != nil {
		cs.cleanup(cfg, switchNs, objects)
		return nil, err
	}

	// 11. Configure transit device (MTU validation + device move)
	transitDevIP, err := configureTransitDevice(cfg, switchNs, objects, cs)
	if err != nil {
		cs.cleanup(cfg, switchNs, objects)
		return nil, err
	}

	// 12. Build and return output (reserved=true since StartReserved)
	return buildStartOutput(cfg, mgmtPlanes, transitDevIP, true), nil
}

// Returns ErrConfigMismatch if critical config fields don't match.
func getExistingSwitch(switchName string, requestedCfg *Config) (*StartOutput, error) {
	sw, err := Open(switchName)
	if err != nil {
		return nil, err
	}
	defer sw.Close()

	cfg := sw.Config()
	meta := sw.Metadata()

	// Validate critical config fields match (uses both cfg and meta)
	if err := validateConfigMatch(requestedCfg, cfg, meta); err != nil {
		return nil, err
	}

	used := uint32(len(sw.Ports(true)))
	reserved := sw.MmapSlots().CountReservedSlots()
	free := sw.MmapSlots().CountFreeSlots()

	out := &StartOutput{
		Switch:         switchName,
		SwitchNetNS:    meta.SwitchNetnsName(),
		SwitchMaps:     switchMapPaths(switchName, sw.Maps().GeneveOpts != nil),
		PortNetNS:      meta.PortNetnsName(),
		Ports:          cfg.N_ports,
		PortsUsed:      used,
		PortsAvailable: free,
		PortsReserved:  reserved,
		FloatingIPBase: bpf.Uint32ToIP(cfg.FloatingIpBase).String(),
		MgmtPlanes:     meta.MgmtPlaneInfos(),
		MgmtServices:   meta.MgmtServiceInfos(),
		TransitDev:     meta.TransitDevName(),
		TransitDevIP:   meta.TransitDevAddrStr(),
	}
	if meta.TransitDevName() != "" {
		out.TransitType = "overlay-geneve"
		locator := geneveLocatorFromConfig(cfg)
		out.GeneveLocator = locator.String()
		out.GenevePort = geneveWirePort(locator, cfg.GenevePortBase, 0)
		if locator == GeneveLocatorPort {
			out.GenevePortBase = uint16(cfg.GenevePortBase)
		}
		if locator == GeneveLocatorTLV {
			out.GeneveTLVLocator = geneveTLVLocatorFromConfig(cfg).String()
		}
	} else {
		out.TransitType = "none"
	}
	return out, nil
}

// validateConfigMatch checks that critical config fields match between requested and existing.
func validateConfigMatch(requested *Config, existing *SwitchConfig, existingMeta *SwitchMetadata) error {
	requested.applyGeneveDefaults()
	var mismatches []string

	// Core fields (from config)
	if requested.NumPorts != existing.N_ports {
		mismatches = append(mismatches, fmt.Sprintf("ports: requested %d, existing %d", requested.NumPorts, existing.N_ports))
	}

	existingFloatingIP := bpf.Uint32ToIP(existing.FloatingIpBase)
	if !requested.FloatingIPBase.Equal(existingFloatingIP) {
		mismatches = append(mismatches, fmt.Sprintf("floating_ip_base: requested %s, existing %s", requested.FloatingIPBase, existingFloatingIP))
	}

	// Namespace fields (from metadata)
	if requested.SwitchNetNS != existingMeta.SwitchNetnsName() {
		mismatches = append(mismatches, fmt.Sprintf("switch_netns: requested %s, existing %s", requested.SwitchNetNS, existingMeta.SwitchNetnsName()))
	}

	if requested.PortNetNS != existingMeta.PortNetnsName() {
		mismatches = append(mismatches, fmt.Sprintf("port_netns: requested %s, existing %s", requested.PortNetNS, existingMeta.PortNetnsName()))
	}

	// Transit/Geneve fields (transit_dev from metadata, wire contract from config)
	existingTransitDev := existingMeta.TransitDevName()
	if requested.TransitDev != existingTransitDev {
		mismatches = append(mismatches, fmt.Sprintf("transit_dev: requested %s, existing %s", requested.TransitDev, existingTransitDev))
	}

	existingLocator := geneveLocatorFromConfig(existing)
	if requested.GeneveLocator != existingLocator {
		mismatches = append(mismatches, fmt.Sprintf("geneve_locator: requested %s, existing %s", requested.GeneveLocator, existingLocator))
	} else {
		switch requested.GeneveLocator {
		case GeneveLocatorPort:
			if uint32(requested.GenevePortBase) != existing.GenevePortBase {
				mismatches = append(mismatches, fmt.Sprintf("geneve_port_base: requested %d, existing %d", requested.GenevePortBase, existing.GenevePortBase))
			}
		case GeneveLocatorTLV:
			existingTLV := geneveTLVLocatorFromConfig(existing)
			if requested.GeneveTLVLocator == nil || *requested.GeneveTLVLocator != existingTLV {
				requestedTLV := "<missing>"
				if requested.GeneveTLVLocator != nil {
					requestedTLV = requested.GeneveTLVLocator.String()
				}
				mismatches = append(mismatches, fmt.Sprintf("geneve_tlv_locator: requested %s, existing %s", requestedTLV, existingTLV.String()))
			}
		}
	}

	if len(mismatches) > 0 {
		return fmt.Errorf("switch %s already exists with different config (%s): %w",
			requested.Name, strings.Join(mismatches, "; "), ErrConfigMismatch)
	}
	return nil
}

// StopOptions controls how Stop behaves.
type StopOptions struct {
	Force bool // true: two-round forced stop (free/reserved first, then used); false: safe mode
}

// portIfaceToDel holds a port slot's ID and ifindex for device deletion.
type portIfaceToDel struct {
	slotID  uint32
	ifindex uint32
}

// countAllocatedSlots returns count of slots that are Allocated (not Free, not Reserved).
// This is a standalone function used by reserveFreeSlots which operates on a subset of slots.
const (
	cleanupMaxRetries = 3
	cleanupRetryDelay = 100 * time.Millisecond
)

// cleanupState tracks created resources for rollback on error
type cleanupState struct {
	pinDirCreated   bool // Whether pin directory was created by mkdir
	bpfLoaded       bool
	mapsPinned      bool
	dummyDevCreated bool         // Whether dummy block anchor device was created
	mgmtIfindexes   []int        // Ifindexes of created mgmt veths (in switch ns)
	transitMoved    bool         // Whether transit device was moved
	transitDevName  string       // Transit device name (for restoration)
	callerNs        *netns.NetNS // Caller namespace (for transit restoration)
}

// retryCleanup executes a cleanup operation with retries
func retryCleanup(fn func() error) error {
	var lastErr error
	for i := 0; i < cleanupMaxRetries; i++ {
		if err := fn(); err == nil {
			return nil
		} else {
			lastErr = err
			if i < cleanupMaxRetries-1 {
				time.Sleep(cleanupRetryDelay)
			}
		}
	}
	return lastErr
}

// cleanup performs rollback of all created resources in reverse order
func (cs *cleanupState) cleanup(cfg *Config, switchNs *netns.NetNS, objects *bpf.Objects) {
	var cleanupErrors []string

	// 1. Restore transit device (if moved)
	if cs.transitMoved && cs.callerNs != nil && cs.transitDevName != "" {
		err := retryCleanup(func() error {
			return netnsMoveDevice(cs.transitDevName, switchNs, cs.callerNs)
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "[cleanup] failed to move transit device %s back: %v\n", cs.transitDevName, err)
			cleanupErrors = append(cleanupErrors, fmt.Sprintf("transit device: %v", err))
		}
		cs.callerNs.Close()
	}

	// 2. Delete dummy block anchor device
	if cs.dummyDevCreated {
		dummyName := cfg.DummyDeviceName()
		err := retryCleanup(func() error {
			return netlinkDeleteVethPairInNs(switchNs, dummyName)
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "[cleanup] failed to delete dummy device %s: %v\n", dummyName, err)
			cleanupErrors = append(cleanupErrors, fmt.Sprintf("dummy device %s: %v", dummyName, err))
		}
	}

	// 3. Delete mgmt veth pairs by ifindex
	for _, ifindex := range cs.mgmtIfindexes {
		err := retryCleanup(func() error {
			return netlinkDelLinkByIndexInNs(switchNs, ifindex)
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "[cleanup] failed to delete mgmt veth ifindex %d: %v\n", ifindex, err)
			cleanupErrors = append(cleanupErrors, fmt.Sprintf("mgmt veth ifindex %d: %v", ifindex, err))
		}
	}

	// 4. Close BPF objects (no retry needed, memory operation)
	if cs.bpfLoaded && objects != nil {
		objects.Close()
	}

	// 5. Unpin BPF maps / remove pin directory
	if cs.mapsPinned || cs.pinDirCreated {
		if err := bpfUnpinMaps(cfg.Name); err != nil {
			fmt.Fprintf(os.Stderr, "[cleanup] failed to unpin BPF maps: %v\n", err)
			cleanupErrors = append(cleanupErrors, fmt.Sprintf("BPF maps: %v", err))
		}
	}

	// Report cleanup errors
	if len(cleanupErrors) > 0 {
		fmt.Fprintf(os.Stderr, "[cleanup] %d cleanup error(s) occurred during rollback\n", len(cleanupErrors))
	}
}

// StartOutput represents the JSON output of the start command.
type StartOutput struct {
	Switch           string            `json:"switch"`
	SwitchNetNS      string            `json:"switch_netns"`
	SwitchMaps       map[string]string `json:"switch_maps"`
	PortNetNS        string            `json:"port_netns"`
	Ports            uint32            `json:"ports"`
	PortsUsed        uint32            `json:"ports_used"`
	PortsAvailable   uint32            `json:"ports_available"`
	PortsReserved    uint32            `json:"ports_reserved"`
	FloatingIPBase   string            `json:"floating_ip_base"`
	MgmtPlanes       []MgmtPlaneInfo   `json:"mgmt_planes,omitempty"`
	MgmtServices     []MgmtServiceInfo `json:"mgmt_services,omitempty"`
	TransitType      string            `json:"transit_type"`
	TransitDev       string            `json:"transit_dev,omitempty"`
	TransitDevIP     string            `json:"transit_dev_ip,omitempty"`
	GeneveLocator    string            `json:"geneve_locator,omitempty"`
	GenevePort       uint16            `json:"geneve_port,omitempty"`
	GenevePortBase   uint16            `json:"geneve_port_base,omitempty"`
	GeneveTLVLocator string            `json:"geneve_tlv_locator,omitempty"`
}
