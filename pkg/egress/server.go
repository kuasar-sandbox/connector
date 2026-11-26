package egress

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func runtimeEnv(libraries string) []string {
	env := os.Environ()
	if libraries != "" {
		env = append(env, "LD_LIBRARY_PATH="+libraries)
	}
	return append(env, "TERM=dumb", "CONNECTOR_EGRESS_PRIVATE_MEMORY=1")
}

func privateDirectory(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 || !ok || st.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("%s must be a private directory owned by the current user", path)
	}
	return nil
}

func startup(c Config) string {
	var b strings.Builder
	fmt.Fprintf(&b, "unix { nodaemon interactive runtime-dir %s }\n", c.RuntimeDir)
	fmt.Fprintf(&b, "api-segment { prefix connector-egress-%d }\n", os.Getpid())
	fmt.Fprintf(&b, "statseg { socket-name none size %s page-size 4k }\n", c.StatsSize)
	fmt.Fprintf(&b, "memory { main-heap-size %s main-heap-page-size 4k }\nbuffers { buffers-per-numa 16384 page-size 4k }\n", c.HeapSize)
	if c.MainCore != nil || len(c.Workers) > 0 {
		b.WriteString("cpu { ")
		if c.MainCore != nil {
			fmt.Fprintf(&b, "main-core %d ", *c.MainCore)
		}
		if len(c.Workers) > 0 {
			parts := []string{}
			for _, cpu := range c.Workers {
				parts = append(parts, strconv.FormatUint(uint64(cpu), 10))
			}
			b.WriteString("corelist-workers " + strings.Join(parts, ","))
		}
		b.WriteString(" }\n")
	}
	fmt.Fprintf(&b, "plugins { path %s\nplugin default { disable }\n", c.PluginPath)
	for _, p := range []string{"nat", "af_packet", "ping", "egress_policy", "egress_geneve", "egress_packet"} {
		fmt.Fprintf(&b, "plugin %s_plugin.so { enable }\n", p)
	}
	b.WriteString("}\n")
	return b.String()
}
func checkInterfaces(c Config, requireUp bool) error {
	for _, i := range c.Interfaces {
		link, err := netlink.LinkByName(i.Name)
		if err != nil {
			return err
		}
		if link.Attrs().MTU != int(i.MTU) {
			return fmt.Errorf("Linux interface %s MTU is %d, expected %d", i.Name, link.Attrs().MTU, i.MTU)
		}
		if requireUp && link.Attrs().Flags&net.FlagUp == 0 {
			return fmt.Errorf("Linux interface %s is down", i.Name)
		}
		addresses, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			return err
		}
		owned := map[string]bool{netip.MustParsePrefix(i.Address).Addr().String(): true}
		for _, area := range c.Areas {
			for _, pool := range area.Pools {
				if pool.Interface == i.Name {
					for _, a := range pool.Addresses {
						owned[a] = true
					}
				}
			}
		}
		for _, a := range addresses {
			if owned[a.IP.String()] {
				return fmt.Errorf("Linux interface %s duplicates Egress address %s", i.Name, a.IP)
			}
		}
	}
	return nil
}

type interfaceIdentity struct {
	index     int
	kind, mac string
}

func interfaceIdentities(c Config) (map[string]interfaceIdentity, error) {
	result := map[string]interfaceIdentity{}
	for _, i := range c.Interfaces {
		link, err := netlink.LinkByName(i.Name)
		if err != nil {
			return nil, err
		}
		a := link.Attrs()
		// A veth peer can receive a different index when vSwitch moves it into
		// its namespace. Only this dataplane endpoint's identity is immutable.
		result[i.Name] = interfaceIdentity{a.Index, link.Type(), a.HardwareAddr.String()}
	}
	return result, nil
}

// Serve owns a file-configured native process. SIGHUP reloads the source
// files; diagnostics are output files, never an alternate configuration source.
func Serve(ctx context.Context, path string, log io.Writer) error {
	reloads := make(chan os.Signal, 1)
	signal.Notify(reloads, syscall.SIGHUP)
	defer signal.Stop(reloads)
	c, err := LoadConfig(path)
	if err != nil {
		return err
	}
	if err = checkInterfaces(*c, true); err != nil {
		return err
	}
	identities, err := interfaceIdentities(*c)
	if err != nil {
		return err
	}
	if err = privateDirectory(c.RuntimeDir); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(c.RuntimeDir, "owner.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fmt.Errorf("gateway already running: %w", err)
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	conf := filepath.Join(c.RuntimeDir, "startup.conf")
	if err = writeOutput(conf, []byte(startup(*c))); err != nil {
		return err
	}
	process := exec.Command(c.VPP, "-c", conf)
	process.Env = runtimeEnv(c.LibraryPath)
	process.Stderr = log
	process.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	// VPP's stdin CLI reads and writes the same descriptor. An unnamed
	// socket pair supplies that duplex stream without bind/listen or a path.
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	parent := os.NewFile(uintptr(fds[0]), "native-parent")
	child := os.NewFile(uintptr(fds[1]), "native-child")
	conn, err := net.FileConn(parent)
	_ = parent.Close()
	if err != nil {
		child.Close()
		return err
	}
	defer conn.Close()
	process.Stdin = child
	process.Stdout = log
	err = process.Start()
	_ = child.Close()
	if err != nil {
		return err
	}
	finished := make(chan error, 1)
	go func() { finished <- process.Wait() }()
	stopped := false
	defer func() {
		_ = conn.Close()
		if !stopped {
			_ = process.Process.Signal(syscall.SIGTERM)
			select {
			case <-finished:
			case <-time.After(3 * time.Second):
				_ = process.Process.Kill()
				<-finished
			}
		}
	}()
	runner := newPipeRunner(conn)
	if _, err = runner.Run(ctx, "show version"); err != nil {
		return fmt.Errorf("native startup: %w", err)
	}
	engine, err := NewEngine(*c, runner)
	if err != nil {
		return err
	}
	engine.interfaceMACs = make(map[string]string, len(identities))
	for name, identity := range identities {
		mac, parseErr := net.ParseMAC(identity.mac)
		if parseErr != nil || len(mac) != 6 {
			return fmt.Errorf("interface %s requires an Ethernet MAC address", name)
		}
		engine.interfaceMACs[name] = mac.String()
	}
	if err = engine.Setup(ctx); err != nil {
		return fmt.Errorf("configure Egress: %w", err)
	}
	_ = writeOutput(filepath.Join(c.RuntimeDir, "pid"), []byte(strconv.Itoa(os.Getpid())+"\n"))
	generation := uint64(1)
	lastError := ""
	failedInterfaces := map[string]bool{}
	publish := func() {
		snapshot, e := engine.Snapshot(ctx)
		if e != nil {
			fmt.Fprintf(log, "Egress diagnostics: %v\n", e)
			return
		}
		snapshot["pid"] = os.Getpid()
		snapshot["native_pid"] = process.Process.Pid
		snapshot["configuration_generation"] = generation
		snapshot["reload_error"] = lastError
		snapshot["interfaces"] = InterfaceStatus(*c)
		snapshot["disabled_interfaces"] = failedInterfaces
		raw, e := json.Marshal(snapshot)
		if e == nil {
			e = writeOutput(filepath.Join(c.RuntimeDir, "status.json"), append(raw, '\n'))
		}
		if e != nil {
			fmt.Fprintf(log, "Egress diagnostic output: %v\n", e)
		}
	}
	publish()
	fmt.Fprintln(log, "Egress configured from files; traffic creates forwarding state automatically")
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err = <-finished:
			stopped = true
			return fmt.Errorf("native dataplane stopped: %v", err)
		case <-reloads:
			next, e := LoadConfig(path)
			if e == nil {
				e = checkInterfaces(*next, false)
			}
			if e == nil {
				e = engine.Reload(ctx, *next)
			}
			if e != nil {
				lastError = e.Error()
				fmt.Fprintf(log, "Egress reload rejected; current configuration retained: %v\n", e)
			} else {
				c = next
				generation++
				lastError = ""
				fmt.Fprintf(log, "Egress configuration reloaded: %d\n", generation)
			}
			if e = engine.Failure(); e != nil {
				return e
			}
			publish()
		case <-tick.C:
			if err = engine.Failure(); err != nil {
				return err
			}
			for _, iface := range c.Interfaces {
				single := *c
				single.Interfaces = []Interface{iface}
				current, e := interfaceIdentities(single)
				if e == nil && current[iface.Name] != identities[iface.Name] {
					e = errors.New("device identity changed")
				}
				if e == nil {
					e = checkInterfaces(single, false)
				}
				if e != nil && !failedInterfaces[iface.Name] {
					failedInterfaces[iface.Name] = true
					if down := engine.empty(ctx, "set interface state host-"+iface.Name+" down"); down != nil {
						return down
					}
					fmt.Fprintf(log, "Egress interface %s disabled pending controlled repair: %v\n", iface.Name, e)
				}
			}
			publish()
		}
	}
}

func writeOutput(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".egress-output-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// InterfaceStatus deliberately distinguishes administrative state from evidence
// of bidirectional Geneve delivery; a carrier alone is never readiness proof.
func InterfaceStatus(c Config) []map[string]any {
	result := []map[string]any{}
	for _, i := range c.Interfaces {
		state := map[string]any{"interface": i.Name, "dataplane_address": netip.MustParsePrefix(i.Address).Addr().String()}
		link, err := netlink.LinkByName(i.Name)
		if err != nil {
			state["error"] = err.Error()
		} else {
			state["up"] = link.Attrs().Flags&net.FlagUp != 0
			state["carrier"] = link.Attrs().RawFlags&unix.IFF_LOWER_UP != 0
			state["ifindex"] = link.Attrs().Index
			state["mtu"] = link.Attrs().MTU
		}
		result = append(result, state)
	}
	return result
}
