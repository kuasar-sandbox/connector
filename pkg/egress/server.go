package egress

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
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
	return append(env, "TERM=dumb")
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
	fmt.Fprintf(&b, "unix { nodaemon cli-listen %s/vpp.sock runtime-dir %s }\n", c.RuntimeDir, c.RuntimeDir)
	fmt.Fprintf(&b, "socksvr { socket-name %s/api.sock }\nstatseg { socket-name %s/stats.sock size 64M page-size 4k }\n", c.RuntimeDir, c.RuntimeDir)
	b.WriteString("memory { main-heap-size 2G main-heap-page-size 4k }\nbuffers { buffers-per-numa 16384 page-size 4k }\n")
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
		if len(addresses) > 0 {
			return fmt.Errorf("Linux interface %s must not own IPv4 addresses; VPP owns L3", i.Name)
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

// Serve runs in the dataplane network namespace. The Unix control socket is
// private to the deployment owner. A dataplane crash terminates this supervisor;
// the service manager can restart it with the same Linux endpoints.
func Serve(ctx context.Context, c Config, log io.Writer) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if err := checkInterfaces(c, true); err != nil {
		return err
	}
	identities, err := interfaceIdentities(c)
	if err != nil {
		return err
	}
	if err := privateDirectory(c.RuntimeDir); err != nil {
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
	for _, iface := range c.Interfaces {
		if err = disableOffloads(iface.Name); err != nil {
			return err
		}
	}
	identity, err := policyIdentity(c)
	if err != nil {
		return err
	}
	if err = restorePolicy(&c, identity); err != nil {
		return fmt.Errorf("restore committed policy: %w", err)
	}
	for _, name := range []string{"control.sock", "vpp.sock", "api.sock", "stats.sock"} {
		path := filepath.Join(c.RuntimeDir, name)
		if st, e := os.Lstat(path); e == nil {
			if st.Mode()&os.ModeSocket == 0 {
				return fmt.Errorf("refusing to replace non-socket %s", path)
			}
			if e = os.Remove(path); e != nil {
				return e
			}
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
	}
	conf := filepath.Join(c.RuntimeDir, "startup.conf")
	f, err := os.OpenFile(conf, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	_, err = f.WriteString(startup(c))
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	process := exec.Command(c.VPP, "-c", conf)
	process.Env = runtimeEnv(c.LibraryPath)
	process.Stdout = log
	process.Stderr = log
	process.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err = process.Start(); err != nil {
		return err
	}
	finished := make(chan error, 1)
	go func() { finished <- process.Wait() }()
	stopped := false
	defer func() {
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
	runner := VPPRunner{Binary: c.VPPCTL, Socket: filepath.Join(c.RuntimeDir, "vpp.sock"), LibraryPath: c.LibraryPath}
	deadline := time.NewTimer(20 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	ready := false
	for !ready {
		select {
		case err = <-finished:
			stopped = true
			return fmt.Errorf("VPP exited before configuration: %w", err)
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("VPP CLI startup timeout")
		case <-ticker.C:
			if _, err = os.Stat(runner.Socket); err == nil {
				ready = true
			}
		}
	}
	engine, err := NewEngine(c, runner)
	if err != nil {
		return err
	}
	if err = engine.Setup(ctx); err != nil {
		return fmt.Errorf("configure Egress: %w", err)
	}
	engine.persist = func(areas []Area) error { return persistPolicy(c.RuntimeDir, identity, areas) }
	socket := filepath.Join(c.RuntimeDir, "control.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	defer listener.Close()
	if err = os.Chmod(socket, 0600); err != nil {
		return err
	}
	server := &http.Server{Handler: engine.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second}
	serverErrors := make(chan error, 1)
	go func() { serverErrors <- server.Serve(listener) }()
	defer server.Close()
	fmt.Fprintln(log, "Egress configured; sandbox leases and bidirectional traffic verification are required before use")
	health := time.NewTicker(time.Second)
	defer health.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err = <-finished:
			stopped = true
			return fmt.Errorf("VPP stopped: %w", err)
		case err = <-serverErrors:
			return err
		case <-health.C:
			if err = engine.Failure(); err != nil {
				return err
			}
			current, err := interfaceIdentities(c)
			if err != nil {
				return fmt.Errorf("dataplane interface lost: %w", err)
			}
			for name, identity := range identities {
				if current[name] != identity {
					return fmt.Errorf("dataplane interface %s replaced; controlled recovery required", name)
				}
			}
			if err = checkInterfaces(c, false); err != nil {
				return fmt.Errorf("dataplane interface changed: %w", err)
			}
		}
	}
}
func (e *Engine) Handler() http.Handler {
	mux := http.NewServeMux()
	reply := func(w http.ResponseWriter, value any, err error) {
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(value)
	}
	decode := func(w http.ResponseWriter, r *http.Request, v any) error {
		return Decode(http.MaxBytesReader(w, r.Body, 4<<20), v)
	}
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) { s, err := e.Snapshot(r.Context()); reply(w, s, err) })
	mux.HandleFunc("POST /v1/sessions", func(w http.ResponseWriter, r *http.Request) {
		var s SessionRequest
		if err := decode(w, r, &s); err != nil {
			reply(w, nil, err)
			return
		}
		result, err := e.Open(r.Context(), s)
		reply(w, result, err)
	})
	mux.HandleFunc("POST /v1/sessions/{id}/renew", func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			Token string `json:"token"`
			Lease uint32 `json:"lease_seconds"`
		}
		if err := decode(w, r, &q); err != nil {
			reply(w, nil, err)
			return
		}
		s, err := e.Renew(r.Context(), r.PathValue("id"), q.Token, q.Lease)
		reply(w, s, err)
	})
	mux.HandleFunc("DELETE /v1/sessions/{id}", func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			Token string `json:"token"`
		}
		if err := decode(w, r, &q); err != nil {
			reply(w, nil, err)
			return
		}
		err := e.Close(r.Context(), r.PathValue("id"), q.Token)
		reply(w, map[string]bool{"released": err == nil}, err)
	})
	mux.HandleFunc("PUT /v1/areas/{id}", func(w http.ResponseWriter, r *http.Request) {
		var a Area
		if err := decode(w, r, &a); err != nil {
			reply(w, nil, err)
			return
		}
		id, err := strconv.ParseUint(r.PathValue("id"), 10, 24)
		if err != nil || uint32(id) != a.VNI {
			reply(w, nil, errors.New("Area path/body mismatch"))
			return
		}
		err = e.ApplyArea(r.Context(), a)
		reply(w, map[string]bool{"applied": err == nil}, err)
	})
	return mux
}

// Request uses the same management API for local and remote gateway deployments.
// Remote controllers can execute the CLI over their existing authenticated transport.
func Request(ctx context.Context, socket, method, path string, body io.Reader) ([]byte, error) {
	if !strings.HasPrefix(path, "/v1/") {
		return nil, errors.New("invalid API path")
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 25 * time.Second}
	req, err := http.NewRequestWithContext(ctx, method, "http://egress"+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	b, err := io.ReadAll(io.LimitReader(response.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Egress API %s: %s", response.Status, b)
	}
	return b, nil
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
