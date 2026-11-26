package egress

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/kuasar-sandbox/connector/pkg/vswitch"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

type LinkConfig struct {
	Name              string `json:"name"`
	OwnerNS           string `json:"owner_netns"`
	GatewayNS         string `json:"gateway_netns"`
	SwitchNS          string `json:"switch_netns"`
	Switch            string `json:"switch"`
	Transit           string `json:"transit"`
	Gateway           string `json:"gateway"`
	MTU               int    `json:"mtu"`
	StateDir          string `json:"state_dir"`
	GatewayRuntimeDir string `json:"gateway_runtime_dir"`
}
type namespaceRecord struct {
	Created bool   `json:"created"`
	Dev     uint64 `json:"dev"`
	Inode   uint64 `json:"inode"`
}
type linkState struct {
	Config         LinkConfig `json:"config"`
	Owner, Gateway namespaceRecord
	Installed      bool `json:"installed"`
}
type LinkStatus struct {
	Owned            bool                `json:"owned"`
	SwitchEndpoint   string              `json:"switch_endpoint"`
	GatewayEndpoint  bool                `json:"gateway_endpoint"`
	PairValid        bool                `json:"pair_valid"`
	SwitchRunning    bool                `json:"switch_running"`
	ActivePorts      uint32              `json:"active_ports"`
	RecoveryRequired bool                `json:"recovery_required"`
	SwitchConditions []vswitch.Condition `json:"switch_conditions,omitempty"`
}

func (c *LinkConfig) Validate() error {
	for _, v := range []string{c.Name, c.GatewayNS, c.SwitchNS, c.Switch, c.Transit, c.Gateway} {
		if !identifier.MatchString(v) {
			return fmt.Errorf("invalid local link identifier %q", v)
		}
	}
	if c.OwnerNS != "" && !identifier.MatchString(c.OwnerNS) {
		return errors.New("invalid owner namespace")
	}
	if c.OwnerNS == c.GatewayNS || c.OwnerNS == c.SwitchNS || c.GatewayNS == c.SwitchNS || c.Transit == c.Gateway {
		return errors.New("local attachment requires distinct namespaces and endpoints")
	}
	if len(c.Transit) > 15 || len(c.Gateway) > 15 || c.MTU < 128 || c.MTU > 65535 {
		return errors.New("invalid local link device name or MTU")
	}
	if c.StateDir == "" {
		c.StateDir = filepath.Join("/run/connector-egress-links", c.Name)
	}
	for _, p := range []string{c.StateDir, c.GatewayRuntimeDir} {
		if !filepath.IsAbs(p) || filepath.Clean(p) == "/" {
			return errors.New("link state and gateway runtime require absolute private directories")
		}
	}
	return nil
}
func LoadLink(path string) (LinkConfig, error) {
	var c LinkConfig
	f, e := os.Open(path)
	if e != nil {
		return c, e
	}
	defer f.Close()
	if e = Decode(f, &c); e != nil {
		return c, e
	}
	return c, c.Validate()
}
func linkLock(c LinkConfig) (*os.File, error) {
	if err := privateDirectory(c.StateDir); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(c.StateDir, "lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
func readLinkState(c LinkConfig) (*linkState, error) {
	f, err := os.Open(filepath.Join(c.StateDir, "state.json"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var s linkState
	if err = Decode(f, &s); err != nil {
		return nil, err
	}
	if s.Config != c {
		return nil, errors.New("existing link state belongs to a different configuration")
	}
	return &s, nil
}
func writeLinkState(s *linkState) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(s.Config.StateDir, ".state-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, filepath.Join(s.Config.StateDir, "state.json")); err != nil {
		return err
	}
	dir, err := os.Open(s.Config.StateDir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func namespaceIdentity(ns netns.NsHandle) (namespaceRecord, error) {
	kind, err := unix.IoctlRetInt(int(ns), unix.NS_GET_NSTYPE)
	if err != nil {
		return namespaceRecord{}, err
	}
	if kind != unix.CLONE_NEWNET {
		return namespaceRecord{}, errors.New("expected a network namespace")
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(ns), &st); err != nil {
		return namespaceRecord{}, err
	}
	return namespaceRecord{Dev: uint64(st.Dev), Inode: st.Ino}, nil
}

// An empty owner uses the deployment manager's current, retained namespace.
// Its inode is recorded and verified just like a named owner on every operation.
func linkNamespace(name string) (netns.NsHandle, error) {
	if name == "" {
		return netns.Get()
	}
	return netns.GetFromName(name)
}
func ensureNamespace(name string, record *namespaceRecord) error {
	ns, err := linkNamespace(name)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if errors.Is(err, os.ErrNotExist) {
		if record.Inode != 0 {
			return fmt.Errorf("managed namespace %s disappeared; explicit repair required", name)
		}
		// iproute2 establishes the shared /run/netns mount before binding the
		// first named namespace. Mixing raw bind mounts with later `ip netns
		// add` would otherwise leave hidden duplicate mounts on a fresh host.
		output, createErr := exec.Command("ip", "netns", "add", name).CombinedOutput()
		if createErr != nil {
			return fmt.Errorf("create network namespace %s: %w: %s", name, createErr, output)
		}
		ns, err = linkNamespace(name)
		if err != nil {
			return err
		}
		record.Created = true
	}
	defer ns.Close()
	actual, err := namespaceIdentity(ns)
	if err != nil {
		return err
	}
	if record.Inode != 0 && (record.Inode != actual.Inode || record.Dev != actual.Dev) {
		return fmt.Errorf("namespace %s was replaced", name)
	}
	record.Dev = actual.Dev
	record.Inode = actual.Inode
	return nil
}
func verifyNamespace(name string, record namespaceRecord) error {
	ns, err := linkNamespace(name)
	if err != nil {
		return err
	}
	defer ns.Close()
	actual, err := namespaceIdentity(ns)
	if err != nil {
		return err
	}
	if actual.Inode != record.Inode || actual.Dev != record.Dev {
		return fmt.Errorf("namespace %s ownership changed", name)
	}
	return nil
}
func inNamespace(name string, f func() error) error {
	ns, err := linkNamespace(name)
	if err != nil {
		return err
	}
	defer ns.Close()
	return namespaceThread(func() error {
		if err := netns.Set(ns); err != nil {
			return err
		}
		return f()
	})
}

// A restoration failure must never return a thread in the wrong namespace to
// Go's scheduler. A goroutine exiting while locked destroys its OS thread.
func namespaceThread(f func() error) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		original, err := netns.Get()
		if err != nil {
			runtime.UnlockOSThread()
			done <- err
			return
		}
		defer original.Close()
		err = f()
		if restore := netns.Set(original); restore != nil {
			done <- fmt.Errorf("restore network namespace: %w (operation: %v)", restore, err)
			return
		}
		runtime.UnlockOSThread()
		done <- err
	}()
	return <-done
}
func findLink(namespace, name string) (netlink.Link, error) {
	var link netlink.Link
	err := inNamespace(namespace, func() error { var err error; link, err = netlink.LinkByName(name); return err })
	var notfound netlink.LinkNotFoundError
	if errors.As(err, &notfound) || errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return link, err
}
func alias(c LinkConfig, end string) string {
	identity := sha256.Sum256([]byte(filepath.Clean(c.StateDir)))
	return fmt.Sprintf("connector-egress:%s:%x:%s", c.Name, identity[:8], end)
}
func ownedLink(c LinkConfig, namespace, name, end string) (netlink.Link, error) {
	link, err := findLink(namespace, name)
	if err != nil || link == nil {
		return link, err
	}
	if link.Type() != "veth" || link.Attrs().Alias != alias(c, end) {
		return nil, fmt.Errorf("refusing foreign device %s/%s", namespace, name)
	}
	return link, nil
}
func inspectLink(s *linkState) (LinkStatus, error) {
	c := s.Config
	status := LinkStatus{Owned: true}
	if err := verifyNamespace(c.OwnerNS, s.Owner); err != nil {
		return status, err
	}
	if err := verifyNamespace(c.GatewayNS, s.Gateway); err != nil {
		return status, err
	}
	left, err := ownedLink(c, c.OwnerNS, c.Transit, "switch")
	if err != nil {
		return status, err
	}
	moved, err := ownedLink(c, c.SwitchNS, c.Transit, "switch")
	if err != nil {
		return status, err
	}
	if left != nil && moved != nil {
		return status, errors.New("duplicate switch endpoints")
	}
	if left != nil {
		status.SwitchEndpoint = c.OwnerNS
		if c.OwnerNS == "" {
			status.SwitchEndpoint = "current-owner"
		}
	} else if moved != nil {
		left = moved
		status.SwitchEndpoint = c.SwitchNS
	}
	right, err := ownedLink(c, c.GatewayNS, c.Gateway, "gateway")
	if err != nil {
		return status, err
	}
	status.GatewayEndpoint = right != nil
	if left != nil && right != nil {
		// vSwitch may lower its endpoint through its existing MTU auto mode.
		// The gateway endpoint keeps the provisioned ceiling.
		status.PairValid = left.Attrs().ParentIndex == right.Attrs().Index && right.Attrs().ParentIndex == left.Attrs().Index && left.Attrs().MTU >= 128 && left.Attrs().MTU <= c.MTU && right.Attrs().MTU == c.MTU
	}
	sw, err := vswitch.Status(c.Switch)
	if err == nil {
		status.SwitchRunning = true
		status.ActivePorts = sw.PortsUsed
		status.SwitchConditions = sw.Conditions
		if sw.SwitchNetNS != c.SwitchNS || sw.TransitDev != c.Transit {
			return status, errors.New("vSwitch configuration does not own this transit attachment")
		}
	} else if !vswitch.IsNotExist(err) {
		return status, err
	}
	status.RecoveryRequired = !status.PairValid || (status.SwitchRunning && status.SwitchEndpoint != c.SwitchNS)
	return status, nil
}
func PrepareLink(c LinkConfig) (LinkStatus, error) {
	if err := c.Validate(); err != nil {
		return LinkStatus{}, err
	}
	lock, err := linkLock(c)
	if err != nil {
		return LinkStatus{}, err
	}
	defer lock.Close()
	return prepareLink(c)
}
func prepareLink(c LinkConfig) (result LinkStatus, retErr error) {
	s, err := readLinkState(c)
	fresh := errors.Is(err, os.ErrNotExist)
	if errors.Is(err, os.ErrNotExist) {
		s = &linkState{Config: c}
	} else if err != nil {
		return LinkStatus{}, err
	}
	// Failed first deployment owns no running switch. Reclaim only namespaces
	// created by this attempt; a cleanup failure leaves its durable ownership
	// record available for a safe uninstall retry.
	defer func() {
		if !fresh || retErr == nil || s.Installed {
			return
		}
		var cleanup error
		for _, entry := range []struct {
			name   string
			record namespaceRecord
		}{{c.GatewayNS, s.Gateway}, {c.OwnerNS, s.Owner}} {
			if entry.record.Created {
				cleanup = errors.Join(cleanup, removeOwnedNamespace(entry.name, entry.record))
			}
		}
		if cleanup == nil {
			if e := os.Remove(filepath.Join(c.StateDir, "state.json")); e != nil && !errors.Is(e, os.ErrNotExist) {
				cleanup = e
			}
		}
		retErr = errors.Join(retErr, cleanup)
	}()
	if err = ensureNamespace(c.OwnerNS, &s.Owner); err != nil {
		return LinkStatus{}, err
	}
	if err = writeLinkState(s); err != nil {
		return LinkStatus{}, err
	}
	if err = ensureNamespace(c.GatewayNS, &s.Gateway); err != nil {
		return LinkStatus{}, err
	}
	if err = writeLinkState(s); err != nil {
		return LinkStatus{}, err
	}
	status, err := inspectLink(s)
	if err != nil {
		return status, err
	}
	if status.PairValid {
		return status, nil
	}
	if s.Installed || status.SwitchRunning || status.SwitchEndpoint != "" || status.GatewayEndpoint {
		return status, errors.New("attachment damaged or partially installed; stop Egress and drain vSwitch before explicit repair")
	}
	eg, err := netns.GetFromName(c.GatewayNS)
	if err != nil {
		return status, err
	}
	defer eg.Close()
	err = inNamespace(c.OwnerNS, func() (err error) {
		link := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: c.Transit, MTU: c.MTU, Alias: alias(c, "switch")}, PeerName: c.Gateway, PeerNamespace: netlink.NsFd(eg)}
		if err = netlink.LinkAdd(link); err != nil {
			return err
		}
		defer func() {
			if err != nil {
				_ = netlink.LinkDel(link)
			}
		}()
		if err = netlink.LinkSetAlias(link, alias(c, "switch")); err != nil {
			return err
		}
		if err = disableOffloads(c.Transit); err != nil {
			return err
		}
		err = inNamespace(c.GatewayNS, func() error {
			peer, e := netlink.LinkByName(c.Gateway)
			if e != nil {
				return e
			}
			if e = netlink.LinkSetAlias(peer, alias(c, "gateway")); e != nil {
				return e
			}
			if e = netlink.LinkSetMTU(peer, c.MTU); e != nil {
				return e
			}
			if e = disableOffloads(c.Gateway); e != nil {
				return e
			}
			return netlink.LinkSetUp(peer)
		})
		return err
	})
	if err != nil {
		return status, err
	}
	s.Installed = true
	if err = writeLinkState(s); err != nil {
		return status, err
	}
	return inspectLink(s)
}
func CheckLink(c LinkConfig) (LinkStatus, error) {
	if err := c.Validate(); err != nil {
		return LinkStatus{}, err
	}
	lock, err := linkLock(c)
	if err != nil {
		return LinkStatus{}, err
	}
	defer lock.Close()
	s, err := readLinkState(c)
	if err != nil {
		return LinkStatus{}, err
	}
	return inspectLink(s)
}
func checkSwitchConfig(c LinkConfig, sw *vswitch.Config) error {
	if sw.Name != c.Switch || sw.SwitchNetNS != c.SwitchNS || sw.TransitDev != c.Transit {
		return errors.New("switch config does not match managed link")
	}
	return nil
}
func StartLocalSwitch(c LinkConfig, sw *vswitch.Config) (*vswitch.StartOutput, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if err := checkSwitchConfig(c, sw); err != nil {
		return nil, err
	}
	lock, err := linkLock(c)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	state, err := prepareLink(c)
	if err != nil {
		return nil, err
	}
	if state.SwitchRunning {
		return nil, errors.New("switch already running; use link check")
	}
	var result *vswitch.StartOutput
	err = inNamespace(c.OwnerNS, func() error { var e error; result, e = vswitch.Start(sw); return e })
	return result, err
}
func StopLocalSwitch(c LinkConfig) error {
	if err := c.Validate(); err != nil {
		return err
	}
	lock, err := linkLock(c)
	if err != nil {
		return err
	}
	defer lock.Close()
	s, err := readLinkState(c)
	if err != nil {
		return err
	}
	if err = verifyNamespace(c.OwnerNS, s.Owner); err != nil {
		return err
	}
	if current, e := vswitch.Status(c.Switch); e == nil {
		if current.SwitchNetNS != c.SwitchNS || current.TransitDev != c.Transit {
			return errors.New("vSwitch does not belong to managed attachment")
		}
	} else if !vswitch.IsNotExist(e) {
		return e
	}
	return inNamespace(c.OwnerNS, func() error {
		err := vswitch.Stop(c.Switch, vswitch.StopOptions{})
		if vswitch.IsNotExist(err) {
			return nil
		}
		return err
	})
}
func stoppedGateway(c LinkConfig) (*os.File, error) {
	if err := privateDirectory(c.GatewayRuntimeDir); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(c.GatewayRuntimeDir, "owner.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("stop Egress before replacing or uninstalling its transit attachment")
	}
	return f, nil
}
func removePair(s *linkState) error {
	c := s.Config
	for _, where := range []struct{ ns, device, end string }{{c.OwnerNS, c.Transit, "switch"}, {c.SwitchNS, c.Transit, "switch"}, {c.GatewayNS, c.Gateway, "gateway"}} {
		link, err := ownedLink(c, where.ns, where.device, where.end)
		if err != nil {
			return err
		}
		if link != nil {
			return inNamespace(where.ns, func() error { return netlink.LinkDel(link) })
		}
	}
	return nil
}

// Repair requires Egress to be stopped and uses vSwitch's atomic normal Stop
// gate: it refuses allocated ports and reserves free ports before teardown.
func RepairLink(c LinkConfig, sw *vswitch.Config) (*vswitch.StartOutput, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if err := checkSwitchConfig(c, sw); err != nil {
		return nil, err
	}
	lock, err := linkLock(c)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	gateway, err := stoppedGateway(c)
	if err != nil {
		return nil, err
	}
	defer gateway.Close()
	s, err := readLinkState(c)
	if err != nil {
		return nil, err
	}
	// Reserve/drain before rebuilding a lost namespace or endpoint. Release is
	// independent of the caller namespace and atomically rejects active ports.
	for _, entry := range []struct {
		name   string
		record namespaceRecord
	}{{c.OwnerNS, s.Owner}, {c.GatewayNS, s.Gateway}} {
		if err = verifyNamespace(entry.name, entry.record); err != nil && (!errors.Is(err, os.ErrNotExist) || !entry.record.Created) {
			return nil, err
		}
	}
	if current, statusErr := vswitch.Status(c.Switch); statusErr == nil {
		if current.SwitchNetNS != c.SwitchNS || current.TransitDev != c.Transit {
			return nil, errors.New("vSwitch does not belong to managed attachment")
		}
	} else if !vswitch.IsNotExist(statusErr) {
		return nil, statusErr
	}
	if _, err = vswitch.ReleasePorts(c.Switch, vswitch.ReleaseOptions{}); err != nil && !vswitch.IsNotExist(err) {
		return nil, err
	}
	for _, entry := range []struct {
		name   string
		record *namespaceRecord
	}{{c.OwnerNS, &s.Owner}, {c.GatewayNS, &s.Gateway}} {
		if err = verifyNamespace(entry.name, *entry.record); err != nil {
			if !errors.Is(err, os.ErrNotExist) || !entry.record.Created {
				return nil, err
			}
			entry.record.Inode, entry.record.Dev = 0, 0
			if err = ensureNamespace(entry.name, entry.record); err != nil {
				return nil, err
			}
			if err = writeLinkState(s); err != nil {
				return nil, err
			}
		}
	}
	err = inNamespace(c.OwnerNS, func() error {
		err := vswitch.StopReleased(c.Switch)
		if vswitch.IsNotExist(err) {
			return nil
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	if err = removePair(s); err != nil {
		return nil, err
	}
	s.Installed = false
	if err = writeLinkState(s); err != nil {
		return nil, err
	}
	if _, err = prepareLink(c); err != nil {
		return nil, err
	}
	var result *vswitch.StartOutput
	err = inNamespace(c.OwnerNS, func() error { var e error; result, e = vswitch.Start(sw); return e })
	return result, err
}
func removeOwnedNamespace(name string, record namespaceRecord) error {
	if !record.Created {
		return nil
	}
	if err := verifyNamespace(name, record); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	pids, err := exec.Command("ip", "netns", "pids", name).Output()
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(pids)) > 0 {
		return fmt.Errorf("namespace %s still has processes", name)
	}
	err = inNamespace(name, func() error {
		links, e := netlink.LinkList()
		if e != nil {
			return e
		}
		for _, l := range links {
			if l.Attrs().Flags&net.FlagLoopback == 0 {
				return fmt.Errorf("namespace %s still contains device %s", name, l.Attrs().Name)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return netns.DeleteNamed(name)
}
func UninstallLink(c LinkConfig) error {
	if err := c.Validate(); err != nil {
		return err
	}
	lock, err := linkLock(c)
	if err != nil {
		return err
	}
	defer lock.Close()
	s, err := readLinkState(c)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	gateway, err := stoppedGateway(c)
	if err != nil {
		return err
	}
	defer gateway.Close()
	status, err := vswitch.Status(c.Switch)
	if err == nil {
		return fmt.Errorf("stop managed vSwitch before uninstall (active ports %d)", status.PortsUsed)
	}
	if !vswitch.IsNotExist(err) {
		return err
	}
	for _, entry := range []struct {
		name   string
		record namespaceRecord
	}{{c.OwnerNS, s.Owner}, {c.GatewayNS, s.Gateway}} {
		if err = verifyNamespace(entry.name, entry.record); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err = removePair(s); err != nil {
		return err
	}
	s.Installed = false
	if err = writeLinkState(s); err != nil {
		return err
	}
	// Borrowed namespaces and all Pool interfaces are always preserved.
	if err = removeOwnedNamespace(c.GatewayNS, s.Gateway); err != nil {
		return err
	}
	if err = removeOwnedNamespace(c.OwnerNS, s.Owner); err != nil {
		return err
	}
	return os.Remove(filepath.Join(c.StateDir, "state.json"))
}
