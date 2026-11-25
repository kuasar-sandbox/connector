package egress

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Runner interface {
	Run(context.Context, string) (string, error)
}
type nativeRejection struct{ command, output string }

func (e *nativeRejection) Error() string {
	return fmt.Sprintf("VPP rejected %q: %s", e.command, e.output)
}

func (e *Engine) uncertain(operation string, err error) error {
	var rejected *nativeRejection
	if !errors.As(err, &rejected) {
		e.failed = fmt.Errorf("%s outcome unknown: %w", operation, err)
	}
	return err
}

type VPPRunner struct{ Binary, Socket, LibraryPath string }

func (v VPPRunner) Run(ctx context.Context, command string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, v.Binary, "-s", v.Socket, command)
	cmd.Env = runtimeEnv(v.LibraryPath)
	b, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("VPP %q: %w: %s", command, err, b)
	}
	return strings.TrimSpace(string(b)), nil
}

type Session struct {
	SessionRequest
	Token     string    `json:"token"`
	Table     uint32    `json:"table"`
	ExpiresAt time.Time `json:"expires_at"`
	Retiring  bool      `json:"retiring"`
}
type NativeSession struct {
	Table      uint32  `json:"table"`
	Area       uint32  `json:"area"`
	Slot       uint32  `json:"slot"`
	Generation uint32  `json:"generation"`
	Retiring   bool    `json:"retiring"`
	Remaining  float64 `json:"remaining"`
	RX         uint64  `json:"rx"`
	TX         uint64  `json:"tx"`
}
type Engine struct {
	mu       sync.Mutex
	config   Config
	runner   Runner
	sessions map[string]Session
	now      func() time.Time
	failed   error
	persist  func([]Area) error
	lastSync time.Time
}

func NewEngine(c Config, r Runner) (*Engine, error) {
	// Own the mutable configuration; caller slices must not race policy updates.
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &Engine{config: c, runner: r, sessions: map[string]Session{}, now: time.Now}, nil
}

// Configuration commands must return exactly the documented success response.
// vppctl can exit zero for a CLI error, so process status alone is insufficient.
func (e *Engine) empty(ctx context.Context, command string) error {
	out, err := e.runner.Run(ctx, command)
	if err != nil {
		return err
	}
	if out != "" {
		return &nativeRejection{command, out}
	}
	return nil
}
func (e *Engine) object(ctx context.Context, command string, result any) error {
	out, err := e.runner.Run(ctx, command)
	if err != nil {
		return err
	}
	if err = json.Unmarshal([]byte(out), result); err != nil {
		// Only the command's explicit CLI error proves rejection. A truncated
		// or malformed success response leaves a mutation's outcome unknown.
		fields := strings.Fields(command)
		if len(fields) >= 2 && strings.HasPrefix(out, strings.Join(fields[:2], " ")+": ") {
			return &nativeRejection{command, out}
		}
		return fmt.Errorf("invalid VPP response to %q: %w", command, err)
	}
	return nil
}
func (e *Engine) Setup(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, i := range e.config.Interfaces {
		cmd := fmt.Sprintf("create host-interface v2 name %s qdisc-bypass-disable cksum-gso-disable rx-size 2048 tx-size 2048 rx-per-block 256 tx-per-block 256", i.Name)
		out, err := e.runner.Run(ctx, cmd)
		if err != nil {
			return err
		}
		if out != "host-"+i.Name {
			return fmt.Errorf("create interface: %s", out)
		}
		for _, cmd := range []string{fmt.Sprintf("set interface mtu packet %d host-%s", i.MTU, i.Name), "set interface state host-" + i.Name + " up"} {
			if err = e.empty(ctx, cmd); err != nil {
				return err
			}
		}
	}
	if err := e.empty(ctx, fmt.Sprintf("nat44 plugin enable sessions %d", e.config.MaxConnections)); err != nil {
		return err
	}
	for _, i := range e.config.Interfaces {
		table := e.interfaceTable(i.Name)
		for _, cmd := range []string{fmt.Sprintf("ip table add %d", table), fmt.Sprintf("set interface ip table host-%s %d", i.Name, table)} {
			if err := e.empty(ctx, cmd); err != nil {
				return err
			}
		}
	}
	for _, i := range e.config.Interfaces {
		if err := e.empty(ctx, fmt.Sprintf("set interface ip address host-%s %s", i.Name, i.Address)); err != nil {
			return err
		}
	}
	peers := map[string]bool{}
	for _, a := range e.config.Attachments {
		key := a.Interface + "/" + a.Peer
		if peers[key] {
			continue
		}
		peers[key] = true
		if err := e.empty(ctx, fmt.Sprintf("ip route add table %d %s/32 via %s host-%s", e.interfaceTable(a.Interface), a.Peer, a.NextHop, a.Interface)); err != nil {
			return err
		}
	}
	for index, x := range e.config.Exits {
		table := 100 + index
		for _, addr := range x.Addresses {
			if err := e.empty(ctx, "nat44 add address "+addr); err != nil {
				return err
			}
			// Native NAT registers each public /32 as local on outside FIBs,
			// including ARP response. An interface /32 alias would overlap its
			// connected prefix and is rejected by VPP for ordinary address pools.
		}
		for _, cmd := range []string{
			fmt.Sprintf("set interface nat44 out host-%s", x.Interface),
			fmt.Sprintf("ip route add table %d 0.0.0.0/0 via %s host-%s", table, x.NextHop, x.Interface),
			fmt.Sprintf("set interface reassembly host-%s ip4", x.Interface),
			fmt.Sprintf("egress-packet-id host-%s mtu 65535", x.Interface),
		} {
			if err := e.empty(ctx, cmd); err != nil {
				return err
			}
		}
	}
	if err := e.empty(ctx, "egress-packet-reassembly"); err != nil {
		return err
	}
	for _, a := range e.config.Areas {
		if err := e.applyArea(ctx, a); err != nil {
			return err
		}
	}
	return nil
}
func (e *Engine) interfaceTable(name string) int {
	for n, x := range e.config.Exits {
		if x.Interface == name {
			return 100 + n
		}
	}
	for n, i := range e.config.Interfaces {
		if i.Name == name {
			return 1000 + n
		}
	}
	panic("validated interface disappeared")
}
func matchCommand(m Match) string {
	p, _ := protocol(m.Protocol)
	return fmt.Sprintf("dst %s proto %d ports %d %d", m.Destination, p, m.PortFirst, m.PortLast)
}
func (e *Engine) applyArea(ctx context.Context, a Area) (err error) {
	if err = e.config.ValidateArea(a); err != nil {
		return err
	}
	if err = e.empty(ctx, fmt.Sprintf("egress-policy begin area %d", a.VNI)); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = e.empty(cleanup, "egress-policy abort")
		}
	}()
	for _, p := range a.Pools {
		table := 0
		for i, x := range e.config.Exits {
			if x.Name == p.Exit {
				table = 100 + i
			}
		}
		if err = e.empty(ctx, fmt.Sprintf("egress-policy pool id %d table %d limit %d", p.ID, table, p.MaxConnections)); err != nil {
			return err
		}
		for _, addr := range p.Addresses {
			if err = e.empty(ctx, fmt.Sprintf("egress-policy address pool %d %s", p.ID, addr)); err != nil {
				return err
			}
		}
	}
	for _, r := range a.ACL {
		if err = e.empty(ctx, "egress-policy acl "+matchCommand(r.Match)+" "+r.Action); err != nil {
			return err
		}
	}
	for _, r := range a.DNAT {
		if err = e.empty(ctx, fmt.Sprintf("egress-policy dnat %s pool %d target %s port %d", matchCommand(r.Match), r.Pool, r.Target, r.TargetPort)); err != nil {
			return err
		}
	}
	for _, r := range a.Routes {
		if err = e.empty(ctx, fmt.Sprintf("egress-policy route dst %s pool %d", r.Destination, r.Pool)); err != nil {
			return err
		}
	}
	var response struct {
		Area       uint32 `json:"area"`
		Terminated uint32 `json:"terminated"`
	}
	if err = e.object(ctx, "egress-policy commit", &response); err != nil {
		// A lost commit response is ambiguous. Stop accepting control mutations;
		// the supervisor will stop the dataplane rather than claim a rollback.
		e.failed = fmt.Errorf("policy commit outcome unknown: %w", err)
		return e.failed
	}
	if response.Area != a.VNI {
		e.failed = errors.New("policy commit identity mismatch")
		return e.failed
	}
	return nil
}
func (e *Engine) ApplyArea(ctx context.Context, a Area) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.failed != nil {
		return e.failed
	}
	raw, err := json.Marshal(a)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(raw, &a); err != nil {
		return err
	}
	index := -1
	for i, old := range e.config.Areas {
		if old.VNI == a.VNI {
			index = i
		}
	}
	if index < 0 {
		return errors.New("runtime update requires an existing Area")
	}
	if err := e.applyArea(ctx, a); err != nil {
		return err
	}
	e.config.Areas[index] = a
	if e.persist != nil {
		if err := e.persist(e.config.Areas); err != nil {
			e.failed = fmt.Errorf("persist committed policy: %w", err)
			return e.failed
		}
	}
	return nil
}
func (e *Engine) nativeSessions(ctx context.Context) ([]NativeSession, error) {
	out, err := e.runner.Run(ctx, "show egress-geneve")
	if err != nil {
		return nil, err
	}
	rows := []NativeSession{}
	if out != "" {
		for _, line := range strings.Split(out, "\n") {
			var s NativeSession
			if err = json.Unmarshal([]byte(line), &s); err != nil {
				return nil, fmt.Errorf("invalid native session response: %w", err)
			}
			rows = append(rows, s)
		}
	}
	live := map[uint32]NativeSession{}
	for _, s := range rows {
		live[s.Table] = s
	}
	for id, s := range e.sessions {
		if row, ok := live[s.Table]; !ok {
			delete(e.sessions, id)
		} else {
			s.Retiring = row.Retiring || row.Remaining <= 0
			e.sessions[id] = s
		}
	}
	e.lastSync = e.now()
	return rows, nil
}
func (e *Engine) Open(ctx context.Context, s SessionRequest) (Session, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.failed != nil {
		return Session{}, e.failed
	}
	if err := e.config.ValidateSession(s); err != nil {
		return Session{}, err
	}
	// The private runtime is owned by this engine. Reconcile native retirement
	// periodically, on retries, and at capacity; avoid quadratic CLI output when
	// a controller registers thousands of attachments.
	_, retry := e.sessions[s.ID]
	if retry || len(e.sessions) >= MaxSessions || e.now().Sub(e.lastSync) >= time.Second {
		if _, err := e.nativeSessions(ctx); err != nil {
			return Session{}, err
		}
	}
	if old, ok := e.sessions[s.ID]; ok {
		if old.SessionRequest != s || old.Retiring {
			return Session{}, errors.New("session ID already belongs to a different or retiring grant")
		}
		return old, nil
	}
	if len(e.sessions) >= MaxSessions {
		return Session{}, errors.New("session capacity includes retiring attachments")
	}
	taken := map[uint32]bool{}
	for _, r := range e.sessions {
		taken[r.Table] = true
	}
	table := uint32(10000)
	for taken[table] {
		table++
	}
	a, i, _ := e.config.attachment(s.Attachment)
	var tokenBytes [24]byte
	if _, err := rand.Read(tokenBytes[:]); err != nil {
		return Session{}, err
	}
	session := Session{SessionRequest: s, Token: hex.EncodeToString(tokenBytes[:]), Table: table, ExpiresAt: e.now().Add(time.Duration(s.LeaseSeconds) * time.Second)}
	local := netip.MustParsePrefix(i.Address).Addr()
	overhead := uint32(36)
	if a.Encapsulation == "ether" {
		overhead += 14
	}
	if a.Locator == "tlv" {
		overhead += 8
	}
	mtu := min(a.MTU, a.InnerMTU+overhead)
	command := fmt.Sprintf("egress-geneve session table %d underlay host-%s underlay-table %d local %s peer %s area %d slot %d locator %s encap %s bits %d generation %d inner %s gateway %s lease %d mac %s mtu %d port-base %d tlv-class %d tlv-type %d",
		table, i.Name, e.interfaceTable(i.Name), local, a.Peer, a.Area, s.Slot, a.Locator, a.Encapsulation, a.GenerationBits, s.Generation, s.InnerIP, a.Gateway, s.LeaseSeconds, s.ReturnMAC, mtu, a.PortBase, a.TLVClass, a.TLVType)
	var response struct {
		Table     uint32 `json:"table"`
		Interface uint32 `json:"interface"`
		Lease     uint32 `json:"lease"`
	}
	if err := e.object(ctx, command, &response); err != nil {
		e.uncertain("session grant", err)
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var ack map[string]any
		if cleanupErr := e.object(cleanup, fmt.Sprintf("egress-geneve retire table %d", table), &ack); cleanupErr != nil {
			e.failed = fmt.Errorf("session grant/rollback outcome unknown: %w", cleanupErr)
		}
		return Session{}, err
	}
	if response.Table != table || response.Lease != s.LeaseSeconds {
		e.failed = errors.New("session grant identity mismatch")
		return Session{}, e.failed
	}
	e.sessions[s.ID] = session
	return session, nil
}
func (e *Engine) Renew(ctx context.Context, id, token string, ttl uint32) (Session, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.failed != nil {
		return Session{}, e.failed
	}
	s, ok := e.sessions[id]
	if !ok || s.Token != token || s.Retiring {
		return Session{}, errors.New("session token is stale or unknown")
	}
	if ttl == 0 || ttl > MaxLeaseSeconds {
		return Session{}, errors.New("invalid lease")
	}
	var ack struct {
		Table    uint32 `json:"table"`
		Retiring *bool  `json:"retiring"`
	}
	if err := e.object(ctx, fmt.Sprintf("egress-geneve renew table %d lease %d", s.Table, ttl), &ack); err != nil {
		return Session{}, e.uncertain("lease renewal", err)
	}
	if ack.Table != s.Table || ack.Retiring == nil || *ack.Retiring {
		e.failed = errors.New("lease renewal identity mismatch")
		return Session{}, e.failed
	}
	s.ExpiresAt = e.now().Add(time.Duration(ttl) * time.Second)
	s.LeaseSeconds = ttl
	e.sessions[id] = s
	return s, nil
}
func (e *Engine) Close(ctx context.Context, id, token string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.failed != nil {
		return e.failed
	}
	s, ok := e.sessions[id]
	if !ok {
		return nil
	}
	if s.Token != token {
		return errors.New("session token is stale")
	}
	var ack struct {
		Table    uint32 `json:"table"`
		Retiring bool   `json:"retiring"`
		Retired  bool   `json:"retired"`
	}
	if err := e.object(ctx, fmt.Sprintf("egress-geneve retire table %d", s.Table), &ack); err != nil {
		return e.uncertain("session revocation", err)
	}
	if ack.Table != s.Table || (!ack.Retiring && !ack.Retired) {
		e.failed = errors.New("session revocation identity mismatch")
		return e.failed
	}
	s.Retiring = true
	e.sessions[id] = s
	return nil
}
func (e *Engine) Snapshot(ctx context.Context) (map[string]any, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.failed != nil {
		return nil, e.failed
	}
	sessions, err := e.nativeSessions(ctx)
	if err != nil {
		return nil, err
	}
	out, err := e.runner.Run(ctx, "egress-policy stats")
	if err != nil {
		return nil, err
	}
	counters := []json.RawMessage{}
	if out != "" {
		for _, line := range strings.Split(out, "\n") {
			if !json.Valid([]byte(line)) {
				return nil, errors.New("invalid policy counters")
			}
			counters = append(counters, json.RawMessage(line))
		}
	}
	paths := []json.RawMessage{}
	out, err = e.runner.Run(ctx, "egress-policy paths")
	if err != nil {
		return nil, err
	}
	if out != "" {
		for _, line := range strings.Split(out, "\n") {
			if !json.Valid([]byte(line)) {
				return nil, errors.New("invalid Pool path response")
			}
			paths = append(paths, json.RawMessage(line))
		}
	}
	return map[string]any{"name": e.config.Name, "dataplane_configured": true,
		"interfaces": InterfaceStatus(e.config), "sessions": sessions, "pools": counters,
		"exits": e.config.Exits, "attachments": e.config.Attachments,
		"pool_paths":     paths,
		"readiness":      "requires bidirectional sandbox probe through each selected Pool",
		"control_socket": filepath.Join(e.config.RuntimeDir, "control.sock")}, nil
}
func (e *Engine) Failure() error { e.mu.Lock(); defer e.mu.Unlock(); return e.failed }
