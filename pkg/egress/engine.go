package egress

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
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

type Engine struct {
	mu     sync.Mutex
	config Config
	runner Runner
	failed error
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
	return &Engine{config: c, runner: r}, nil
}

// Configuration commands must return exactly the documented success response.
// Native CLI errors are response text, so process liveness alone is insufficient.
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
	configuredOut := map[string]bool{}
	configuredAddress := map[string]bool{}
	for index, x := range e.config.Exits {
		table := len(e.config.Interfaces) + 1 + index
		if err := e.empty(ctx, fmt.Sprintf("ip table add %d", table)); err != nil {
			return err
		}
		for _, addr := range x.Addresses {
			if configuredAddress[addr] {
				continue
			}
			configuredAddress[addr] = true
			if err := e.empty(ctx, "nat44 add address "+addr); err != nil {
				return err
			}
			// Native NAT registers each public /32 as local on outside FIBs,
			// including ARP response. An interface /32 alias would overlap its
			// connected prefix and is rejected by VPP for ordinary address pools.
		}
		if !configuredOut[x.Interface] {
			if err := e.empty(ctx, "set interface nat44 out host-"+x.Interface); err != nil {
				return err
			}
			configuredOut[x.Interface] = true
		}
		for _, cmd := range []string{
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
	for _, i := range e.config.Interfaces {
		if err := e.empty(ctx, "set interface reassembly host-"+i.Name+" ip4"); err != nil {
			return err
		}
	}
	return e.configure(ctx, e.config)
}
func (e *Engine) interfaceTable(name string) int {
	for n, i := range e.config.Interfaces {
		if i.Name == name {
			return 1 + n
		}
	}
	panic("validated interface disappeared")
}
func matchCommand(m Match) string {
	p, _ := protocol(m.Protocol)
	return fmt.Sprintf("dst %s proto %d ports %d %d", m.Destination, p, m.PortFirst, m.PortLast)
}
func (e *Engine) stageArea(ctx context.Context, a Area) (err error) {
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
				table = len(e.config.Interfaces) + 1 + i
			}
		}
		if err = e.empty(ctx, fmt.Sprintf("egress-policy pool id %d table %d return-table %d limit %d", p.ID, table, e.exitReturnTable(p.Exit), p.MaxConnections)); err != nil {
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
		Area   uint32 `json:"area"`
		Staged bool   `json:"staged"`
	}
	if err = e.object(ctx, "egress-policy commit", &response); err != nil {
		return err
	}
	if response.Area != a.VNI || !response.Staged {
		return errors.New("Area staging acknowledgement mismatch")
	}
	return nil
}

func (e *Engine) exitReturnTable(name string) int {
	for _, x := range e.config.Exits {
		if x.Name == name {
			return e.interfaceTable(x.Interface)
		}
	}
	panic("validated exit disappeared")
}

// configure prepares the entire file set before one native publication point.
func (e *Engine) configure(ctx context.Context, c Config) (err error) {
	if err = c.Validate(); err != nil {
		return err
	}
	if err = e.empty(ctx, "egress-policy reset"); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = e.empty(cleanup, "egress-policy abort")
			_ = e.empty(cleanup, "egress-geneve abort")
		}
	}()
	if err = e.empty(ctx, fmt.Sprintf("egress-geneve begin max-contexts %d idle %d udp %d tcp-established %d tcp-transitory %d icmp %d",
		c.MaxContexts, c.ContextIdleSeconds, c.Timeouts.UDP, c.Timeouts.TCPEstablished, c.Timeouts.TCPTransitory, c.Timeouts.ICMP)); err != nil {
		return err
	}
	for _, a := range c.Areas {
		if err = e.stageArea(ctx, a); err != nil {
			return err
		}
	}
	for _, a := range c.Attachments {
		_, i, _ := c.attachment(a.Name)
		overhead := uint32(36)
		if a.Encapsulation == "ether" {
			overhead += 14
		}
		if a.Locator == "tlv" {
			overhead += 8
		}
		mtu := min(a.MTU, a.InnerMTU+overhead)
		command := fmt.Sprintf("egress-geneve profile underlay host-%s underlay-table %d local %s peer %s next-hop %s area %d locator %s encap %s bits %d gateway %s mtu %d port-base %d tlv-class %d tlv-type %d",
			i.Name, e.interfaceTable(i.Name), netip.MustParsePrefix(i.Address).Addr(), a.Peer, a.NextHop, a.Area, a.Locator, a.Encapsulation, a.GenerationBits, a.Gateway, mtu, a.PortBase, a.TLVClass, a.TLVType)
		if err = e.empty(ctx, command); err != nil {
			return err
		}
	}
	var ack struct {
		Committed  bool   `json:"committed"`
		Terminated uint64 `json:"terminated"`
	}
	if err = e.object(ctx, "egress-geneve commit", &ack); err != nil {
		return e.uncertain("configuration publication", err)
	}
	if !ack.Committed {
		e.failed = errors.New("configuration commit acknowledgement mismatch")
		return e.failed
	}
	return nil
}

// Snapshot is emitted to a local diagnostic file by the owner process. It is
// not a request endpoint and never becomes a configuration source.
func (e *Engine) Snapshot(ctx context.Context) (map[string]any, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var state map[string]any
	if err := e.object(ctx, "show egress-geneve", &state); err != nil {
		return nil, err
	}
	out, err := e.runner.Run(ctx, "egress-policy summary")
	if err != nil {
		return nil, err
	}
	rows := []json.RawMessage{}
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		if !json.Valid([]byte(line)) {
			return nil, errors.New("invalid native counters")
		}
		rows = append(rows, json.RawMessage(line))
	}
	state["pools"] = rows
	errors, err := e.runner.Run(ctx, "show errors")
	if err != nil {
		return nil, err
	}
	state["native_errors"] = errors
	return state, nil
}
func (e *Engine) Failure() error { e.mu.Lock(); defer e.mu.Unlock(); return e.failed }

// Reload prepares all mutable file configuration before publication. Changes
// to runtime resources are detected before any native command; support for
// re-provisioning those resources is tracked separately from policy reload.
func (e *Engine) Reload(ctx context.Context, c Config) error {
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	var owned Config
	if err = json.Unmarshal(raw, &owned); err != nil {
		return err
	}
	c = owned
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.failed != nil {
		return e.failed
	}
	if err := c.Validate(); err != nil {
		return err
	}
	oldResources, newResources := e.config, c
	oldResources.Areas = nil
	newResources.Areas = nil
	oldResources.AreaFiles = nil
	newResources.AreaFiles = nil
	oldResources.Attachments = nil
	newResources.Attachments = nil
	oldResources.MaxContexts = 0
	newResources.MaxContexts = 0
	oldResources.ContextIdleSeconds = 0
	newResources.ContextIdleSeconds = 0
	oldResources.Timeouts = NATTimeouts{}
	newResources.Timeouts = NATTimeouts{}
	if !reflect.DeepEqual(oldResources, newResources) {
		return errors.New("runtime resource change requires restart; configuration retained")
	}
	if err := e.configure(ctx, c); err != nil {
		return err
	}
	e.config = c
	return nil
}
