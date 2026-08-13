package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kuasar-sandbox/connector/pkg/netns"
	"github.com/kuasar-sandbox/connector/pkg/tapfd"
	"github.com/kuasar-sandbox/connector/pkg/vswitch"
)

const (
	tapFDRequestTimeout    = 5 * time.Second
	tapFDStaleProbeTimeout = 100 * time.Millisecond
)

type tapFDServer struct {
	path     string
	ln       *net.UnixListener
	cancel   context.CancelFunc
	netns    *netns.NetNS
	handlers sync.WaitGroup
	done     chan struct{}
	errCh    chan error
}

func startTapFDServer(parent context.Context, path, switchName string, sw vswitch.Interface) (*tapFDServer, error) {
	if err := prepareTapFDListenPath(path); err != nil {
		return nil, err
	}
	var switchNs *netns.NetNS
	if sw != nil {
		switchNsName := sw.Metadata().SwitchNetnsName()
		ns, err := netns.GetByName(switchNsName)
		if err != nil {
			return nil, fmt.Errorf("switch netns %s: %w", switchNsName, err)
		}
		switchNs = ns
	}
	addr, err := net.ResolveUnixAddr("unix", path)
	if err != nil {
		if switchNs != nil {
			_ = switchNs.Close()
		}
		return nil, fmt.Errorf("resolve tapfd socket %s: %w", path, err)
	}
	ln, err := net.ListenUnix("unix", addr)
	if err != nil {
		if switchNs != nil {
			_ = switchNs.Close()
		}
		return nil, fmt.Errorf("listen tapfd socket %s: %w", path, err)
	}
	if err := os.Chmod(path, 0660); err != nil {
		_ = ln.Close()
		_ = os.Remove(path)
		if switchNs != nil {
			_ = switchNs.Close()
		}
		return nil, fmt.Errorf("chmod tapfd socket %s: %w", path, err)
	}

	ctx, cancel := context.WithCancel(parent)
	s := &tapFDServer{
		path:   path,
		ln:     ln,
		cancel: cancel,
		netns:  switchNs,
		done:   make(chan struct{}),
		errCh:  make(chan error, 1),
	}
	go s.serve(ctx, switchName, sw)
	return s, nil
}

func (s *tapFDServer) Close() error {
	s.cancel()
	err := s.ln.Close()
	<-s.done
	s.handlers.Wait()
	if rmErr := os.Remove(s.path); rmErr != nil && !os.IsNotExist(rmErr) && err == nil {
		err = rmErr
	}
	if s.netns != nil {
		if nsErr := s.netns.Close(); nsErr != nil && err == nil {
			err = nsErr
		}
	}
	return err
}

func (s *tapFDServer) Err() <-chan error {
	return s.errCh
}

func (s *tapFDServer) serve(ctx context.Context, switchName string, sw vswitch.Interface) {
	defer close(s.done)
	for {
		conn, err := s.ln.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			select {
			case s.errCh <- fmt.Errorf("accept tapfd socket %s: %w", s.path, err):
			default:
			}
			return
		}
		s.handlers.Add(1)
		go func() {
			defer s.handlers.Done()
			handleTapFDConn(conn, switchName, sw, s.netns)
		}()
	}
}

func prepareTapFDListenPath(path string) error {
	if path == "" {
		return fmt.Errorf("tapfd listen socket path is required")
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("tapfd listen socket path must be absolute: %s", path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return fmt.Errorf("create tapfd socket directory: %w", err)
	}

	st, err := os.Lstat(path)
	if err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("tapfd listen path exists and is not a socket: %s", path)
		}
		conn, dialErr := net.DialTimeout("unix", path, tapFDStaleProbeTimeout)
		if dialErr == nil {
			_ = conn.Close()
			return fmt.Errorf("tapfd listen socket already active: %s", path)
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove stale tapfd socket %s: %w", path, err)
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("stat tapfd listen socket %s: %w", path, err)
	}
	return nil
}

func handleTapFDConn(conn *net.UnixConn, switchName string, sw vswitch.Interface, switchNs *netns.NetNS) {
	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(tapFDRequestTimeout)); err != nil {
		sendTapFDError(conn, tapfd.ErrorCodeProviderInternal, err)
		return
	}
	line, err := readTapFDRequestLine(conn)
	if err != nil {
		sendTapFDError(conn, tapfd.ErrorCodeBadRequest, err)
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	req, err := tapfd.ParseRequestLine(line)
	if err != nil {
		sendTapFDError(conn, tapfd.ErrorCodeBadRequest, err)
		return
	}

	requestSwitch := requestField(req, "switch", "vswitch", "VSWITCH")
	if requestSwitch == "" {
		sendTapFDError(conn, tapfd.ErrorCodeBadRequest, fmt.Errorf("missing switch field"))
		return
	}
	if requestSwitch != switchName {
		sendTapFDError(conn, tapfd.ErrorCodeSwitchMismatch, fmt.Errorf("requested switch %s, serving %s", requestSwitch, switchName))
		return
	}
	if sw == nil {
		sendTapFDError(conn, tapfd.ErrorCodeProviderInternal, fmt.Errorf("switch handle unavailable"))
		return
	}

	switch req.Op {
	case tapfd.RequestOpPrepare:
		handleTapFDPrepare(conn, sw, req)
	case tapfd.RequestOpOpen:
		handleTapFDOpen(conn, switchName, sw, switchNs, req)
	case tapfd.RequestOpRelease:
		handleTapFDRelease(conn, sw, req)
	default:
		sendTapFDError(conn, tapfd.ErrorCodeBadRequest, fmt.Errorf("unsupported request op %q", req.Op))
	}
}

func handleTapFDPrepare(conn *net.UnixConn, sw vswitch.Interface, req *tapfd.Request) {
	opts, err := prepareAttachOptions(req)
	if err != nil {
		sendTapFDError(conn, tapfd.ErrorCodeBadRequest, err)
		return
	}
	out, err := sw.Attach(opts)
	if err != nil {
		sendTapFDError(conn, tapFDErrorCode(err), err)
		return
	}
	if out.Mode != vswitch.PortKindTap.String() {
		if detachErr := sw.Detach(vswitch.DetachOptions{Port: int(out.Port), SkipDevice: true}); detachErr != nil {
			sendTapFDError(conn, tapfd.ErrorCodeProviderInternal,
				fmt.Errorf("port %d is %s, not tap; rollback: %w", out.Port, out.Mode, detachErr))
			return
		}
		sendTapFDError(conn, tapfd.ErrorCodePortInvalid, fmt.Errorf("port %d is %s, not tap", out.Port, out.Mode))
		return
	}
	if err := sendTapFDOK(conn, fmt.Sprintf("port=%d floating_ip=%s mac=%s ip=%s mode=%s",
		out.Port, out.FloatingIP, out.PortMAC, out.InnerIP, out.Mode)); err != nil {
		// The client never received the allocated port number and therefore cannot
		// RELEASE it. Roll back here so a disconnected caller cannot leak a slot.
		_ = sw.Detach(vswitch.DetachOptions{Port: int(out.Port), SkipDevice: true})
	}
}

func handleTapFDOpen(conn *net.UnixConn, switchName string, sw vswitch.Interface, switchNs *netns.NetNS, req *tapfd.Request) {
	portText := requestField(req, "port", "PORT")
	if portText == "" {
		sendTapFDError(conn, tapfd.ErrorCodePortInvalid, fmt.Errorf("missing port field"))
		return
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 {
		sendTapFDError(conn, tapfd.ErrorCodePortInvalid, fmt.Errorf("invalid port %q", portText))
		return
	}

	slotID, err := validateOpenPort(sw, port)
	if err != nil {
		sendTapFDError(conn, tapFDErrorCode(err), err)
		return
	}
	if _, err := openPortAndSendToConn(sw, switchName, slotID, conn, "tapfd-listen:"+switchName, req.WantNetns, true, switchNs); err != nil {
		sendTapFDError(conn, tapFDErrorCode(err), err)
	}
}

func handleTapFDRelease(conn *net.UnixConn, sw vswitch.Interface, req *tapfd.Request) {
	portText := requestField(req, "port", "PORT")
	if portText == "" {
		sendTapFDError(conn, tapfd.ErrorCodePortInvalid, fmt.Errorf("missing port field"))
		return
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 {
		sendTapFDError(conn, tapfd.ErrorCodePortInvalid, fmt.Errorf("invalid port %q", portText))
		return
	}
	if err := sw.Detach(vswitch.DetachOptions{Port: port}); err != nil {
		sendTapFDError(conn, tapFDErrorCode(err), err)
		return
	}
	_ = sendTapFDOK(conn, fmt.Sprintf("port=%d released=1", port))
}

func prepareAttachOptions(req *tapfd.Request) (vswitch.AttachOptions, error) {
	innerText := requestField(req, "inner_ip", "INNER_IP")
	if innerText == "" {
		return vswitch.AttachOptions{}, fmt.Errorf("missing inner_ip field")
	}
	innerIP := net.ParseIP(innerText)
	if innerIP == nil {
		return vswitch.AttachOptions{}, fmt.Errorf("invalid inner_ip %q", innerText)
	}
	opts := vswitch.AttachOptions{InnerIP: innerIP}

	if gatewayText := requestField(req, "transit_gateway_ip", "transit-gateway-ip", "TRANSIT_GATEWAY_IP"); gatewayText != "" {
		opts.TransitGatewayIP = net.ParseIP(gatewayText)
		if opts.TransitGatewayIP == nil {
			return vswitch.AttachOptions{}, fmt.Errorf("invalid transit_gateway_ip %q", gatewayText)
		}
	}
	if vniText := requestField(req, "transit_geneve_vni", "transit-geneve-vni", "TRANSIT_GENEVE_VNI"); vniText != "" {
		vni, err := strconv.ParseUint(vniText, 10, 32)
		if err != nil {
			return vswitch.AttachOptions{}, fmt.Errorf("invalid transit_geneve_vni %q", vniText)
		}
		opts.TransitGeneveVNI = uint32(vni)
	}
	if optionsText := requestField(req, "transit_geneve_opts", "transit-geneve-opts", "TRANSIT_GENEVE_OPTS"); optionsText != "" {
		options, err := vswitch.ParseGeneveOptions(optionsText)
		if err != nil {
			return vswitch.AttachOptions{}, fmt.Errorf("invalid transit_geneve_opts %q: %w", optionsText, err)
		}
		opts.TransitGeneveOpts = options
	}
	if macText := requestField(req, "transit_mac", "transit-mac", "transit-mac-addr", "TRANSIT_MAC"); macText != "" {
		mac, err := net.ParseMAC(macText)
		if err != nil {
			return vswitch.AttachOptions{}, fmt.Errorf("invalid transit_mac %q: %w", macText, err)
		}
		opts.TransitMAC = mac
	}
	return opts, nil
}

func readTapFDRequestLine(conn *net.UnixConn) (string, error) {
	buf := make([]byte, 0, tapfd.RequestMaxLineSize)
	one := make([]byte, 1)
	for len(buf) < tapfd.RequestMaxLineSize {
		n, err := conn.Read(one)
		if n == 1 {
			switch one[0] {
			case '\n':
				return string(buf), nil
			case 0:
				return "", fmt.Errorf("request line contains NUL")
			default:
				buf = append(buf, one[0])
			}
		}
		if err != nil {
			if err == io.EOF && len(buf) > 0 {
				return string(buf), nil
			}
			return "", err
		}
	}
	return "", fmt.Errorf("request line too long: %d > %d", len(buf)+1, tapfd.RequestMaxLineSize)
}

func sendTapFDError(conn *net.UnixConn, code string, err error) {
	msg := "error"
	if err != nil {
		msg = err.Error()
	}
	_, _ = conn.Write(tapfd.BuildErrorResponse(code, msg))
}

func sendTapFDOK(conn *net.UnixConn, fields string) error {
	msg, err := tapfd.BuildOKLine(fields)
	if err != nil {
		_, _ = conn.Write(tapfd.BuildErrorResponse(tapfd.ErrorCodeProviderInternal, err.Error()))
		return err
	}
	n, err := conn.Write(msg)
	if err != nil {
		return err
	}
	if n != len(msg) {
		return io.ErrShortWrite
	}
	return nil
}

func tapFDErrorCode(err error) string {
	switch {
	case vswitch.IsPortOutOfRange(err):
		return tapfd.ErrorCodePortInvalid
	case vswitch.IsPortAllocated(err), vswitch.IsPortNotAttached(err), vswitch.IsPortNotProvisioned(err):
		return tapfd.ErrorCodePortUnavailable
	case strings.Contains(err.Error(), "no free slots available"):
		return tapfd.ErrorCodePortUnavailable
	case strings.Contains(err.Error(), "not tap"):
		return tapfd.ErrorCodePortInvalid
	default:
		return tapfd.ErrorCodeProviderInternal
	}
}

func requestField(req *tapfd.Request, names ...string) string {
	for _, name := range names {
		if v := req.Fields[name]; v != "" {
			return v
		}
	}
	return ""
}
