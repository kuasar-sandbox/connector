package main

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/kuasar-sandbox/connector/pkg/tapfd"
	"github.com/kuasar-sandbox/connector/pkg/vswitch"
)

func TestTapFDServerRejectsSwitchMismatch(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "tapfd.sock")
	srv, err := startTapFDServer(context.Background(), sock, "sw0", nil)
	if err != nil {
		t.Fatalf("startTapFDServer: %v", err)
	}
	defer srv.Close()

	conn, err := tapfd.ConnectUnix(sock)
	if err != nil {
		t.Fatalf("ConnectUnix: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("TAPFD/1 OPEN switch=other port=1\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	_, _, _, err = tapfd.RecvFdsWithNetns(conn)
	if err == nil || !strings.Contains(err.Error(), tapfd.ErrorCodeSwitchMismatch) {
		t.Fatalf("RecvFdsWithNetns error = %v, want switch mismatch", err)
	}
}

func TestTapFDServerRejectsMalformedRequest(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "tapfd.sock")
	srv, err := startTapFDServer(context.Background(), sock, "sw0", nil)
	if err != nil {
		t.Fatalf("startTapFDServer: %v", err)
	}
	defer srv.Close()

	conn, err := tapfd.ConnectUnix(sock)
	if err != nil {
		t.Fatalf("ConnectUnix: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("bad request\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	_, _, _, err = tapfd.RecvFdsWithNetns(conn)
	if err == nil || !strings.Contains(err.Error(), tapfd.ErrorCodeBadRequest) {
		t.Fatalf("RecvFdsWithNetns error = %v, want bad request", err)
	}
}

func TestPrepareTapFDListenPathRejectsNonSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tapfd.sock")
	if err := os.WriteFile(path, []byte("not socket"), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if err := prepareTapFDListenPath(path); err == nil {
		t.Fatalf("prepareTapFDListenPath: want error for non-socket path")
	}
}

func TestTapFDServerCloseWaitsForHandlers(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "tapfd.sock")
	addr, err := net.ResolveUnixAddr("unix", sock)
	if err != nil {
		t.Fatalf("ResolveUnixAddr: %v", err)
	}
	ln, err := net.ListenUnix("unix", addr)
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	srv := &tapFDServer{
		path:   sock,
		ln:     ln,
		cancel: cancel,
		done:   make(chan struct{}),
		errCh:  make(chan error, 1),
	}
	attachStarted := make(chan struct{})
	continueAttach := make(chan struct{})
	fake := &fakeVSwitch{
		attachOut:      &vswitch.AttachOutput{Port: 7, InnerIP: "169.254.0.21", Mode: "tap"},
		attachStarted:  attachStarted,
		continueAttach: continueAttach,
	}
	go srv.serve(ctx, "sw0", fake)

	conn, err := tapfd.ConnectUnix(sock)
	if err != nil {
		t.Fatalf("ConnectUnix: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("TAPFD/1 PREPARE VSWITCH=sw0 INNER_IP=169.254.0.21\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	<-attachStarted

	closed := make(chan error, 1)
	go func() { closed <- srv.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("Close returned while handler was blocked: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(continueAttach)
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not return after handler exited")
	}
}

func TestTapFDServerPrepare(t *testing.T) {
	server, client := unixSocketPair(t)
	defer client.Close()
	fake := &fakeVSwitch{
		attachOut: &vswitch.AttachOutput{
			Port:       7,
			FloatingIP: "100.100.96.7",
			PortMAC:    "02:00:00:00:80:07",
			InnerIP:    "169.254.0.21",
			Mode:       "tap",
		},
	}
	go handleTapFDConn(server, "sw0", fake, nil)

	if _, err := client.Write([]byte("TAPFD/1 PREPARE VSWITCH=sw0 INNER_IP=169.254.0.21 TRANSIT_GATEWAY_IP=192.0.2.1 TRANSIT_GENEVE_VNI=4242 transit_geneve_opts=0102:02:0000002a,0102:83: TRANSIT_MAC=02:00:00:00:00:09\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp := readAllString(t, client)
	if !strings.HasPrefix(resp, "TAPFD/1 OK ") || !strings.Contains(resp, "port=7") || !strings.Contains(resp, "mode=tap") {
		t.Fatalf("response = %q, want OK prepare fields", resp)
	}
	if fake.attachOpts.InnerIP.String() != "169.254.0.21" ||
		fake.attachOpts.TransitGatewayIP.String() != "192.0.2.1" ||
		fake.attachOpts.TransitGeneveVNI != 4242 ||
		len(fake.attachOpts.TransitGeneveOpts) != 2 ||
		fake.attachOpts.TransitGeneveOpts[0].String() != "0102:02:0000002a" ||
		fake.attachOpts.TransitGeneveOpts[1].String() != "0102:83:" ||
		fake.attachOpts.TransitMAC.String() != "02:00:00:00:00:09" {
		t.Fatalf("attach opts = %+v", fake.attachOpts)
	}
}

func TestPrepareAttachOptionsEmptyAndInvalidGeneveOptions(t *testing.T) {
	empty := &tapfd.Request{Fields: map[string]string{
		"inner_ip":            "169.254.0.21",
		"transit_geneve_opts": "",
	}}
	opts, err := prepareAttachOptions(empty)
	if err != nil {
		t.Fatal(err)
	}
	if len(opts.TransitGeneveOpts) != 0 {
		t.Fatalf("empty options = %#v", opts.TransitGeneveOpts)
	}

	invalid := &tapfd.Request{Fields: map[string]string{
		"inner_ip":            "169.254.0.21",
		"transit_geneve_opts": "0102:02:0000",
	}}
	if _, err := prepareAttachOptions(invalid); err == nil {
		t.Fatal("expected invalid TAPFD GENEVE options error")
	}
}

func TestTapFDPrepareMaximumGeneveOptionsFitsRequestLine(t *testing.T) {
	// One option with 60 data bytes occupies the full 64-byte port/vni wire
	// budget. Its canonical text plus the required PREPARE fields must remain
	// below the TAPFD/1 512-byte request-line limit.
	extra := "VSWITCH=sw0 INNER_IP=169.254.0.21 transit_geneve_opts=0102:02:" + strings.Repeat("00", 60)
	request, err := tapfd.BuildRequest(tapfd.RequestOpPrepare, extra, false)
	if err != nil {
		t.Fatalf("maximum options request: %v", err)
	}
	if len(request) > tapfd.RequestMaxLineSize {
		t.Fatalf("request length = %d", len(request))
	}
}

func TestTapFDServerPrepareRejectsNonTapAndRollsBack(t *testing.T) {
	server, client := unixSocketPair(t)
	defer client.Close()
	fake := &fakeVSwitch{
		attachOut: &vswitch.AttachOutput{
			Port:    3,
			InnerIP: "169.254.0.21",
			Mode:    "veth",
		},
	}
	go handleTapFDConn(server, "sw0", fake, nil)

	if _, err := client.Write([]byte("TAPFD/1 PREPARE VSWITCH=sw0 INNER_IP=169.254.0.21\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp := readAllString(t, client)
	if !strings.Contains(resp, tapfd.ErrorCodePortInvalid) {
		t.Fatalf("response = %q, want port invalid", resp)
	}
	if fake.detachOpts.Port != 3 || !fake.detachOpts.SkipDevice {
		t.Fatalf("rollback detach opts = %+v", fake.detachOpts)
	}
}

func TestTapFDServerPrepareResponseFailureRollsBack(t *testing.T) {
	server, client := unixSocketPair(t)
	attachStarted := make(chan struct{})
	continueAttach := make(chan struct{})
	fake := &fakeVSwitch{
		attachOut:      &vswitch.AttachOutput{Port: 7, InnerIP: "169.254.0.21", Mode: "tap"},
		attachStarted:  attachStarted,
		continueAttach: continueAttach,
	}
	done := make(chan struct{})
	go func() {
		handleTapFDConn(server, "sw0", fake, nil)
		close(done)
	}()

	if _, err := client.Write([]byte("TAPFD/1 PREPARE VSWITCH=sw0 INNER_IP=169.254.0.21\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	<-attachStarted
	_ = client.Close()
	close(continueAttach)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler did not return")
	}
	if fake.detachOpts.Port != 7 || !fake.detachOpts.SkipDevice {
		t.Fatalf("response failure rollback opts = %+v", fake.detachOpts)
	}
}

func TestTapFDServerRelease(t *testing.T) {
	server, client := unixSocketPair(t)
	defer client.Close()
	fake := &fakeVSwitch{}
	go handleTapFDConn(server, "sw0", fake, nil)

	if _, err := client.Write([]byte("TAPFD/1 RELEASE VSWITCH=sw0 PORT=9\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp := readAllString(t, client)
	if got, want := resp, "TAPFD/1 OK port=9 released=1\n"; got != want {
		t.Fatalf("response = %q, want %q", got, want)
	}
	if fake.detachOpts.Port != 9 {
		t.Fatalf("detach opts = %+v", fake.detachOpts)
	}
}

type fakeVSwitch struct {
	vswitch.Interface
	attachOpts     vswitch.AttachOptions
	attachOut      *vswitch.AttachOutput
	attachErr      error
	attachStarted  chan struct{}
	continueAttach chan struct{}
	detachOpts     vswitch.DetachOptions
	detachErr      error
}

func (f *fakeVSwitch) Attach(opts vswitch.AttachOptions) (*vswitch.AttachOutput, error) {
	f.attachOpts = opts
	if f.attachStarted != nil {
		close(f.attachStarted)
		<-f.continueAttach
	}
	return f.attachOut, f.attachErr
}

func (f *fakeVSwitch) Detach(opts vswitch.DetachOptions) error {
	f.detachOpts = opts
	return f.detachErr
}

func unixSocketPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	return unixConnFromFD(t, fds[0]), unixConnFromFD(t, fds[1])
}

func unixConnFromFD(t *testing.T, fd int) *net.UnixConn {
	t.Helper()
	file := os.NewFile(uintptr(fd), "tapfd-server-test")
	conn, err := net.FileConn(file)
	_ = file.Close()
	if err != nil {
		t.Fatalf("FileConn: %v", err)
	}
	return conn.(*net.UnixConn)
}

func readAllString(t *testing.T, conn *net.UnixConn) string {
	t.Helper()
	b, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return string(b)
}
