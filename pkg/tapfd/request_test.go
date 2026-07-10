package tapfd

import (
	"net"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestBuildAndParseOpenRequest(t *testing.T) {
	line, err := BuildOpenRequest("switch=sw0 port=1", true)
	if err != nil {
		t.Fatalf("BuildOpenRequest: %v", err)
	}
	if got, want := string(line), "TAPFD/1 OPEN want_netns=1 switch=sw0 port=1\n"; got != want {
		t.Fatalf("request = %q, want %q", got, want)
	}
	req, err := ParseRequestLine(strings.TrimSuffix(string(line), "\n"))
	if err != nil {
		t.Fatalf("ParseRequestLine: %v", err)
	}
	if req.Version != RequestVersion || req.Op != RequestOpOpen || !req.WantNetns {
		t.Fatalf("request header = %+v", req)
	}
	if req.Fields["switch"] != "sw0" || req.Fields["port"] != "1" {
		t.Fatalf("request fields = %+v", req.Fields)
	}
}

func TestBuildAndParsePrepareReleaseRequests(t *testing.T) {
	for _, tt := range []struct {
		name  string
		op    string
		extra string
	}{
		{"prepare", RequestOpPrepare, "VSWITCH=sw0 INNER_IP=169.254.0.21"},
		{"release", RequestOpRelease, "VSWITCH=sw0 PORT=7"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			line, err := BuildRequest(tt.op, tt.extra, false)
			if err != nil {
				t.Fatalf("BuildRequest: %v", err)
			}
			req, err := ParseRequestLine(strings.TrimSuffix(string(line), "\n"))
			if err != nil {
				t.Fatalf("ParseRequestLine: %v", err)
			}
			if req.Version != RequestVersion || req.Op != tt.op || req.WantNetns {
				t.Fatalf("request header = %+v", req)
			}
			if req.Fields["VSWITCH"] != "sw0" {
				t.Fatalf("request fields = %+v", req.Fields)
			}
		})
	}
}

func TestParseOpenRequestRejectsMalformed(t *testing.T) {
	for _, line := range []string{
		"",
		"TAPFD/2 OPEN switch=sw0",
		"TAPFD/1 CLOSE switch=sw0",
		"TAPFD/1 OPEN switch",
	} {
		if _, err := ParseRequestLine(line); err == nil {
			t.Fatalf("ParseRequestLine(%q): want error", line)
		}
	}
	if _, err := BuildOpenRequest("switch=sw0\nport=1", true); err == nil {
		t.Fatal("BuildOpenRequest with newline: want error")
	}
	if _, err := BuildRequest("CLOSE", "switch=sw0", false); err == nil {
		t.Fatal("BuildRequest with unsupported op: want error")
	}
}

func TestErrorResponse(t *testing.T) {
	resp := BuildErrorResponse("BAD REQUEST", "port 1 not attached")
	code, msg, ok, err := ParseErrorResponse(resp)
	if err != nil {
		t.Fatalf("ParseErrorResponse: %v", err)
	}
	if !ok || code != "BAD_REQUEST" || msg != "port_1_not_attached" {
		t.Fatalf("parsed error = code=%q msg=%q ok=%t", code, msg, ok)
	}
}

func TestOKLine(t *testing.T) {
	resp, err := BuildOKLine("port=7 released=1")
	if err != nil {
		t.Fatalf("BuildOKLine: %v", err)
	}
	if got, want := string(resp), "TAPFD/1 OK port=7 released=1\n"; got != want {
		t.Fatalf("OK line = %q, want %q", got, want)
	}
	if _, err := BuildOKLine("port=7\nreleased=1"); err == nil {
		t.Fatal("BuildOKLine with newline: want error")
	}
}

func TestOKResponse(t *testing.T) {
	payload := []byte("port=1 mac=02:00:00:00:00:01 ip=100.100.96.1 fd=1\x00")
	resp, err := BuildOKResponse(payload)
	if err != nil {
		t.Fatalf("BuildOKResponse: %v", err)
	}
	if got, want := string(resp[:11]), "TAPFD/1 OK "; got != want {
		t.Fatalf("response prefix = %q, want %q", got, want)
	}
	stripped, err := StripOKResponse(resp)
	if err != nil {
		t.Fatalf("StripOKResponse: %v", err)
	}
	if string(stripped) != string(payload) {
		t.Fatalf("stripped payload = %q, want %q", stripped, payload)
	}
	bare, err := StripOKResponse(payload)
	if err != nil {
		t.Fatalf("StripOKResponse bare: %v", err)
	}
	if string(bare) != string(payload) {
		t.Fatalf("bare payload = %q, want %q", bare, payload)
	}
}

func TestRecvFdsWithNetnsProviderError(t *testing.T) {
	a, b := unixSocketPair(t)
	defer a.Close()
	defer b.Close()

	if _, err := a.Write(BuildErrorResponse(ErrorCodePortUnavailable, "port_not_attached")); err != nil {
		t.Fatalf("write error response: %v", err)
	}
	_, _, _, err := RecvFdsWithNetns(b)
	if err == nil || !strings.Contains(err.Error(), ErrorCodePortUnavailable) {
		t.Fatalf("RecvFdsWithNetns error = %v, want provider error", err)
	}
}

func unixSocketPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	return unixConnFromRawFD(t, fds[0]), unixConnFromRawFD(t, fds[1])
}

func unixConnFromRawFD(t *testing.T, fd int) *net.UnixConn {
	t.Helper()
	file := os.NewFile(uintptr(fd), "tapfd-test-socket")
	conn, err := net.FileConn(file)
	_ = file.Close()
	if err != nil {
		t.Fatalf("FileConn: %v", err)
	}
	return conn.(*net.UnixConn)
}
