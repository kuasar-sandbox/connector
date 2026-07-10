package tapfd

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"
)

// socketpairUnixConns returns a connected pair of *net.UnixConn backed by
// socketpair(2). Both ends are stream-mode AF_UNIX sockets — exactly what
// connector-ctl vswitch uses on the wire — so SCM_RIGHTS roundtrips behave
// identically to the production path. No root required.
func socketpairUnixConns(t *testing.T) (a, b *net.UnixConn) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	for i, fd := range fds {
		if err := syscall.SetNonblock(fd, true); err != nil {
			t.Fatalf("set nonblock fd %d: %v", fd, err)
		}
		f := os.NewFile(uintptr(fd), fmt.Sprintf("sp-%d", i))
		c, err := net.FileConn(f)
		f.Close()
		if err != nil {
			t.Fatalf("FileConn: %v", err)
		}
		uc, ok := c.(*net.UnixConn)
		if !ok {
			t.Fatalf("FileConn returned %T, want *net.UnixConn", c)
		}
		if i == 0 {
			a = uc
		} else {
			b = uc
		}
	}
	return a, b
}

func TestRecvFdRoundTrip(t *testing.T) {
	sender, receiver := socketpairUnixConns(t)
	defer sender.Close()
	defer receiver.Close()

	// A stand-in for the tap fd: a pipe read-end. Any open fd works for
	// SCM_RIGHTS — RecvFd doesn't validate fd kind.
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer pw.Close()
	defer pr.Close()

	in := PortMetadata{
		Port: 3, MAC: "02:00:00:00:80:03", InnerIP: "169.254.1.3", FDCount: 1,
	}
	wire, err := in.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	go func() {
		if err := SendFd(sender, wire, pr.Fd()); err != nil {
			t.Errorf("SendFd: %v", err)
		}
	}()

	gotFile, gotMeta, err := RecvFd(receiver)
	if err != nil {
		t.Fatalf("RecvFd: %v", err)
	}
	defer gotFile.Close()

	if *gotMeta != in {
		t.Errorf("meta mismatch:\n got: %+v\nwant: %+v", *gotMeta, in)
	}
	if gotFile.Fd() == pr.Fd() {
		t.Errorf("expected receiver to get a distinct fd number, got same as sender (%d)", gotFile.Fd())
	}

	// Sanity: writing into the sender's pipe end is readable through the
	// SCM_RIGHTS-received fd (kernel-level proof we got the right open file).
	if _, err := pw.Write([]byte("hello")); err != nil {
		t.Fatalf("write to pipe: %v", err)
	}
	pw.Close()
	got := make([]byte, 16)
	n, err := gotFile.Read(got)
	if err != nil {
		t.Fatalf("read from received fd: %v", err)
	}
	if string(got[:n]) != "hello" {
		t.Errorf("read through SCM_RIGHTS fd: got %q want %q", got[:n], "hello")
	}
}

func TestRecvFdRejectsZeroFds(t *testing.T) {
	sender, receiver := socketpairUnixConns(t)
	defer sender.Close()
	defer receiver.Close()

	in := PortMetadata{Port: 1, MAC: "02:00:00:00:80:01", InnerIP: "1.2.3.4", FDCount: 1}
	wire, err := in.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	go func() {
		_, _, _ = sender.WriteMsgUnix(wire, nil, nil) // no SCM_RIGHTS
	}()

	if _, _, err := RecvFd(receiver); err == nil {
		t.Fatal("expected error for missing SCM_RIGHTS, got nil")
	}
}

func TestRecvFdsMultiFd(t *testing.T) {
	sender, receiver := socketpairUnixConns(t)
	defer sender.Close()
	defer receiver.Close()

	pr1, pw1, _ := os.Pipe()
	pr2, pw2, _ := os.Pipe()
	defer pr1.Close()
	defer pr2.Close()
	defer pw1.Close()
	defer pw2.Close()

	in := PortMetadata{Port: 1, MAC: "02:00:00:00:80:01", InnerIP: "1.2.3.4", FDCount: 2}
	wire, err := in.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	go func() {
		rights := syscall.UnixRights(int(pr1.Fd()), int(pr2.Fd()))
		_, _, _ = sender.WriteMsgUnix(wire, rights, nil)
	}()

	files, gotMeta, err := RecvFds(receiver)
	if err != nil {
		t.Fatalf("RecvFds: %v", err)
	}
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	if len(files) != 2 {
		t.Fatalf("got %d files, want 2", len(files))
	}
	if gotMeta.FDCount != 2 {
		t.Errorf("meta.FDCount = %d, want 2", gotMeta.FDCount)
	}
}

func TestRecvFdsWithNetnsRoundTrip(t *testing.T) {
	sender, receiver := socketpairUnixConns(t)
	defer sender.Close()
	defer receiver.Close()

	// One stand-in tap fd + one stand-in netns fd (the netns fd is sent last).
	tapR, tapW, _ := os.Pipe()
	nsR, nsW, _ := os.Pipe()
	defer tapR.Close()
	defer tapW.Close()
	defer nsR.Close()
	defer nsW.Close()

	in := PortMetadata{
		Port: 3, MAC: "02:00:00:00:80:03", InnerIP: "169.254.1.3",
		FDCount: 1, NetnsFDCount: 1,
	}
	wire, err := in.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	go func() {
		if err := SendFd(sender, wire, tapR.Fd(), nsR.Fd()); err != nil {
			t.Errorf("SendFd: %v", err)
		}
	}()

	tapFiles, netnsFile, gotMeta, err := RecvFdsWithNetns(receiver)
	if err != nil {
		t.Fatalf("RecvFdsWithNetns: %v", err)
	}
	defer func() {
		for _, f := range tapFiles {
			f.Close()
		}
		if netnsFile != nil {
			netnsFile.Close()
		}
	}()

	if len(tapFiles) != 1 {
		t.Fatalf("got %d tap files, want 1", len(tapFiles))
	}
	if netnsFile == nil {
		t.Fatal("expected a netns fd, got nil")
	}
	if *gotMeta != in {
		t.Errorf("meta mismatch:\n got: %+v\nwant: %+v", *gotMeta, in)
	}

	// Prove the split is correct: writing into the tap pipe is readable through
	// the first received fd, and the netns pipe through the netns fd.
	tapW.Write([]byte("tap"))
	tapW.Close()
	buf := make([]byte, 8)
	if n, _ := tapFiles[0].Read(buf); string(buf[:n]) != "tap" {
		t.Errorf("tap fd read %q, want %q", buf[:n], "tap")
	}
	nsW.Write([]byte("ns"))
	nsW.Close()
	if n, _ := netnsFile.Read(buf); string(buf[:n]) != "ns" {
		t.Errorf("netns fd read %q, want %q", buf[:n], "ns")
	}
}

func TestRecvFdsDropsNetnsFD(t *testing.T) {
	// The netns-unaware RecvFds returns only the tap fd(s) and closes the
	// trailing netns fd so it doesn't leak.
	sender, receiver := socketpairUnixConns(t)
	defer sender.Close()
	defer receiver.Close()

	tapR, tapW, _ := os.Pipe()
	nsR, nsW, _ := os.Pipe()
	defer tapR.Close()
	defer tapW.Close()
	defer nsR.Close()
	defer nsW.Close()

	in := PortMetadata{Port: 1, MAC: "02:00:00:00:80:01", InnerIP: "1.2.3.4", FDCount: 1, NetnsFDCount: 1}
	wire, err := in.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	go func() {
		if err := SendFd(sender, wire, tapR.Fd(), nsR.Fd()); err != nil {
			t.Errorf("SendFd: %v", err)
		}
	}()

	files, gotMeta, err := RecvFds(receiver)
	if err != nil {
		t.Fatalf("RecvFds: %v", err)
	}
	defer closeFiles(files)
	if len(files) != 1 {
		t.Fatalf("RecvFds returned %d files, want 1 (netns fd dropped)", len(files))
	}
	if gotMeta.NetnsFDCount != 1 {
		t.Errorf("meta.NetnsFDCount = %d, want 1", gotMeta.NetnsFDCount)
	}
}

func TestRecvFdsWithNetnsCountMismatch(t *testing.T) {
	sender, receiver := socketpairUnixConns(t)
	defer sender.Close()
	defer receiver.Close()

	// Payload claims fd=1 netns_fd=1 (total 2) but only 1 fd is attached.
	bogus := []byte("port=1 mac=02:00:00:00:80:01 mtu=1500 ip=1.2.3.4 fd=1 netns_fd=1\x00")
	pr, pw, _ := os.Pipe()
	defer pr.Close()
	defer pw.Close()

	go func() {
		rights := syscall.UnixRights(int(pr.Fd()))
		_, _, _ = sender.WriteMsgUnix(bogus, rights, nil)
	}()

	if _, _, _, err := RecvFdsWithNetns(receiver); err == nil {
		t.Fatal("expected fd count mismatch error, got nil")
	}
}

func TestRecvFdFdCountMismatch(t *testing.T) {
	sender, receiver := socketpairUnixConns(t)
	defer sender.Close()
	defer receiver.Close()

	// Payload claims FDCount=2 but sender only attaches 1 fd.
	bogus := []byte("port=1 mac=02:00:00:00:80:01 mtu=1500 ip=1.2.3.4 fd=2\x00")
	pr, pw, _ := os.Pipe()
	defer pr.Close()
	defer pw.Close()

	go func() {
		rights := syscall.UnixRights(int(pr.Fd()))
		_, _, _ = sender.WriteMsgUnix(bogus, rights, nil)
	}()

	if _, _, err := RecvFds(receiver); err == nil {
		t.Fatal("expected fd count mismatch error, got nil")
	}
}
