package tapfd

import (
	"fmt"
	"net"
	"os"
	"syscall"
)

// recvOOBSize is the SCM_RIGHTS ancillary buffer size. Sized for up to 8 fds
// (room for future multi-queue plus a trailing netns fd); senders today
// deliver 1 tap fd and at most 1 netns fd. CmsgSpace handles 8-byte alignment
// of the cmsghdr automatically.
var recvOOBSize = syscall.CmsgSpace(8 * 4) // 8 * sizeof(int)

// RecvFd receives a single tap fd plus its metadata payload from conn.
// It is the happy-path receiver: if the sender delivered exactly one tap
// fd, returns it as an owning *os.File. Any other count is an error and all
// received fds are closed before return.
//
// If the sender also delivered a netns fd (meta.NetnsFDCount > 0), it is
// closed and discarded — callers that want the tap's netns fd must use
// RecvFdsWithNetns. See RecvFds for the multi-tap-fd variant.
func RecvFd(conn *net.UnixConn) (*os.File, *PortMetadata, error) {
	files, meta, err := RecvFds(conn)
	if err != nil {
		return nil, nil, err
	}
	if len(files) != 1 {
		for _, f := range files {
			_ = f.Close()
		}
		return nil, nil, fmt.Errorf("RecvFd: expected exactly 1 fd, got %d", len(files))
	}
	return files[0], meta, nil
}

// RecvFds receives one or more tap fds plus the accompanying metadata
// payload from conn. Each returned *os.File owns its fd; the caller must
// Close every file (or transfer ownership).
//
// On any error all already-received fds are closed and a nil slice is
// returned. If the sender appended a netns fd (meta.NetnsFDCount > 0), it is
// closed and discarded here — use RecvFdsWithNetns to obtain it. Tap fd count
// is cross-checked as in RecvFdsWithNetns.
func RecvFds(conn *net.UnixConn) ([]*os.File, *PortMetadata, error) {
	tapFiles, netnsFile, meta, err := RecvFdsWithNetns(conn)
	if err != nil {
		return nil, nil, err
	}
	if netnsFile != nil {
		// This receiver doesn't expose the netns fd; close it so we don't leak.
		_ = netnsFile.Close()
	}
	return tapFiles, meta, nil
}

// RecvFdsWithNetns receives the tap fds plus an optional trailing netns fd and
// the accompanying metadata payload from conn. The netns fd, when present, is
// an open handle to the network namespace the tap device lives in (usable with
// setns(2)/CLONE_NEWNET); netnsFile is nil when the sender attached none.
//
// fd accounting: the SCM_RIGHTS ancillary carries meta.FDCount tap fds followed
// by meta.NetnsFDCount netns fds (the netns fds are last). The total number of
// fds actually delivered must equal FDCount + NetnsFDCount; a mismatch is an
// error. At most one netns fd is supported.
//
// Each returned *os.File owns its fd; the caller must Close every tap file and
// the netns file (or transfer ownership). On any error all already-received
// fds are closed and nil slices are returned.
func RecvFdsWithNetns(conn *net.UnixConn) (tapFiles []*os.File, netnsFile *os.File, meta *PortMetadata, err error) {
	buf := make([]byte, MaxPayloadSize)
	oob := make([]byte, recvOOBSize)

	n, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("recvmsg: %w", err)
	}
	if n == 0 {
		return nil, nil, nil, fmt.Errorf("recvmsg: empty payload (sender must include metadata)")
	}

	// Parse the SCM_RIGHTS ancillary — collect every fd from every control
	// message (defensive: senders should only attach one cmsg, but we mustn't
	// leak if they don't).
	scms, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse ancillary: %w", err)
	}
	var fds []int
	for _, scm := range scms {
		if scm.Header.Level == syscall.SOL_SOCKET && scm.Header.Type == syscall.SCM_RIGHTS {
			more, err := syscall.ParseUnixRights(&scm)
			if err != nil {
				closeIntFds(fds)
				return nil, nil, nil, fmt.Errorf("parse SCM_RIGHTS: %w", err)
			}
			fds = append(fds, more...)
		}
	}
	if len(fds) == 0 {
		if code, msg, ok, perr := ParseErrorResponse(buf[:n]); ok {
			if perr != nil {
				return nil, nil, nil, perr
			}
			if msg != "" {
				return nil, nil, nil, fmt.Errorf("tapfd provider error %s: %s", code, msg)
			}
			return nil, nil, nil, fmt.Errorf("tapfd provider error %s", code)
		}
		return nil, nil, nil, fmt.Errorf("no SCM_RIGHTS fds in message")
	}

	// Decode payload before wrapping fds, so a malformed payload still closes
	// the fds and returns clean. Persistent socket providers prefix success
	// with "TAPFD/1 OK"; exec helpers may still send bare metadata.
	payload, err := StripOKResponse(buf[:n])
	if err != nil {
		closeIntFds(fds)
		return nil, nil, nil, fmt.Errorf("parse response: %w", err)
	}
	meta, err = ParsePayload(payload)
	if err != nil {
		closeIntFds(fds)
		return nil, nil, nil, fmt.Errorf("parse payload: %w", err)
	}

	nNetns := int(meta.NetnsFDCount)
	if nNetns > 1 {
		closeIntFds(fds)
		return nil, nil, nil, fmt.Errorf("netns_fd=%d unsupported (at most 1 netns fd allowed)", meta.NetnsFDCount)
	}
	// Cross-check counts. When FDCount is given (the normal case) the total
	// must be tap + netns exactly. When FDCount is absent (0, lenient mode) we
	// can't pin the split, so only require enough fds to carve off the netns
	// fds and treat the rest as tap fds.
	if meta.FDCount != 0 {
		if want := int(meta.FDCount) + nNetns; len(fds) != want {
			closeIntFds(fds)
			return nil, nil, nil, fmt.Errorf("fd count mismatch: payload says fd=%d netns_fd=%d (total %d), ancillary delivered %d",
				meta.FDCount, meta.NetnsFDCount, want, len(fds))
		}
	} else if nNetns > len(fds) {
		closeIntFds(fds)
		return nil, nil, nil, fmt.Errorf("fd count mismatch: payload says netns_fd=%d but ancillary delivered only %d fds",
			meta.NetnsFDCount, len(fds))
	}

	files := make([]*os.File, 0, len(fds))
	for i, fd := range fds {
		name := fmt.Sprintf("tap-fd-%d", i)
		if i >= len(fds)-nNetns {
			name = "tap-netns-fd"
		}
		f := os.NewFile(uintptr(fd), name)
		if f == nil {
			closeFiles(files)
			closeIntFds(fds[i:])
			return nil, nil, nil, fmt.Errorf("os.NewFile returned nil for fd %d", fd)
		}
		files = append(files, f)
	}

	// The trailing nNetns fds are netns fds; the rest are tap fds.
	cut := len(files) - nNetns
	tapFiles = files[:cut]
	if nNetns == 1 {
		netnsFile = files[cut]
	}
	return tapFiles, netnsFile, meta, nil
}

func closeIntFds(fds []int) {
	for _, fd := range fds {
		_ = syscall.Close(fd)
	}
}

func closeFiles(fs []*os.File) {
	for _, f := range fs {
		_ = f.Close()
	}
}
