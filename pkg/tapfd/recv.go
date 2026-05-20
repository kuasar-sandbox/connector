package tapfd

import (
	"fmt"
	"net"
	"os"
	"syscall"
)

// recvOOBSize is the SCM_RIGHTS ancillary buffer size. Sized for up to 4 fds
// (forward-compat with future multi-queue); v1 senders deliver exactly 1.
// CmsgSpace handles 8-byte alignment of the cmsghdr automatically.
var recvOOBSize = syscall.CmsgSpace(4 * 4) // 4 * sizeof(int)

// RecvFd receives a single tap fd plus its metadata payload from conn.
// It is the v1 happy-path receiver: if the sender delivered exactly one fd,
// returns it as an owning *os.File. Any other count is an error and all
// received fds are closed before return.
//
// See RecvFds for the multi-fd variant.
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
// returned. If meta.FDCount is nonzero it is cross-checked against the
// number of fds actually delivered; a mismatch is an error.
func RecvFds(conn *net.UnixConn) ([]*os.File, *PortMetadata, error) {
	buf := make([]byte, MaxPayloadSize)
	oob := make([]byte, recvOOBSize)

	n, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
	if err != nil {
		return nil, nil, fmt.Errorf("recvmsg: %w", err)
	}
	if n == 0 {
		return nil, nil, fmt.Errorf("recvmsg: empty payload (sender must include metadata)")
	}

	// Parse the SCM_RIGHTS ancillary — collect every fd from every control
	// message (defensive: senders should only attach one, but we mustn't
	// leak if they don't).
	scms, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return nil, nil, fmt.Errorf("parse ancillary: %w", err)
	}
	var fds []int
	for _, scm := range scms {
		if scm.Header.Level == syscall.SOL_SOCKET && scm.Header.Type == syscall.SCM_RIGHTS {
			more, err := syscall.ParseUnixRights(&scm)
			if err != nil {
				closeIntFds(fds)
				return nil, nil, fmt.Errorf("parse SCM_RIGHTS: %w", err)
			}
			fds = append(fds, more...)
		}
	}
	if len(fds) == 0 {
		return nil, nil, fmt.Errorf("no SCM_RIGHTS fds in message")
	}

	// Decode payload before wrapping fds, so a malformed payload still closes
	// the fds and returns clean.
	meta, err := ParsePayload(buf[:n])
	if err != nil {
		closeIntFds(fds)
		return nil, nil, fmt.Errorf("parse payload: %w", err)
	}
	if meta.FDCount != 0 && int(meta.FDCount) != len(fds) {
		closeIntFds(fds)
		return nil, nil, fmt.Errorf("fd count mismatch: payload says %d, ancillary delivered %d",
			meta.FDCount, len(fds))
	}

	files := make([]*os.File, 0, len(fds))
	for i, fd := range fds {
		f := os.NewFile(uintptr(fd), fmt.Sprintf("tap-fd-%d", i))
		if f == nil {
			closeFiles(files)
			closeIntFds(fds[i:])
			return nil, nil, fmt.Errorf("os.NewFile returned nil for fd %d", fd)
		}
		files = append(files, f)
	}
	return files, meta, nil
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
