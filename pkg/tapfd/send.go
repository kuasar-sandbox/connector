package tapfd

import (
	"fmt"
	"net"
	"os"
	"syscall"
)

// SendFd sends one or more open file descriptors over a connected unix socket
// via SCM_RIGHTS, accompanied by a structured payload (see PortMetadata for the
// wire format). The receiver retrieves the fd(s) from the SCM_RIGHTS ancillary
// buffer and parses the payload bytes — typically by calling RecvFd or RecvFds
// in this same package.
//
// Some Linux versions require nonzero payload for SCM_RIGHTS delivery; the
// metadata serves both as user data and as that required payload.
func SendFd(sock *net.UnixConn, payload []byte, fds ...uintptr) error {
	if len(fds) == 0 {
		return fmt.Errorf("SendFd: at least one fd required")
	}
	if len(payload) == 0 {
		return fmt.Errorf("SendFd: payload must be non-empty (kernel requires data with SCM_RIGHTS)")
	}
	ints := make([]int, len(fds))
	for i, fd := range fds {
		ints[i] = int(fd)
	}
	rights := syscall.UnixRights(ints...)
	if _, _, err := sock.WriteMsgUnix(payload, rights, nil); err != nil {
		return fmt.Errorf("send fd via SCM_RIGHTS: %w", err)
	}
	return nil
}

// ConnectUnix dials a stream unix socket at the given filesystem path.
// Use this for the "connector-ctl vswitch is the client, VMM listens" pattern.
func ConnectUnix(path string) (*net.UnixConn, error) {
	addr, err := net.ResolveUnixAddr("unix", path)
	if err != nil {
		return nil, fmt.Errorf("resolve unix %s: %w", path, err)
	}
	conn, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		return nil, fmt.Errorf("connect unix %s: %w", path, err)
	}
	return conn, nil
}

// UnixConnFromFd wraps an already-inherited unix socket fd (e.g. fd=3 passed
// from a parent process) as a *net.UnixConn. The underlying fd is duplicated
// by net.FileConn; the original fd is closed before return.
func UnixConnFromFd(fd int) (*net.UnixConn, error) {
	f := os.NewFile(uintptr(fd), fmt.Sprintf("inherited-fd-%d", fd))
	if f == nil {
		return nil, fmt.Errorf("fd %d is not a valid file descriptor", fd)
	}
	defer f.Close()
	c, err := net.FileConn(f)
	if err != nil {
		return nil, fmt.Errorf("wrap fd %d as net.Conn: %w", fd, err)
	}
	uc, ok := c.(*net.UnixConn)
	if !ok {
		c.Close()
		return nil, fmt.Errorf("fd %d is not a unix socket (got %T)", fd, c)
	}
	return uc, nil
}
