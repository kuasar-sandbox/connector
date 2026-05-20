package tapfd

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ifReq mirrors the kernel struct ifreq used by TUNSETIFF. Only ifr_name (the
// first 16 bytes) and ifr_flags (the next 2 bytes) are populated; the rest is
// padding to reach the ABI struct size.
type ifReq struct {
	Name  [16]byte
	Flags uint16
	_     [22]byte
}

const tunDevice = "/dev/net/tun"

// OpenTap opens /dev/net/tun and attaches to the existing persistent tap device
// named `tapName` via TUNSETIFF. Returns the new fd as an *os.File.
//
// The caller must already be inside the netns where the tap lives (use
// netns.Do() to enter switch-netns). The returned file owns the underlying fd
// and is non-blocking; the caller must Close() it (or transfer ownership
// elsewhere, e.g. via SCM_RIGHTS).
//
// extraFlags is the TUNSETIFF ifr_flags bitmask excluding IFF_TAP (added
// implicitly). The typical value for VMM use is unix.IFF_NO_PI.
func OpenTap(tapName string, extraFlags uint16) (*os.File, error) {
	if len(tapName) == 0 || len(tapName) >= 16 {
		return nil, fmt.Errorf("invalid tap name %q (must be 1..15 chars)", tapName)
	}

	fd, err := unix.Open(tunDevice, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", tunDevice, err)
	}

	var req ifReq
	copy(req.Name[:], tapName)
	req.Flags = extraFlags | unix.IFF_TAP

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&req))); errno != 0 {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("ioctl TUNSETIFF %s: %w", tapName, errno)
	}

	// Confirm the kernel kept the name we asked for. (The kernel would only
	// rename if the input contained a "%d" template, which our length check
	// above already rules out — paranoid guard against stale-state cases.)
	got := cstr(req.Name[:])
	if got != tapName {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("TUNSETIFF returned unexpected name %q (wanted %q)", got, tapName)
	}

	// Tap fds need explicit non-blocking mode because the kernel only
	// registers the device for poll() after TUNSETIFF, and Go's runtime
	// won't pollify a fd unless it was created with non-blocking semantics
	// from the start. See https://github.com/golang/go/issues/30426.
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("set nonblock on %s: %w", tapName, err)
	}

	return os.NewFile(uintptr(fd), tapName), nil
}

// cstr trims trailing NULs from a fixed-size C-style byte array.
func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
