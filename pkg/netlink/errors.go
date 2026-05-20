package netlink

import (
	"errors"
	"syscall"

	"github.com/vishvananda/netlink"
)

// ErrDumpInterrupted is returned by netlink dump operations when the kernel
// sets NLM_F_DUMP_INTR, indicating the results may be incomplete but are still usable.
var ErrDumpInterrupted = netlink.ErrDumpInterrupted

// IsLinkNotExist returns true if the error indicates a network link/device does not exist.
// This handles ENOENT, ENODEV, and vishvananda/netlink.LinkNotFoundError.
func IsLinkNotExist(err error) bool {
	if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ENODEV) {
		return true
	}
	var lnf netlink.LinkNotFoundError
	return errors.As(err, &lnf)
}
