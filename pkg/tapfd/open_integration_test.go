//go:build integration

package tapfd

import (
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func ioctl(fd, req, arg uintptr) error {
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, fd, req, arg); e != 0 {
		return e
	}
	return nil
}

// makePersistentTap creates a persistent tap WITHOUT vnet_hdr — exactly how
// `provision` creates it via netlink (TUNTAP_DEFAULTS|TUNTAP_NO_PI) — and then
// releases its create-queue, leaving the device attachable by OpenTap. A
// t.Cleanup removes the device. This is the realistic starting state: the
// vnet_hdr flag must come from the later open, not the device's birth.
func makePersistentTap(t *testing.T, name string) {
	t.Helper()
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open /dev/net/tun: %v", err)
	}
	var req ifReq
	copy(req.Name[:], name)
	req.Flags = unix.IFF_TAP | unix.IFF_NO_PI
	if err := ioctl(uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&req))); err != nil {
		unix.Close(fd)
		t.Fatalf("TUNSETIFF create %s: %v", name, err)
	}
	if err := ioctl(uintptr(fd), uintptr(unix.TUNSETPERSIST), 1); err != nil {
		unix.Close(fd)
		t.Fatalf("TUNSETPERSIST(1) %s: %v", name, err)
	}
	unix.Close(fd) // release create-queue; the persistent device remains

	t.Cleanup(func() {
		cfd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
		if err != nil {
			return
		}
		defer unix.Close(cfd)
		var r ifReq
		copy(r.Name[:], name)
		r.Flags = unix.IFF_TAP | unix.IFF_NO_PI
		if ioctl(uintptr(cfd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&r))) == nil {
			_ = ioctl(uintptr(cfd), uintptr(unix.TUNSETPERSIST), 0) // clear persist → close destroys it
		}
	})
}

func queueFlags(t *testing.T, f *os.File) uint16 {
	t.Helper()
	var req ifReq
	if err := ioctl(f.Fd(), uintptr(unix.TUNGETIFF), uintptr(unsafe.Pointer(&req))); err != nil {
		t.Fatalf("TUNGETIFF: %v", err)
	}
	return req.Flags
}

// TestOpenTapVnetHdrIT verifies that the queue fd OpenTap hands off carries the
// virtio-net header flag iff IFF_VNET_HDR was requested. cloud-hypervisor and
// the other virtio VMMs expect a vnet_hdr-framed tap fd;
// without the flag the framing is mismatched and the link silently breaks. The
// flag must take effect on this attaching open regardless of the persistent
// device's creation flags (kernel-verified: vnet_hdr follows the open).
func TestOpenTapVnetHdrIT(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root (creates tap devices)")
	}

	t.Run("with IFF_VNET_HDR", func(t *testing.T) {
		const name = "tapfd-vh-it"
		makePersistentTap(t, name)
		f, err := OpenTap(name, unix.IFF_NO_PI|unix.IFF_VNET_HDR)
		if err != nil {
			t.Fatalf("OpenTap: %v", err)
		}
		defer f.Close()
		if fl := queueFlags(t, f); fl&unix.IFF_VNET_HDR == 0 {
			t.Fatalf("queue flags %#x: IFF_VNET_HDR not set (a virtio VMM would mis-frame this fd)", fl)
		}
	})

	t.Run("without IFF_VNET_HDR", func(t *testing.T) {
		const name = "tapfd-novh-it"
		makePersistentTap(t, name)
		f, err := OpenTap(name, unix.IFF_NO_PI)
		if err != nil {
			t.Fatalf("OpenTap: %v", err)
		}
		defer f.Close()
		if fl := queueFlags(t, f); fl&unix.IFF_VNET_HDR != 0 {
			t.Fatalf("queue flags %#x: IFF_VNET_HDR unexpectedly set", fl)
		}
	})
}
