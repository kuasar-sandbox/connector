package egress

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Linux UAPI struct ethtool_value and pointer-bearing struct ifreq. Keep the
// data pointer typed so the Go collector can see it throughout the ioctl.
type ethtoolValue struct{ command, value uint32 }
type ethtoolRequest struct {
	name [unix.IFNAMSIZ]byte
	data *ethtoolValue
	_    [unsafe.Sizeof(unix.Ifreq{}) - unix.IFNAMSIZ - unsafe.Sizeof(uintptr(0))]byte
}

func offloadValue(fd int, device string, command, value uint32) (uint32, error) {
	if len(device) == 0 || len(device) >= unix.IFNAMSIZ {
		return 0, fmt.Errorf("invalid offload interface %q", device)
	}
	request := ethtoolRequest{data: &ethtoolValue{command, value}}
	copy(request.name[:], device)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCETHTOOL, uintptr(unsafe.Pointer(&request)))
	runtime.KeepAlive(&request)
	if errno != 0 {
		return 0, errno
	}
	return request.data.value, nil
}

// AF_PACKET consumes complete wire packets. Dedicated endpoints must not hand
// it CHECKSUM_PARTIAL or GSO frames. Use the kernel API, without an ethtool CLI
// dependency, and verify each required feature actually became disabled.
func disableOffloads(device string) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	for _, feature := range []struct {
		name     string
		get, set uint32
	}{
		{"TX checksum", unix.ETHTOOL_GTXCSUM, unix.ETHTOOL_STXCSUM},
		{"RX checksum", unix.ETHTOOL_GRXCSUM, unix.ETHTOOL_SRXCSUM},
		{"GSO", unix.ETHTOOL_GGSO, unix.ETHTOOL_SGSO},
		{"GRO", unix.ETHTOOL_GGRO, unix.ETHTOOL_SGRO},
		{"TSO", unix.ETHTOOL_GTSO, unix.ETHTOOL_STSO},
	} {
		value, err := offloadValue(fd, device, feature.get, 0)
		if err != nil {
			return fmt.Errorf("read %s on %s: %w", feature.name, device, err)
		}
		if value == 0 {
			continue
		}
		if _, err = offloadValue(fd, device, feature.set, 0); err != nil {
			return fmt.Errorf("disable %s on %s: %w", feature.name, device, err)
		}
		value, err = offloadValue(fd, device, feature.get, 0)
		if err != nil || value != 0 {
			return fmt.Errorf("%s remains enabled on %s (read error: %v)", feature.name, device, err)
		}
	}
	return nil
}
