package netlink

import (
	"errors"
	"fmt"
	"reflect"
	"syscall"
	"testing"
	"unsafe"

	"github.com/vishvananda/netlink"
)

// newLinkNotFoundError constructs a netlink.LinkNotFoundError with the given
// inner error. The struct embeds an unexported error field, so we use reflect
// + unsafe to set it from outside the package.
func newLinkNotFoundError(inner error) netlink.LinkNotFoundError {
	var lnf netlink.LinkNotFoundError
	v := reflect.ValueOf(&lnf).Elem()
	f := v.Field(0)
	fp := reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem()
	fp.Set(reflect.ValueOf(inner))
	return lnf
}

func TestIsLinkNotExist(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "ENOENT",
			err:  fmt.Errorf("link operation failed: %w", syscall.ENOENT),
			want: true,
		},
		{
			name: "ENODEV",
			err:  fmt.Errorf("link operation failed: %w", syscall.ENODEV),
			want: true,
		},
		{
			name: "wrapped ENOENT",
			err:  fmt.Errorf("delete link: %w", fmt.Errorf("netlink: %w", syscall.ENOENT)),
			want: true,
		},
		{
			name: "wrapped ENODEV",
			err:  fmt.Errorf("delete link: %w", fmt.Errorf("netlink: %w", syscall.ENODEV)),
			want: true,
		},
		{
			name: "LinkNotFoundError with fmt.Errorf",
			err:  newLinkNotFoundError(fmt.Errorf("Link not found")),
			want: true,
		},
		{
			name: "LinkNotFoundError with ENODEV",
			err:  newLinkNotFoundError(syscall.ENODEV),
			want: true,
		},
		{
			name: "wrapped LinkNotFoundError",
			err:  fmt.Errorf("failed to get link by index 314: %w", newLinkNotFoundError(fmt.Errorf("Link not found"))),
			want: true,
		},
		{
			name: "other error",
			err:  errors.New("some other error"),
			want: false,
		},
		{
			name: "nil",
			err:  nil,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsLinkNotExist(tt.err); got != tt.want {
				t.Errorf("IsLinkNotExist() = %v, want %v", got, tt.want)
			}
		})
	}
}
