package bpf

import (
	"errors"

	"github.com/cilium/ebpf"
)

// IsKeyNotExist returns true if the error indicates a BPF map key does not exist.
func IsKeyNotExist(err error) bool {
	return errors.Is(err, ebpf.ErrKeyNotExist)
}
