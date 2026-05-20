package bpf

import (
	"errors"
	"fmt"
	"testing"

	"github.com/cilium/ebpf"
)

func TestIsKeyNotExist(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "ErrKeyNotExist",
			err:  fmt.Errorf("map lookup failed: %w", ebpf.ErrKeyNotExist),
			want: true,
		},
		{
			name: "wrapped ErrKeyNotExist",
			err:  fmt.Errorf("delete key: %w", fmt.Errorf("bpf: %w", ebpf.ErrKeyNotExist)),
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
			if got := IsKeyNotExist(tt.err); got != tt.want {
				t.Errorf("IsKeyNotExist() = %v, want %v", got, tt.want)
			}
		})
	}
}
