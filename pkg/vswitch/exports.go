package vswitch

import "github.com/fullof-work/sandbox-vswitch/pkg/internal/bpf"

// Re-exports of low-level BPF helpers that the CLI legitimately needs but
// must not import directly (pkg/internal/* is off-limits to cmd/ by the Go
// internal-package rule once this package moves under pkg/).
//
// Anything cmd/vswitch-ctl references through bpf.* should be wired here.

// IP conversion utilities (used by show / open-port / status for JSON
// rendering).
var (
	Uint32ToIP    = bpf.Uint32ToIP
	IPToUint32    = bpf.IPToUint32
	ParsePortKind = bpf.ParsePortKind
)

// Maps re-exports the BPF maps wrapper type — needed by mock Interface
// implementations in tests.
type Maps = bpf.Maps
